from datetime import datetime
from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from sqlalchemy import and_, func, or_
from sqlalchemy.orm import joinedload
from app import db
from app.forms import AssessmentForm, IterationForm, QuickTaskForm, TaskForm
from app.models import Project, Scan, ScanFinding, Task, TestCase, User, Vulnerability
from app.permissions import (
    PERM_DASHBOARD_VIEW, PERM_ITERATION_MANAGE, PERM_PROJECT_CREATE, ROLE_BUSINESS, ROLE_DEVELOPER,
    apply_scan_scope, apply_vuln_scope, can_access_business, can_access_testing, has_perm,
    is_admin, require_perm,
)
from app.analytics import build_dashboard
from app.labels import SCAN_TYPE_LABELS
from app.state_machine import ALL_STATUSES, TERMINAL_STATUSES
from app.services import log_audit

bp = Blueprint('main', __name__)


@bp.route('/')
@bp.route('/index')
@login_required
@require_perm(PERM_DASHBOARD_VIEW)
def index():
    """首页仪表盘（统计看板）。

    改造前这里一进来就 ``abort(403)``,只有管理员能看。现在按角色放开,
    统计口径统一为"当前用户可见的漏洞",页面上会标明范围。
    """
    stats = build_dashboard(current_user)
    stats['recent_vulns'] = (apply_vuln_scope(
        Vulnerability.query.filter_by(is_deleted=False), current_user
    ).options(
        joinedload(Vulnerability.project),
        joinedload(Vulnerability.assignee),
    ).order_by(Vulnerability.created_at.desc()).limit(10).all())
    return render_template('dashboard.html', stats=stats, title='统计看板')


@bp.route('/business/requirements/iterations/create', methods=['GET', 'POST'])
@login_required
def create_iteration():
    """创建需求控制阶段的项目迭代。

    它落库的就是一个 Project,所以权限点与"创建项目"一致。
    """
    if not has_perm(current_user, PERM_PROJECT_CREATE):
        abort(403)

    form = IterationForm()
    if form.validate_on_submit():
        status_criticality = {
            'planned': '普通',
            'in_progress': '重要',
            'completed': '核心'
        }
        assessment = '需要' if form.has_recent_test.data else '不需要'
        project = Project(
            name=form.name.data,
            project_type=form.system_version.data,
            department='业务迭代',
            owner_id=current_user.id,
            environment='testing',
            criticality=status_criticality[form.status.data],
            description=(
                f'{form.description.data}\n'
                f'周期：{form.start_date.data} ~ {form.end_date.data}\n'
                f'移动App：{"是" if form.is_mobile.data else "否"}；'
                f'新立项系统：{"是" if form.is_new_system.data else "否"}；'
                f'安全测试评估：{assessment}；'
                f'评估对象：{form.target_type.data}；'
                f'大版本发布：{"是" if form.has_release.data else "否"}'
            ),
            status='active'
        )
        db.session.add(project)
        db.session.flush()
        db.session.add(Task(
            name=project.name,
            project_id=project.id,
            test_type='security_test',
            creator_id=current_user.id,
            status='scheduled'
        ))
        log_audit(
            operator_id=current_user.id,
            resource_type='project',
            resource_id=project.id,
            action='create_iteration',
            detail=f'创建迭代“{project.name}”'
        )
        db.session.commit()
        flash(f'迭代“{project.name}”创建成功', 'success')
        return redirect(url_for('main.business', stage='requirement'))

    return render_template('iteration_form.html', form=form, title='创建迭代')


@bp.route('/business/testing/tasks/create', methods=['GET', 'POST'])
@login_required
def create_testing_task():
    """创建测试环境下的安全测试任务。"""
    if not can_access_testing(current_user):
        abort(403)

    form = TaskForm()
    testing_projects = Project.query.filter_by(
        status='active',
        environment='testing'
    ).order_by(Project.created_at.desc()).all()
    form.project_id.choices = [('', '不关联项目')] + [(project.id, project.name) for project in testing_projects]

    if form.validate_on_submit():
        task = Task(
            name=form.name.data,
            test_type=form.test_type.data,
            project_id=form.project_id.data,
            creator_id=current_user.id,
            tester_id=current_user.id,
            status='scheduled'
        )
        db.session.add(task)
        db.session.flush()
        log_audit(
            operator_id=current_user.id,
            resource_type='task',
            resource_id=task.id,
            action='create_task',
            detail=f'创建安全测试任务“{task.name}”'
        )
        db.session.commit()
        flash(f'测试任务“{task.name}”创建成功', 'success')
        return redirect(url_for('main.business', stage='testing'))

    return render_template('testing_task_form.html', form=form, title='创建安全测试任务')


def _active_iterations(user):
    """与“需求控制”页所见一致的迭代集合(所有 active 项目,不限环境)。

    业务人员只能选自己名下;admin/测试人员可选全部。
    """
    query = Project.query.filter_by(status='active')
    if can_access_business(user) and not is_admin(user):
        query = query.filter_by(owner_id=user.id)
    return query.order_by(Project.created_at.desc()).all()


@bp.route('/business/testing/tasks/create-quick', methods=['POST'])
@login_required
def create_testing_task_quick():
    """测试控制页“新建安全测试任务”:业务/开发建的任务先进入“待推送”,由业务推送后管理员在测试端分配测试人员。"""
    if not can_access_testing(current_user) and current_user.role not in (ROLE_BUSINESS, ROLE_DEVELOPER):
        abort(403)

    form = QuickTaskForm()
    form.iteration_id.choices = [('', '不关联迭代')] + [
        (project.id, project.name) for project in _active_iterations(current_user)
    ]

    if not form.validate_on_submit():
        # 多个字段可能出现相同报错(如两个空日期),去重后只提示一次
        flashed = set()
        for messages in form.errors.values():
            for message in messages:
                if message not in flashed:
                    flashed.add(message)
                    flash(message, 'danger')
        return redirect(url_for('main.business', stage='testing'))

    project = Project.query.get(form.iteration_id.data) if form.iteration_id.data else None
    name = (form.name.data or '').strip() or (
        f'{project.name} - 安全测试' if project else '安全测试任务'
    )
    # 业务/开发创建的任务先以“draft(待推送)”保存、不指派测试人员,推送后才进入管理员测试端;
    # 管理端(如 admin)直接创建则沿用旧行为(已提交、自己作为处理人)
    is_business_creator = current_user.role in (ROLE_BUSINESS, ROLE_DEVELOPER)
    task = Task(
        name=name,
        project_id=form.iteration_id.data,
        test_type=form.test_type.data,
        creator_id=current_user.id,
        tester_id=None if is_business_creator else current_user.id,
        start_date=form.start_date.data,
        end_date=form.end_date.data,
        status='scheduled',
        submission_status='draft' if is_business_creator else 'submitted'
    )
    db.session.add(task)
    db.session.flush()
    log_audit(
        operator_id=current_user.id,
        resource_type='task',
        resource_id=task.id,
        action='create_task',
        detail=f'创建安全测试任务“{name}”'
               + ('（待推送）' if is_business_creator else '')
    )
    db.session.commit()
    if is_business_creator:
        flash(f'安全测试任务“{name}”已创建，点击“推送”后才会进入测试端列表', 'success')
    else:
        flash(f'安全测试任务“{name}”已创建', 'success')
    return redirect(url_for('main.business', stage='testing'))


@bp.route('/business/testing/tasks/<int:task_id>/push', methods=['POST'])
@login_required
def push_testing_task(task_id):
    """业务把“待推送”的任务推送到管理员测试端,由管理员分配测试人员。"""
    task = Task.query.get_or_404(task_id)
    if not is_admin(current_user) and task.creator_id != current_user.id:
        abort(403)
    if task.submission_status == 'submitted':
        flash(f'任务“{task.name}”已在测试端列表中', 'info')
    else:
        task.submission_status = 'submitted'
        log_audit(
            operator_id=current_user.id,
            resource_type='task',
            resource_id=task.id,
            action='push_task',
            detail=f'推送测试任务“{task.name}”至测试端'
        )
        db.session.commit()
        flash(f'任务“{task.name}”已推送到测试端，等待管理员分配测试人员', 'success')
    return redirect(url_for('main.business', stage='testing'))


@bp.route('/business/iterations/<int:project_id>/push', methods=['POST'])
@login_required
def push_iteration(project_id):
    """业务人员把“需要安全测试”的迭代推送给测试侧。"""
    if not has_perm(current_user, PERM_ITERATION_MANAGE):
        abort(403)

    project = Project.query.get_or_404(project_id)
    # 保留原有的归属约束:管理员不受限,其余人必须是该迭代的负责人
    if not is_admin(current_user) and project.owner_id != current_user.id:
        abort(403)
    if not project.security_test_required:
        flash('该迭代未勾选“需要安全测试”，无需推送', 'warning')
        return redirect(url_for('main.business', stage='requirement'))

    project.requirements_pushed = True
    task = Task.query.filter_by(project_id=project.id, test_type='security_test').first()
    if task is None:
        task = Task(
            name=project.name,
            project_id=project.id,
            test_type='security_test',
            creator_id=current_user.id,
            status='scheduled'
        )
        db.session.add(task)
    task.submission_status = 'submitted'  # 进入测试侧队列(projects.list 只显示 submitted/无标记)
    log_audit(
        operator_id=current_user.id,
        resource_type='project',
        resource_id=project.id,
        action='push_iteration',
        detail=f'推送迭代“{project.name}”进入安全测试'
    )
    db.session.commit()
    flash(f'迭代“{project.name}”已推送到安全测试', 'success')
    return redirect(url_for('main.business', stage='requirement'))


@bp.route('/business/iterations/<int:project_id>/delete', methods=['POST'])
@login_required
def delete_iteration(project_id):
    """删除迭代及其关联的测试任务、测试用例与漏洞记录。"""
    if not has_perm(current_user, PERM_ITERATION_MANAGE):
        abort(403)

    project = Project.query.get_or_404(project_id)
    # 保留原有的归属约束:管理员不受限,其余人必须是该迭代的负责人
    if not is_admin(current_user) and project.owner_id != current_user.id:
        abort(403)

    name = project.name
    for task in Task.query.filter_by(project_id=project.id).all():
        TestCase.query.filter_by(task_id=task.id).delete(synchronize_session=False)
        Vulnerability.query.filter_by(task_id=task.id).update(
            {'is_deleted': True, 'deleted_at': datetime.utcnow()},
            synchronize_session=False
        )
        db.session.delete(task)
    log_audit(
        operator_id=current_user.id,
        resource_type='project',
        resource_id=project.id,
        action='delete_iteration',
        detail=f'删除迭代：{name}'
    )
    db.session.delete(project)
    db.session.commit()
    flash(f'迭代“{name}”已删除', 'info')
    return redirect(url_for('main.business', stage='requirement'))


@bp.route('/business/assessment', methods=['GET', 'POST'])
@login_required
def level_assessment():
    """定级备案：填写安全合规评估问卷。"""
    if not can_access_business(current_user):
        abort(403)

    form = AssessmentForm()
    project_query = Project.query.filter_by(status='active')
    if not is_admin(current_user):
        project_query = project_query.filter_by(owner_id=current_user.id)
    form.project_id.choices = [
        (p.id, p.name) for p in project_query.order_by(Project.created_at.desc()).all()
    ]

    if form.validate_on_submit():
        project = Project.query.get_or_404(form.project_id.data)
        if not is_admin(current_user) and project.owner_id != current_user.id:
            abort(403)
        importance = form.importance.data
        is_new = '是' if form.is_new_system.data else '否'
        need_test = '是' if form.requires_test.data else '否'
        project.description = (project.description or '') + (
            f'\n安全合规评估：软件服务重要性={importance}；'
            f'新立项系统={is_new}；需安全测试={need_test}'
        )
        project.security_test_required = form.requires_test.data
        project.questionnaire_completed = True
        db.session.commit()
        flash(f'评估问卷已保存：{project.name}', 'success')
        return redirect(url_for('main.business', stage='level'))

    return render_template('assessment_form.html', form=form, title='安全合规评估问卷')


@bp.route('/business')
@login_required
def business():
    """SDLC 流程页：每个阶段对应真实的页面内容。"""
    if can_access_testing(current_user) and not can_access_business(current_user):
        return redirect(url_for('projects.list'))

    if not can_access_business(current_user) and not can_access_testing(current_user):
        abort(403)

    requested_stage = request.args.get('stage')
    active_stage = requested_stage or ('requirement' if not is_admin(current_user) else 'testing')
    stage_order = [
        ('level', '定级备案'),
        ('requirement', '需求控制'),
        ('development', '研发控制'),
        ('testing', '测试控制'),
        ('release', '发布')
    ]

    valid_stage_keys = {stage_key for stage_key, _ in stage_order}
    if active_stage not in valid_stage_keys:
        active_stage = 'requirement'

    # 原先这里有一个 stage_data_by_key,每个 stage 配一段**写死的假问卷**：
    # options 是硬编码的字符串列表、selected_index 是常量（所以"选中项"永远一样）、
    # 渲染出来的是 <span class="radio"> 而不是真的表单控件,点了没反应。
    # 而且那段 markup 引用的 20 个 CSS 类在全项目都没有定义 —— 是一段无样式的裸 HTML。
    # 现在每个 stage 都用自己的真实数据。
    now = datetime.utcnow()
    open_statuses = tuple(s for s in ALL_STATUSES if s not in TERMINAL_STATUSES)

    level_projects = None
    if active_stage == 'level':
        level_query = Project.query.filter_by(status='active')
        if can_access_business(current_user) and not is_admin(current_user):
            level_query = level_query.filter_by(owner_id=current_user.id)
        level_projects = level_query.order_by(Project.created_at.desc()).all()

    dev_stats = None
    if active_stage == 'development':
        dev_vulns = apply_vuln_scope(
            Vulnerability.query.filter_by(is_deleted=False), current_user
        ).options(joinedload(Vulnerability.assignee)).all()
        status_counts, by_assignee, overdue = {}, {}, 0
        for vuln in dev_vulns:
            status_counts[vuln.status] = status_counts.get(vuln.status, 0) + 1
            if vuln.status in open_statuses:
                who = vuln.assignee.username if vuln.assignee else '待分配'
                by_assignee[who] = by_assignee.get(who, 0) + 1
                if vuln.due_date and vuln.due_date < now:
                    overdue += 1
        dev_stats = {
            'total': len(dev_vulns),
            'status_counts': status_counts,
            'by_assignee': sorted(by_assignee.items(), key=lambda kv: -kv[1])[:8],
            'open_total': sum(by_assignee.values()),
            'overdue': overdue,
        }

    # 研发控制阶段要顺带展示安全扫描结果 —— SDL 里"研发控制"正是自动化检测
    # 落地的环节（SAST/SCA/容器扫描通常挂在 CI 上跑）。
    dev_scans = None
    if active_stage == 'development':
        visible_scans = apply_scan_scope(
            Scan.query.filter_by(is_deleted=False), current_user
        ).all()
        scan_ids = [s.id for s in visible_scans]
        pending_by_scan = {}
        if scan_ids:
            rows = (db.session.query(ScanFinding.scan_id, func.count(ScanFinding.id))
                    .filter(ScanFinding.scan_id.in_(scan_ids), ScanFinding.status == 'open')
                    .group_by(ScanFinding.scan_id).all())
            pending_by_scan = dict(rows)

        dev_scans = []
        for key, label in SCAN_TYPE_LABELS.items():
            subset = sorted(
                (s for s in visible_scans if s.scan_type == key),
                key=lambda s: s.created_at or datetime.min,
                reverse=True,
            )
            dev_scans.append({
                'key': key,
                'label': label,
                'runs': len(subset),
                'latest': subset[0] if subset else None,
                'critical': sum(s.critical_count for s in subset),
                'high': sum(s.high_count for s in subset),
                'medium': sum(s.medium_count for s in subset),
                'low': sum(s.low_count for s in subset),
                'total': sum(s.total_findings for s in subset),
                # 已扫描出、但还没转成漏洞跟进的条数 —— 这是最能说明"检测是否闭环"的数
                'pending': sum(pending_by_scan.get(s.id, 0) for s in subset),
            })

    release_rows = None
    if active_stage == 'release':
        release_rows = []
        for project in Project.query.filter_by(status='active').order_by(Project.name.asc()).all():
            pv = Vulnerability.query.filter_by(project_id=project.id, is_deleted=False).all()
            open_vulns = [v for v in pv if v.status not in TERMINAL_STATUSES]
            release_rows.append({
                'project': project,
                'total': len(pv),
                'open_total': len(open_vulns),
                'high_open': len([v for v in open_vulns if v.severity in ('严重', '高危')]),
                'overdue': len([v for v in open_vulns if v.due_date and v.due_date < now]),
                'tasks_pending': Task.query.filter_by(project_id=project.id)
                                         .filter(Task.status != 'archived').count(),
            })
        for row in release_rows:
            # 发布前必须满足:没有未闭环的高危及以上、没有 SLA 逾期、相关测试任务已归档
            row['blockers'] = row['high_open'] + row['overdue'] + row['tasks_pending']
            row['ready'] = row['blockers'] == 0

    tasks = (Task.query.filter(or_(
        Task.project_id.is_(None),
        Task.project.has(Project.status == 'active')
    )).options(
        joinedload(Task.project),
        joinedload(Task.tester)
    ).order_by(Task.created_at.desc()).all())
    # 归档的迭代默认不显示。但必须给一个开关 —— 否则用户归档完发现列表里
    # 少了一条,会以为数据丢了。归档是"从常用视图里收起来",不是删除。
    show_archived = request.args.get('show_archived', type=int) == 1
    iteration_query = Project.query
    if not show_archived:
        iteration_query = iteration_query.filter_by(status='active')
    if can_access_business(current_user) and not is_admin(current_user):
        iteration_query = iteration_query.filter_by(owner_id=current_user.id)
    iteration_name = request.args.get('iteration_name', '').strip()
    if iteration_name:
        iteration_query = iteration_query.filter(Project.name.ilike(f'%{iteration_name}%'))
    iterations = iteration_query.order_by(Project.created_at.desc()).all()
    archived_count = Project.query.filter_by(status='archived').count()

    # 测试控制页的“新建安全测试任务”(admin 直接创建;business/developer 创建后走“待推送→推送”)
    quick_form = None
    if active_stage == 'testing' and (
        can_access_testing(current_user) or current_user.role in (ROLE_BUSINESS, ROLE_DEVELOPER)
    ):
        quick_form = QuickTaskForm()
        quick_form.iteration_id.choices = [('', '不关联迭代')] + [
            (project.id, project.name) for project in _active_iterations(current_user)
        ]

    return render_template(
        'business.html',
        stage_order=stage_order,
        active_stage=active_stage,
        stage_title=dict(stage_order).get(active_stage, ''),
        level_projects=level_projects,
        dev_stats=dev_stats,
        dev_scans=dev_scans,
        release_rows=release_rows,
        tasks=tasks,
        iterations=iterations,
        iteration_name=iteration_name,
        show_archived=show_archived,
        archived_count=archived_count,
        quick_form=quick_form,
        title='业务端'
    )
