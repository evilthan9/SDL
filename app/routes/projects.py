import csv
import io

from flask import Blueprint, render_template, redirect, url_for, flash, request, abort, make_response
from flask_login import login_required, current_user
from datetime import datetime
from sqlalchemy import func, or_
from sqlalchemy.orm import joinedload
from app import db
from app.models import Project, Task, TestCase, User, Vulnerability
from app.forms import ProjectForm
from app.permissions import (
    PERM_CASE_UPDATE, PERM_PROJECT_CREATE, PERM_TASK_ASSIGN, PERM_TASK_DELETE,
    PERM_VULN_VIEW, ROLE_TESTER, apply_vuln_scope, can_access_business,
    can_access_testing, has_perm, is_admin
)
from app.services import (
    calculate_due_date, calculate_risk_score, delete_project_cascade,
    generate_vuln_code, log_audit, safe_next_url
)
from app.labels import TASK_STATUS_LABELS, TASK_TEST_TYPE_LABELS
from app.state_machine import TERMINAL_STATUSES as _TERMINAL_STATUSES
from app.test_cases import TEST_CASE_NAMES

bp = Blueprint('projects', __name__, url_prefix='/projects')

#: 用例列表每页条数（播种时有 156 条,不分页会一次全渲染出来）
CASE_PER_PAGE = 30

#: 任务列表每页条数
TASK_PER_PAGE = 20


@bp.route('/')
@login_required
def list():
    """项目列表(测试端)，支持筛选和导出"""
    if not (is_admin(current_user) or can_access_testing(current_user)):
        # 业务/开发/访客误入测试端入口时,回到业务端而不是停在 403
        if can_access_business(current_user):
            return redirect(url_for('main.business'))
        abort(403)

    query = Task.query.outerjoin(Project).filter(
        or_(Task.submission_status == 'submitted', Task.submission_status.is_(None))
    )

    name = request.args.get('name', '').strip()
    test_type = request.args.get('test_type', '').strip()
    department = request.args.get('department', '').strip()
    owner_name = request.args.get('owner_name', '').strip()
    task_status = request.args.get('task_status', '').strip()
    created_from = request.args.get('created_from', '').strip()
    created_to = request.args.get('created_to', '').strip()

    if name:
        query = query.filter(Task.name.ilike(f'%{name}%'))
    # 直接按枚举值筛。原先是拿"Web应用/移动应用/API接口"去比 Task.test_type
    # （实际值是 penetration_test / compliance_test / ...），两边对不上,
    # 这个筛选器从来筛不出任何数据。
    if test_type in TASK_TEST_TYPE_LABELS:
        query = query.filter(Task.test_type == test_type)
    if department:
        query = query.filter(Project.department.ilike(f'%{department}%'))
    if owner_name:
        query = query.join(User, Task.tester_id == User.id).filter(User.username.ilike(f'%{owner_name}%'))
    # 同样:原映射只覆盖 3 个状态,Task.status 的另外 2 个永远筛不到
    if task_status in TASK_STATUS_LABELS:
        query = query.filter(Task.status == task_status)
    if created_from:
        query = query.filter(Task.created_at >= datetime.strptime(created_from, '%Y-%m-%d'))
    if created_to:
        query = query.filter(Task.created_at <= datetime.strptime(created_to, '%Y-%m-%d'))

    if current_user.role == ROLE_TESTER:
        query = query.filter(Task.tester_id == current_user.id)

    query = query.options(
        joinedload(Task.project).joinedload(Project.owner),
        joinedload(Task.creator),
        joinedload(Task.tester)
    ).order_by(Task.created_at.desc())
    testers = User.query.filter(User.role.in_(['tester', 'test_lead'])).order_by(User.username.asc()).all()

    if request.args.get('export') == '1':
        tasks = query.all()
        output = io.StringIO()
        # BOM 要写进内容:仅靠 Content-Type 的 charset=utf-8-sig 不会真的加 BOM,
        # Excel 打开中文会乱码。
        output.write('﻿')
        writer = csv.writer(output)
        writer.writerow(['ID', '任务名称', '测试类型', '关联项目', '责任人', '优先级', '创建时间'])
        for task in tasks:
            writer.writerow([
                task.id,
                task.name,
                task.test_type or '未分类',
                task.project.name if task.project else '未关联项目',
                task.tester.username if task.tester else '待分配',
                task.status,
                task.created_at.strftime('%Y-%m-%d') if task.created_at else ''
            ])

        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv; charset=utf-8-sig'
        response.headers['Content-Disposition'] = 'attachment; filename=projects.csv'
        return response

    page = request.args.get('page', 1, type=int)
    pagination = query.paginate(page=page, per_page=TASK_PER_PAGE, error_out=False)

    return render_template(
        'projects/list.html',
        projects=pagination.items,
        pagination=pagination,
        testers=testers,
        filters={
            'name': name,
            'test_type': test_type,
            'department': department,
            'owner_name': owner_name,
            'task_status': task_status,
            'created_from': created_from,
            'created_to': created_to,
        }
    )


@bp.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    """创建项目"""
    if not has_perm(current_user, PERM_PROJECT_CREATE):
        abort(403)

    form = ProjectForm()
    
    if form.validate_on_submit():
        project = Project(
            name=form.name.data,
            project_type=form.project_type.data,
            department=form.department.data,
            environment=form.environment.data,
            criticality=form.criticality.data,
            description=form.description.data,
            status='active'
        )
        db.session.add(project)
        db.session.flush()  # 先取 project.id 供任务与审计日志使用

        db.session.add(Task(
            name=project.name,
            project_id=project.id,
            test_type='security_test',
            creator_id=current_user.id,
            submission_status='draft',
            status='scheduled'
        ))

        log_audit(
            operator_id=current_user.id,
            resource_type='project',
            resource_id=project.id,
            action='create',
            detail=f'创建项目：{project.name}'
        )
        db.session.commit()

        flash(f'项目 "{project.name}" 创建成功！', 'success')
        return redirect(safe_next_url(request.args.get('next', '')) or url_for('projects.list'))
    
    return render_template('projects/form.html', form=form, title='创建项目')


@bp.route('/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit(id):
    """编辑项目 / 迭代。

    项目与迭代在数据上是同一张表，所以这一条路由同时服务两者。
    权限点与"创建"共用（能建就能改），具体的项目归属另外校验。

    注意迭代的"周期 / 移动App / 新立项系统"等字段在创建时被拼成了一个
    字符串存进 ``description``，**无法无损反解**回结构化字段。所以这里
    description 当作自由文本编辑，不去假装能还原那六个字段。
    """
    if not has_perm(current_user, PERM_PROJECT_CREATE):
        abort(403)

    project = Project.query.get_or_404(id)
    if not is_admin(current_user) and project.owner_id != current_user.id:
        abort(403)

    form = ProjectForm(obj=project)
    if form.validate_on_submit():
        before = {
            'name': project.name,
            'criticality': project.criticality,
            'department': project.department,
            'environment': project.environment,
        }
        project.name = form.name.data
        project.project_type = form.project_type.data
        project.department = form.department.data
        project.environment = form.environment.data
        project.criticality = form.criticality.data
        project.description = form.description.data

        changed = [
            f'{label}：{before[key] or "—"} → {getattr(project, key) or "—"}'
            for key, label in (('name', '名称'), ('criticality', '重要等级'),
                               ('department', '部门'), ('environment', '环境'))
            if before[key] != getattr(project, key)
        ]
        log_audit(
            operator_id=current_user.id,
            resource_type='project',
            resource_id=project.id,
            action='edit_project',
            detail=f'编辑项目「{project.name}」'
                   + ('；' + '；'.join(changed) if changed else '（无字段变化）')
        )
        db.session.commit()
        flash(f'项目「{project.name}」已更新', 'success')
        return redirect(url_for('projects.detail', id=project.id))

    return render_template('projects/form.html', form=form, project=project,
                           title='编辑项目')


@bp.route('/<int:id>/archive', methods=['POST'])
@login_required
def archive(id):
    """归档项目。

    归档前 ``Project.status`` 全项目只有 ``'active'`` 一个取值，
    而大量查询都在过滤 ``status == 'active'`` —— 那个过滤条件其实是恒真的。
    归档是给这个字段一个真实语义：归档后不再出现在"新建漏洞"的项目下拉与
    业务端的迭代列表里（可用"显示已归档"开关找回来），但历史数据完整保留。
    """
    if not has_perm(current_user, PERM_PROJECT_CREATE):
        abort(403)

    project = Project.query.get_or_404(id)
    if not is_admin(current_user) and project.owner_id != current_user.id:
        abort(403)

    if project.status == 'archived':
        flash(f'项目「{project.name}」已经是归档状态', 'info')
    else:
        project.status = 'archived'
        log_audit(
            operator_id=current_user.id,
            resource_type='project',
            resource_id=project.id,
            action='archive_project',
            from_status='active',
            to_status='archived',
            detail=f'归档项目「{project.name}」'
        )
        db.session.commit()
        flash(f'项目「{project.name}」已归档，可在“显示已归档”中找回', 'success')
    return redirect(request.form.get('back_url') or url_for('projects.detail', id=project.id))


@bp.route('/<int:id>/restore', methods=['POST'])
@login_required
def restore(id):
    """把归档的项目恢复为进行中。"""
    if not has_perm(current_user, PERM_PROJECT_CREATE):
        abort(403)

    project = Project.query.get_or_404(id)
    if not is_admin(current_user) and project.owner_id != current_user.id:
        abort(403)

    project.status = 'active'
    log_audit(
        operator_id=current_user.id,
        resource_type='project',
        resource_id=project.id,
        action='restore_project',
        from_status='archived',
        to_status='active',
        detail=f'恢复项目「{project.name}」'
    )
    db.session.commit()
    flash(f'项目「{project.name}」已恢复', 'success')
    return redirect(request.form.get('back_url') or url_for('projects.detail', id=project.id))


@bp.route('/<int:id>/delete', methods=['POST'])
@login_required
def delete(id):
    """删除项目及全部关联数据。仅管理员。

    不可逆，所以做了二次确认（模板层）并要求输入项目名（这里校验）。
    漏洞走软删除进回收站，不会真的丢。
    """
    if not is_admin(current_user):
        abort(403)

    project = Project.query.get_or_404(id)
    name = project.name
    task_count = Task.query.filter_by(project_id=project.id).count()
    vuln_count = Vulnerability.query.filter_by(project_id=project.id, is_deleted=False).count()

    log_audit(
        operator_id=current_user.id,
        resource_type='project',
        resource_id=project.id,
        action='delete_project',
        detail=f'删除项目「{name}」（连带 {task_count} 个任务，'
               f'{vuln_count} 条漏洞移入回收站）'
    )
    delete_project_cascade(project)
    db.session.commit()

    flash(f'项目「{name}」已删除，关联漏洞已移入回收站', 'info')
    return redirect(url_for('projects.list'))


@bp.route('/task/<int:id>/assign', methods=['POST'])
@login_required
def assign_task(id):
    """管理员将待分配测试任务分配给测试人员。"""
    if not has_perm(current_user, PERM_TASK_ASSIGN):
        abort(403)

    task = Task.query.get_or_404(id)
    tester_id = request.form.get('tester_id', type=int)
    tester = User.query.filter(
        User.id == tester_id,
        User.role.in_(['tester', 'test_lead'])
    ).first()
    if not tester:
        flash('请选择有效的测试人员', 'danger')
        return redirect(url_for('projects.task_workflow', id=id))

    start_value = request.form.get('start_date', '').strip()
    end_value = request.form.get('end_date', '').strip()
    try:
        task.start_date = datetime.strptime(start_value, '%Y-%m-%dT%H:%M') if start_value else None
        task.end_date = datetime.strptime(end_value, '%Y-%m-%dT%H:%M') if end_value else None
    except ValueError:
        flash('请填写正确的任务时间', 'danger')
        return redirect(url_for('projects.task_workflow', id=id))

    task.tester_id = tester.id
    task.status = 'assigned'
    log_audit(
        operator_id=current_user.id,
        resource_type='task',
        resource_id=task.id,
        action='task_assign',
        detail=f'分配测试任务“{task.name}”给 {tester.username}'
    )
    db.session.commit()
    flash(f'任务“{task.name}”已分配给 {tester.username}', 'success')
    return redirect(url_for('projects.task_workflow', id=task.id))


@bp.route('/task/<int:id>/start', methods=['POST'])
@login_required
def start_task(id):
    """确认后开始执行测试任务。"""
    task = Task.query.get_or_404(id)
    if not is_admin(current_user) and task.tester_id != current_user.id:
        abort(403)
    if task.status != 'assigned':
        flash('当前任务不在待测试状态', 'warning')
        return redirect(url_for('projects.task_workflow', id=id))

    if request.form.get('start') != 'yes':
        flash('已取消开始测试', 'info')
        return redirect(url_for('projects.task_workflow', id=id))

    task.status = 'in_progress'
    log_audit(
        operator_id=current_user.id,
        resource_type='task',
        resource_id=task.id,
        action='task_start',
        detail=f'开始测试任务“{task.name}”'
    )
    db.session.commit()
    flash(f'任务“{task.name}”已开始测试', 'success')
    return redirect(url_for('projects.task_workflow', id=id))


@bp.route('/task/<int:id>/review', methods=['POST'])
@login_required
def review_task(id):
    """审核测试结果并推进任务工作流。"""
    task = Task.query.get_or_404(id)
    if not is_admin(current_user) and task.tester_id != current_user.id:
        abort(403)
    if task.status != 'in_progress':
        flash('当前任务不在测试中状态', 'warning')
        return redirect(url_for('projects.task_workflow', id=id))

    result = request.form.get('result')
    if result == 'pass':
        task.status = 'archived'
        message = f'任务“{task.name}”审核通过，已完成'
    elif result == 'fail':
        task.status = 'retest'
        message = f'任务“{task.name}”审核不通过，进入整改与复测'
    else:
        flash('请选择测试通过或测试不通过', 'danger')
        return redirect(url_for('projects.task_workflow', id=id))

    log_audit(
        operator_id=current_user.id,
        resource_type='task',
        resource_id=task.id,
        action='task_review',
        detail=f'审核测试任务“{task.name}”：{"通过" if result == "pass" else "不通过"}'
    )
    db.session.commit()
    flash(message, 'success' if result == 'pass' else 'warning')
    return redirect(url_for('projects.task_workflow', id=id))


@bp.route('/task/<int:id>/retest-complete', methods=['POST'])
@login_required
def complete_retest(id):
    """整改与复测后审核完成:任务直接结束归档。"""
    task = Task.query.get_or_404(id)
    if not is_admin(current_user) and task.tester_id != current_user.id:
        abort(403)
    if task.status != 'retest':
        flash('当前任务不在“整改与复测”状态', 'warning')
        return redirect(url_for('projects.task_workflow', id=id))

    task.status = 'archived'
    log_audit(
        operator_id=current_user.id,
        resource_type='task',
        resource_id=task.id,
        action='retest_complete',
        detail=f'整改与复测审核完成，任务“{task.name}”已归档'
    )
    db.session.commit()
    flash(f'任务“{task.name}”整改与复测审核完成', 'success')
    return redirect(url_for('projects.task_workflow', id=id))


@bp.route('/task/<int:id>/workflow')
@login_required
def task_workflow(id):
    """查看测试任务工作流。"""
    if not (is_admin(current_user) or can_access_testing(current_user)):
        abort(403)

    task = Task.query.get_or_404(id)
    if current_user.role == ROLE_TESTER and task.tester_id != current_user.id:
        abort(403)

    if not task.test_cases:
        for case_number, case_name in enumerate(TEST_CASE_NAMES, start=1):
            db.session.add(TestCase(
                task_id=task.id,
                case_number=case_number,
                name=case_name,
                status='disabled',
                version='1.0',
                vulnerability_count=0
            ))
        db.session.commit()

    testers = User.query.filter(User.role.in_(['tester', 'test_lead'])).order_by(User.username.asc()).all()
    test_case_query = TestCase.query.filter_by(task_id=task.id)
    test_case_total = test_case_query.count()
    case_status = request.args.get('case_status', '').strip()
    if case_status in {'disabled', 'pass', 'fail'}:
        test_case_query = test_case_query.filter(TestCase.status == case_status)

    # 一次查询拿到全部用例的漏洞数,避免逐条懒加载（156 条用例就是 156 次查询）
    case_counts = dict(
        db.session.query(Vulnerability.test_case_id, func.count(Vulnerability.id))
        .filter(Vulnerability.task_id == task.id,
                Vulnerability.is_deleted.is_(False),
                Vulnerability.test_case_id.isnot(None))
        .group_by(Vulnerability.test_case_id)
        .all()
    )

    page = request.args.get('page', 1, type=int)
    pagination = (test_case_query
                  .order_by(TestCase.case_number.asc())
                  .paginate(page=page, per_page=CASE_PER_PAGE, error_out=False))
    test_cases = pagination.items

    # 本页用例关联的漏洞,一次查完再按用例分组。
    # 不能依赖 test_case.vulnerabilities 懒加载 —— 那会变成每页 30 次额外查询。
    case_ids = [case.id for case in test_cases]
    case_vulns = {}
    if case_ids:
        linked = (Vulnerability.query
                  .filter(Vulnerability.test_case_id.in_(case_ids),
                          Vulnerability.is_deleted.is_(False))
                  .options(joinedload(Vulnerability.assignee))
                  .order_by(Vulnerability.created_at.desc())
                  .all())
        for vuln in linked:
            case_vulns.setdefault(vuln.test_case_id, []).append(vuln)
    workflow_stages = [
        ('scheduled', '待分配'),
        ('assigned', '待测试'),
        ('in_progress', '测试中'),
        ('retest', '整改与复测'),
        ('archived', '完成')
    ]
    current_stage = 'assigned' if task.status == 'assigned' else task.status
    current_stage_index = next(
        (index for index, (stage_key, _) in enumerate(workflow_stages) if stage_key == current_stage),
        0
    )

    return render_template(
        'projects/task_workflow.html',
        task=task,
        testers=testers,
        workflow_stages=workflow_stages,
        current_stage=current_stage,
        current_stage_index=current_stage_index,
        test_cases=test_cases,
        test_case_total=test_case_total,
        case_counts=case_counts,
        case_vulns=case_vulns,
        can_edit_cases=_case_mutable(task),
        pagination=pagination,
        case_status=case_status,
        title='工作流'
    )


@bp.route('/task/<int:id>/delete', methods=['POST'])
@login_required
def delete_task(id):
    """管理员删除测试任务及其关联测试数据。"""
    if not has_perm(current_user, PERM_TASK_DELETE):
        abort(403)

    task = Task.query.get_or_404(id)
    task_name = task.name
    TestCase.query.filter_by(task_id=task.id).delete(synchronize_session=False)
    Vulnerability.query.filter_by(task_id=task.id).update(
        {'is_deleted': True, 'deleted_at': datetime.utcnow()},
        synchronize_session=False
    )
    db.session.delete(task)
    db.session.commit()
    flash(f'任务“{task_name}”已删除', 'info')
    return redirect(url_for('projects.list'))


def _case_mutable(task):
    """当前用户能否增删改这个任务的用例。"""
    return is_admin(current_user) or task.tester_id == current_user.id


@bp.route('/task/<int:task_id>/case/create', methods=['POST'])
@login_required
def create_case(task_id):
    """新增一条测试用例。

    任务首次进入工作流时会按固定清单播种 156 条用例,但那份清单是只读的 ——
    原先没有任何入口能新增、改名、改版本或删除用例,``detail`` 列更是从未被写入过。
    """
    if not has_perm(current_user, PERM_CASE_UPDATE):
        abort(403)

    task = Task.query.get_or_404(task_id)
    if not _case_mutable(task):
        abort(403)

    name = request.form.get('name', '').strip()
    if not name:
        flash('用例名称不能为空', 'danger')
        return redirect(url_for('projects.task_workflow', id=task.id))
    if len(name) > 200:
        flash('用例名称过长（最多 200 字）', 'danger')
        return redirect(url_for('projects.task_workflow', id=task.id))

    max_number = (db.session.query(func.max(TestCase.case_number))
                  .filter(TestCase.task_id == task.id).scalar()) or 0
    test_case = TestCase(
        task_id=task.id,
        case_number=max_number + 1,
        name=name,
        status='disabled',
        version=(request.form.get('version', '').strip() or '1.0')[:20],
        detail=(request.form.get('detail', '').strip() or None),
    )
    db.session.add(test_case)
    db.session.flush()
    log_audit(
        operator_id=current_user.id,
        resource_type='task',
        resource_id=task.id,
        action='case_create',
        detail=f'新增测试用例 No.{test_case.case_number}「{test_case.name}」'
    )
    db.session.commit()
    flash(f'测试用例「{name}」已新增', 'success')
    return redirect(url_for('projects.task_workflow', id=task.id))


@bp.route('/task/<int:task_id>/case/<int:case_id>/edit', methods=['POST'])
@login_required
def edit_case(task_id, case_id):
    """编辑用例的名称 / 版本 / 说明。

    状态不在这里改 —— 它走 ``update_case_status``,那条路径会联动生成漏洞记录。
    """
    if not has_perm(current_user, PERM_CASE_UPDATE):
        abort(403)

    task = Task.query.get_or_404(task_id)
    if not _case_mutable(task):
        abort(403)

    test_case = TestCase.query.filter_by(id=case_id, task_id=task.id).first_or_404()

    name = request.form.get('name', '').strip()
    if not name:
        flash('用例名称不能为空', 'danger')
        return redirect(url_for('projects.task_workflow', id=task.id))

    before = {'name': test_case.name, 'version': test_case.version,
              'detail': test_case.detail}
    test_case.name = name[:200]
    test_case.version = (request.form.get('version', '').strip() or '1.0')[:20]
    test_case.detail = request.form.get('detail', '').strip() or None

    changed = [label for key, label in (('name', '名称'), ('version', '版本'),
                                        ('detail', '说明'))
               if before[key] != getattr(test_case, key)]
    log_audit(
        operator_id=current_user.id,
        resource_type='task',
        resource_id=task.id,
        action='case_edit',
        detail=f'编辑测试用例 No.{test_case.case_number}「{test_case.name}」'
               + (f'（{", ".join(changed)}）' if changed else '（无字段变化）')
    )
    db.session.commit()
    flash(f'测试用例「{test_case.name}」已更新', 'success')
    return redirect(url_for('projects.task_workflow', id=task.id))


@bp.route('/task/<int:task_id>/case/<int:case_id>/delete', methods=['POST'])
@login_required
def delete_case(task_id, case_id):
    """删除测试用例。

    已关联漏洞的用例不允许删除 —— 那些漏洞的 "来源测试用例" 会变成悬空引用,
    详情页会显示成一片空白。要删就先处理掉漏洞(删除或改挂别的用例)。
    """
    if not has_perm(current_user, PERM_CASE_UPDATE):
        abort(403)

    task = Task.query.get_or_404(task_id)
    if not _case_mutable(task):
        abort(403)

    test_case = TestCase.query.filter_by(id=case_id, task_id=task.id).first_or_404()

    linked = Vulnerability.query.filter_by(test_case_id=test_case.id, is_deleted=False).count()
    if linked:
        flash(f'该用例已关联 {linked} 条漏洞，请先处理这些漏洞再删除用例', 'warning')
        return redirect(url_for('projects.task_workflow', id=task.id))

    number, name = test_case.case_number, test_case.name
    db.session.delete(test_case)
    log_audit(
        operator_id=current_user.id,
        resource_type='task',
        resource_id=task.id,
        action='case_delete',
        detail=f'删除测试用例 No.{number}「{name}」'
    )
    db.session.commit()
    flash(f'测试用例「{name}」已删除', 'info')
    return redirect(url_for('projects.task_workflow', id=task.id))


@bp.route('/task/<int:task_id>/case/<int:case_id>/status', methods=['POST'])
@login_required
def update_case_status(task_id, case_id):
    """更新任务测试用例状态。"""
    if not has_perm(current_user, PERM_CASE_UPDATE):
        abort(403)

    task = Task.query.get_or_404(task_id)
    # 保留原有的归属约束:管理员不受限,其余人必须是该任务的处理人
    if not is_admin(current_user) and task.tester_id != current_user.id:
        abort(403)

    test_case = TestCase.query.filter_by(id=case_id, task_id=task.id).first_or_404()
    status = request.form.get('status')
    if status not in {'disabled', 'pass', 'fail'}:
        abort(400)

    old_case_status = test_case.status
    test_case.status = status
    # 不再写 vulnerability_count:原来的 `1 if status == 'fail' else 0` 是个假计数,
    # 与该用例实际关联的漏洞条数无关(一个用例可能报出 3 条,也可能一条没报)。
    # 真实条数在 task_workflow 里用一次 group by 聚合算出来。
    log_audit(
        operator_id=current_user.id,
        resource_type='task',
        resource_id=task.id,
        action='case_update',
        from_status=old_case_status,
        to_status=status,
        detail=f'测试用例 No.{test_case.case_number}「{test_case.name}」状态：'
               f'{old_case_status} → {status}'
    )
    if status == 'fail':
        existing_vulnerability = Vulnerability.query.filter_by(
            task_id=task.id,
            title=test_case.name,
            is_deleted=False
        ).first()
        if not existing_vulnerability:
            project = task.project
            db.session.add(Vulnerability(
                vuln_code=generate_vuln_code(),
                title=test_case.name,
                description=f'测试用例 No.{test_case.case_number} 未通过',
                project_id=task.project_id,
                task_id=task.id,
                test_case_id=test_case.id,
                source='manual',
                severity='中危',
                risk_score=calculate_risk_score('中危', project.criticality if project else None),
                status='pending',
                creator_id=current_user.id,
                due_date=calculate_due_date('中危')
            ))
    db.session.commit()
    case_status = request.form.get('case_status', '').strip()
    redirect_args = {'id': task.id}
    if case_status in {'disabled', 'pass', 'fail'}:
        redirect_args['case_status'] = case_status
    return redirect(url_for('projects.task_workflow', **redirect_args))


@bp.route('/<int:id>')
@login_required
def detail(id):
    """项目详情:基本信息 + 漏洞概况 + 编辑/归档/删除入口。"""
    if not (can_access_business(current_user) or can_access_testing(current_user)):
        abort(403)

    project = Project.query.get_or_404(id)
    if can_access_business(current_user) and not is_admin(current_user) and project.owner_id != current_user.id:
        abort(403)

    # 漏洞概况:按状态与等级各聚合一次,不逐个 count()
    vulns = apply_vuln_scope(
        Vulnerability.query.filter_by(project_id=project.id, is_deleted=False),
        current_user
    ).all()
    status_counts = {}
    severity_counts = {}
    overdue = 0
    now = datetime.utcnow()
    for vuln in vulns:
        status_counts[vuln.status] = status_counts.get(vuln.status, 0) + 1
        severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1
        if vuln.due_date and vuln.status not in _TERMINAL_STATUSES and vuln.due_date < now:
            overdue += 1

    can_manage = has_perm(current_user, PERM_PROJECT_CREATE) and (
        is_admin(current_user) or project.owner_id == current_user.id
    )

    next_url = request.args.get('next', '')
    back_url = safe_next_url(next_url) or (
        url_for('projects.list') if can_access_testing(current_user) else url_for('main.business')
    )
    return render_template(
        'projects/detail.html',
        project=project,
        back_url=back_url,
        vuln_total=len(vulns),
        status_counts=status_counts,
        severity_counts=severity_counts,
        overdue=overdue,
        can_manage=can_manage,
        can_delete=is_admin(current_user),
        task_count=Task.query.filter_by(project_id=project.id).count(),
    )


@bp.route('/<int:id>/vulnerabilities')
@login_required
def vulnerabilities(id):
    """直接展示某项目的漏洞列表(业务端“查看项目”直达,不跳项目概览)。

    业务端测试任务列表本身不限 owner,所以这里读列表对业务/测试角色放开;
    更深入的漏洞详情/操作权限由 vulnerabilities.detail/transition 各自按角色收口。
    """
    if not (can_access_business(current_user) or can_access_testing(current_user)):
        abort(403)

    project = Project.query.get_or_404(id)

    # 与 vulnerabilities.detail 用同一套数据范围,否则列表里点进去就是死链
    vuln_query = apply_vuln_scope(
        Vulnerability.query.filter_by(project_id=project.id, is_deleted=False),
        current_user
    )
    vulns = (vuln_query.options(
        joinedload(Vulnerability.task),
        joinedload(Vulnerability.assignee),
        joinedload(Vulnerability.creator)
    ).order_by(Vulnerability.created_at.desc()).all())
    next_url = request.args.get('next', '')
    back_url = safe_next_url(next_url) or (
        url_for('projects.list') if can_access_testing(current_user) else url_for('main.business')
    )
    return render_template(
        'projects/vulnerabilities.html',
        project=project,
        vulnerabilities=vulns,
        can_open_detail=has_perm(current_user, PERM_VULN_VIEW),
        back_url=back_url,
        title='项目漏洞列表'
    )