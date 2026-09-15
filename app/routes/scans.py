"""安全扫描（SAST / 组件 / 容器镜像）。

对应 SDL 里"研发控制"阶段的自动化检测环节。三类扫描共用一张表,
用 ``scan_type`` 区分 —— 它们的字段结构完全一致（工具、目标、时间、发现数）。

权限划分参照业界通行做法（GitHub Advanced Security 的 Read alerts /
Manage alerts 两级、Prisma Cloud 的 DevSecOps User、Semgrep 的 Member /
Read-only、Invicti 的 Developer 只读角色）:

- 开发人员与业务人员**只读**,且只看自己参与的项目;
- 安全团队（tester / test_lead）负责录入与分级处置,可以把发现转成漏洞;
- 编辑与删除收口到 test_lead 与 admin。

发现默认只是"待梳理"的数据,勾选后才生成漏洞记录 —— 这样"检测 → 梳理 →
分派修复 → 复测闭环"接得上,又不会把低危噪音一股脑倒给开发。
"""
import re
from datetime import datetime

from flask import (Blueprint, render_template, redirect, url_for, flash,
                   request, abort)
from flask_login import login_required, current_user
from sqlalchemy import func, or_
from sqlalchemy.orm import joinedload

from app import db
from app.forms import ScanForm
from app.labels import (
    FINDING_STATUS_LABELS, SCAN_STATUS_LABELS, SCAN_TOOL_SUGGESTIONS,
    SCAN_TYPE_LABELS, SCAN_TYPE_TO_VULN_SOURCE, SEVERITY_LABELS,
    guess_vuln_type, scan_status_class, scan_type_class,
)
from app.models import Project, Scan, ScanFinding, Task, User, Vulnerability
from app.permissions import (
    PERM_SCAN_CONVERT, PERM_SCAN_CREATE, PERM_SCAN_MANAGE, PERM_SCAN_TRIAGE,
    PERM_SCAN_VIEW, apply_scan_scope, can_view_scan, has_perm,
    scan_scope_is_global, scan_scope_label,
)
from app.services import calculate_due_date, calculate_risk_score, generate_vuln_code, log_audit
from app.state_machine import STATUS_PENDING

bp = Blueprint('scans', __name__, url_prefix='/scans')

PER_PAGE = 20

#: 常见等级写法 -> 标准中文等级，方便直接粘贴扫描器输出
_SEVERITY_ALIASES = {
    'critical': '严重', '严重': '严重', '危急': '严重',
    'high': '高危', '高危': '高危', '高': '高危',
    'medium': '中危', '中危': '中危', '中': '中危', 'moderate': '中危',
    'low': '低危', '低危': '低危', '低': '低危', 'info': '低危', 'lowinfo': '低危',
}


def _as_datetime(value):
    """表单给的是 date,模型存的是 datetime —— 补成当天零点。"""
    if not value:
        return None
    return datetime(value.year, value.month, value.day)


def parse_findings(text):
    """把粘贴的多行文本解析成发现列表。

    每行格式（分隔符支持半角 ``|``、全角 ``｜`` 与 Tab）::

        等级 | 标题
        等级 | 规则编号 | 标题
        等级 | 规则编号 | 标题 | 位置

    等级支持中英文写法（严重/Critical、高危/High …）。
    解析不出等级的行按"中危"处理,标题为空的整行跳过 —— 不做静默丢弃,
    调用方会把跳过条数告诉用户。
    """
    parsed, skipped = [], 0
    for raw in (text or '').splitlines():
        line = raw.strip()
        if not line:
            continue
        parts = [p.strip() for p in re.split(r'[|｜\t]', line)]
        severity = _SEVERITY_ALIASES.get(parts[0].lower()) or _SEVERITY_ALIASES.get(parts[0])

        if severity is None:
            # 首段不是等级:整行当标题,按中危记
            severity, rule_id, title, location = '中危', '', line, ''
        else:
            # 按段数对齐,不能简单取首尾 —— 段数不同含义不同:
            #   等级|标题
            #   等级|规则|标题
            #   等级|规则|标题|位置
            rest = parts[1:]
            if len(rest) == 0:
                rule_id, title, location = '', '', ''
            elif len(rest) == 1:
                rule_id, title, location = '', rest[0], ''
            elif len(rest) == 2:
                rule_id, title, location = rest[0], rest[1], ''
            else:
                rule_id, title, location = rest[0], rest[1], rest[2]

        if not title:
            # 只有等级、没有标题的行没有意义,跳过并计数（调用方会告诉用户跳了几行,
            # 不做静默丢弃）
            skipped += 1
            continue
        parsed.append({'severity': severity, 'rule_id': rule_id,
                       'title': title[:200], 'location': location[:300]})
    return parsed, skipped


def sync_finding_counts(scan):
    """按发现明细重算各等级计数。扫描记录保存后调用。"""
    rows = (db.session.query(ScanFinding.severity, func.count(ScanFinding.id))
            .filter(ScanFinding.scan_id == scan.id)
            .group_by(ScanFinding.severity).all())
    counts = {severity: 0 for severity in SEVERITY_LABELS}
    for severity, n in rows:
        counts[severity] = n
    scan.critical_count = counts.get('严重', 0)
    scan.high_count = counts.get('高危', 0)
    scan.medium_count = counts.get('中危', 0)
    scan.low_count = counts.get('低危', 0)
    scan.total_findings = sum(counts.values())


def _visible_projects():
    """新建/编辑扫描时可选的关联项目。

    安全团队看到全部活跃项目;其他人只看自己的（虽然他们没有创建权限,
    这里仍保持一致的收窄逻辑,避免将来放开时留下越权口子）。
    """
    query = Project.query.filter_by(status='active')
    if not scan_scope_is_global(current_user):
        # 与 apply_scan_scope 用同一条规则 —— 两条规则不一致会出两种 bug:
        # 要么选不到项目,要么能选到本来看不见的项目的扫描。
        query = query.filter(or_(
            Project.owner_id == current_user.id,
            Project.id.in_(
                db.session.query(Vulnerability.project_id).filter(
                    Vulnerability.assignee_id == current_user.id)),
        ))
    return query.order_by(Project.name.asc()).all()


def _load_scan_or_404(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    if scan.is_deleted and not has_perm(current_user, PERM_SCAN_MANAGE):
        abort(404)
    if not can_view_scan(scan, current_user):
        log_audit(operator_id=current_user.id, resource_type='scan',
                  resource_id=scan.id, action='view_denied',
                  detail=f'越权访问扫描记录尝试：{scan.scan_code}')
        db.session.commit()
        abort(403)
    return scan


@bp.route('/')
@login_required
def index():
    """扫描结果列表。按类型 / 项目 / 状态 / 关键字筛选。"""
    if not has_perm(current_user, PERM_SCAN_VIEW):
        abort(403)

    scan_type = request.args.get('scan_type', '').strip()
    project_id = request.args.get('project_id', type=int)
    status = request.args.get('status', '').strip()
    keyword = request.args.get('keyword', '').strip()

    query = apply_scan_scope(Scan.query.filter_by(is_deleted=False), current_user)

    if scan_type in SCAN_TYPE_LABELS:
        query = query.filter(Scan.scan_type == scan_type)
    if project_id:
        query = query.filter(Scan.project_id == project_id)
    if status in SCAN_STATUS_LABELS:
        query = query.filter(Scan.status == status)
    if keyword:
        like = f'%{keyword}%'
        query = query.filter(or_(Scan.target.ilike(like), Scan.tool.ilike(like),
                                 Scan.scan_code.ilike(like)))

    # 三个子分类各自的条数（页签上的数字）。必须走数据范围 ——
    # 直接 group by 会把别人项目的数量也统计进去,等于泄漏。
    type_counts = {
        key: apply_scan_scope(
            Scan.query.filter_by(is_deleted=False, scan_type=key), current_user
        ).count()
        for key in SCAN_TYPE_LABELS
    }

    page = request.args.get('page', 1, type=int)
    pagination = (query.options(joinedload(Scan.project), joinedload(Scan.creator))
                  .order_by(Scan.created_at.desc())
                  .paginate(page=page, per_page=PER_PAGE, error_out=False))

    return render_template(
        'scans/list.html',
        scans=pagination.items,
        pagination=pagination,
        type_counts=type_counts,
        projects=_all_visible_project_names(),
        filters={'scan_type': scan_type, 'project_id': project_id,
                 'status': status, 'keyword': keyword},
        scope_label=scan_scope_label(current_user),
        title='安全扫描',
    )


def _all_visible_project_names():
    """列表筛选用的项目下拉（只列有可见扫描的项目）。"""
    rows = (apply_scan_scope(Scan.query.filter(Scan.is_deleted.is_(False)), current_user)
            .with_entities(Scan.project_id).distinct().all())
    ids = [r[0] for r in rows if r[0]]
    if not ids:
        return []
    return Project.query.filter(Project.id.in_(ids)).order_by(Project.name.asc()).all()


@bp.route('/<int:scan_id>')
@login_required
def detail(scan_id):
    """扫描详情与发现明细。"""
    if not has_perm(current_user, PERM_SCAN_VIEW):
        abort(403)

    scan = _load_scan_or_404(scan_id)
    findings = (scan.findings if isinstance(scan.findings, list)
                else ScanFinding.query.filter_by(scan_id=scan.id)
                .order_by(ScanFinding.severity.desc(), ScanFinding.id.asc()).all())

    # 按等级排序展示:严重 -> 高危 -> 中危 -> 低危
    order = {severity: index for index, severity in enumerate(SEVERITY_LABELS)}
    findings = sorted(findings, key=lambda f: (order.get(f.severity, 99), f.id))

    return render_template(
        'scans/detail.html',
        scan=scan,
        findings=findings,
        can_triage=has_perm(current_user, PERM_SCAN_TRIAGE),
        can_convert=has_perm(current_user, PERM_SCAN_CONVERT),
        can_manage=has_perm(current_user, PERM_SCAN_MANAGE),
        assignees=_assignee_choices(),
        title=f'扫描详情 {scan.scan_code}',
    )


def _assignee_choices():
    return (User.query.filter(User.role.in_(['developer', 'test_lead']))
            .order_by(User.username.asc()).all())


@bp.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    """录入一次扫描记录（可同时粘贴发现明细）。"""
    if not has_perm(current_user, PERM_SCAN_CREATE):
        abort(403)

    form = ScanForm()
    form.project_id.choices = [(0, '不关联项目')] + [
        (project.id, project.name) for project in _visible_projects()
    ]

    if request.method == 'GET':
        form.scan_type.data = request.args.get('scan_type', 'sast')

    if form.validate_on_submit():
        project = Project.query.get(form.project_id.data) if form.project_id.data else None
        scan = Scan(
            scan_code=_generate_scan_code(),
            scan_type=form.scan_type.data,
            project_id=project.id if project else None,
            creator_id=current_user.id,
            tool=form.tool.data,
            target=form.target.data,
            status=form.status.data,
            started_at=_as_datetime(form.started_at.data),
            finished_at=_as_datetime(form.finished_at.data),
            note=form.note.data,
        )
        db.session.add(scan)
        db.session.flush()

        parsed, skipped = parse_findings(form.findings_text.data)
        for item in parsed:
            db.session.add(ScanFinding(scan_id=scan.id, **item))
        db.session.flush()
        sync_finding_counts(scan)

        log_audit(
            operator_id=current_user.id, resource_type='scan', resource_id=scan.id,
            action='create',
            detail=f'录入{SCAN_TYPE_LABELS.get(scan.scan_type, "")}记录 {scan.scan_code}'
                   f'（{scan.tool or "未填工具"}），发现 {scan.total_findings} 条'
        )
        db.session.commit()

        message = f'扫描记录 {scan.scan_code} 已保存，共 {scan.total_findings} 条发现'
        if skipped:
            message += f'（{skipped} 行无法解析已跳过）'
        flash(message, 'success')
        return redirect(url_for('scans.detail', scan_id=scan.id))

    return render_template('scans/form.html', form=form, scan=None,
                           tool_suggestions=SCAN_TOOL_SUGGESTIONS,
                           title='录入扫描记录')


@bp.route('/<int:scan_id>/edit', methods=['GET', 'POST'])
@login_required
def edit(scan_id):
    """编辑扫描记录的基本信息。发现明细在详情页单独维护。"""
    if not has_perm(current_user, PERM_SCAN_MANAGE):
        abort(403)

    scan = Scan.query.get_or_404(scan_id)
    form = ScanForm(obj=scan)
    form.project_id.choices = [(0, '不关联项目')] + [
        (project.id, project.name) for project in _visible_projects()
    ]

    if form.validate_on_submit():
        before_status = scan.status
        project = Project.query.get(form.project_id.data) if form.project_id.data else None
        scan.scan_type = form.scan_type.data
        scan.project_id = project.id if project else None
        scan.tool = form.tool.data
        scan.target = form.target.data
        scan.status = form.status.data
        scan.started_at = _as_datetime(form.started_at.data)
        scan.finished_at = _as_datetime(form.finished_at.data)
        scan.note = form.note.data

        log_audit(
            operator_id=current_user.id, resource_type='scan', resource_id=scan.id,
            action='edit_scan',
            from_status=before_status, to_status=scan.status,
            detail=f'编辑扫描记录 {scan.scan_code}'
        )
        db.session.commit()
        flash(f'扫描记录 {scan.scan_code} 已更新', 'success')
        return redirect(url_for('scans.detail', scan_id=scan.id))

    return render_template('scans/form.html', form=form, scan=scan,
                           tool_suggestions=SCAN_TOOL_SUGGESTIONS,
                           title='编辑扫描记录')


@bp.route('/<int:scan_id>/delete', methods=['POST'])
@login_required
def delete(scan_id):
    """软删除扫描记录（可恢复）。只有管理员能删。"""
    if not has_perm(current_user, PERM_SCAN_MANAGE):
        abort(403)

    scan = Scan.query.get_or_404(scan_id)
    scan.is_deleted = True
    scan.deleted_at = datetime.utcnow()
    log_audit(operator_id=current_user.id, resource_type='scan', resource_id=scan.id,
              action='delete_scan', detail=f'删除扫描记录 {scan.scan_code}')
    db.session.commit()
    flash(f'扫描记录 {scan.scan_code} 已删除', 'info')
    return redirect(url_for('scans.index'))


@bp.route('/finding/<int:finding_id>/ignore', methods=['POST'])
@login_required
def ignore_finding(finding_id):
    """把一条发现标记为忽略（误报 / 风险接受）。

    对应业界的 "dismiss alert" —— 只有安全团队有权限,开发人员没有。
    """
    if not has_perm(current_user, PERM_SCAN_TRIAGE):
        abort(403)

    finding = ScanFinding.query.get_or_404(finding_id)
    _load_scan_or_404(finding.scan_id)

    if finding.status == 'converted':
        flash('该发现已转为漏洞，不能再忽略', 'warning')
        return redirect(url_for('scans.detail', scan_id=finding.scan_id))

    finding.status = 'ignored'
    finding.handled_by_id = current_user.id
    finding.handled_at = datetime.utcnow()
    log_audit(operator_id=current_user.id, resource_type='scan',
              resource_id=finding.scan_id, action='ignore_finding',
              detail=f'忽略扫描发现：{finding.title}')
    db.session.commit()
    flash(f'发现「{finding.title}」已标记为忽略', 'info')
    return redirect(url_for('scans.detail', scan_id=finding.scan_id))


@bp.route('/finding/<int:finding_id>/reopen', methods=['POST'])
@login_required
def reopen_finding(finding_id):
    """把忽略掉的发现恢复为待处理。"""
    if not has_perm(current_user, PERM_SCAN_TRIAGE):
        abort(403)

    finding = ScanFinding.query.get_or_404(finding_id)
    _load_scan_or_404(finding.scan_id)
    if finding.status == 'ignored':
        finding.status = 'open'
        finding.handled_by_id = current_user.id
        finding.handled_at = datetime.utcnow()
        log_audit(operator_id=current_user.id, resource_type='scan',
                  resource_id=finding.scan_id, action='reopen_finding',
                  detail=f'恢复扫描发现：{finding.title}')
        db.session.commit()
        flash(f'发现「{finding.title}」已恢复为待处理', 'success')
    return redirect(url_for('scans.detail', scan_id=finding.scan_id))


@bp.route('/<int:scan_id>/convert', methods=['POST'])
@login_required
def convert_findings(scan_id):
    """把勾选的发现转成漏洞记录，进入"待修复 → 已修复 → 已闭环"的流转闭环。

    这是 SDL 的关键一环:扫描只负责"发现",真正推动修复的是漏洞流程。
    刻意做成**手动勾选**而不是自动全转 —— 业界一致建议先梳理再分派,
    否则低危噪音会把开发淹没。
    """
    if not has_perm(current_user, PERM_SCAN_CONVERT):
        abort(403)

    scan = _load_scan_or_404(scan_id)
    if not scan.project_id:
        flash('该扫描未关联项目，无法转成漏洞。请先编辑扫描记录并选择项目。', 'danger')
        return redirect(url_for('scans.detail', scan_id=scan.id))

    finding_ids = [int(v) for v in request.form.getlist('finding_ids') if v.isdigit()]
    if not finding_ids:
        flash('请先勾选要转成漏洞的发现', 'warning')
        return redirect(url_for('scans.detail', scan_id=scan.id))

    assignee_id = request.form.get('assignee_id', type=int) or None
    if assignee_id and not User.query.get(assignee_id):
        assignee_id = None

    project = Project.query.get(scan.project_id)
    candidates = ScanFinding.query.filter(
        ScanFinding.id.in_(finding_ids),
        ScanFinding.scan_id == scan.id,
        ScanFinding.status == 'open',
    ).all()
    if not candidates:
        flash('勾选的发现都已被处置（已转漏洞或已忽略），没有可转换的项', 'warning')
        return redirect(url_for('scans.detail', scan_id=scan.id))

    created = []
    for finding in candidates:
        vuln = Vulnerability(
            vuln_code=generate_vuln_code(),
            title=finding.title,
            description=_finding_to_description(finding, scan),
            project_id=scan.project_id,
            task_id=scan.task_id,
            source=SCAN_TYPE_TO_VULN_SOURCE.get(scan.scan_type, 'security_scan'),
            severity=finding.severity,
            vuln_type=guess_vuln_type(finding.rule_id, finding.title),
            risk_score=calculate_risk_score(finding.severity,
                                            project.criticality if project else None),
            status=STATUS_PENDING,
            creator_id=current_user.id,
            assignee_id=assignee_id,
            due_date=calculate_due_date(finding.severity),
        )
        db.session.add(vuln)
        db.session.flush()
        finding.status = 'converted'
        finding.vulnerability_id = vuln.id
        finding.handled_by_id = current_user.id
        finding.handled_at = datetime.utcnow()
        created.append(vuln)

    log_audit(
        operator_id=current_user.id, resource_type='scan', resource_id=scan.id,
        action='convert_findings',
        detail=f'把 {len(created)} 条扫描发现转为漏洞（{scan.scan_code}）'
    )
    db.session.commit()

    flash(f'已从扫描发现创建 {len(created)} 条漏洞，请到漏洞管理中跟进修复', 'success')
    return redirect(url_for('scans.detail', scan_id=scan.id))


def _finding_to_description(finding, scan):
    """把发现的关键信息拼成漏洞描述，便于修复人直接照做。"""
    parts = ['<p>该问题由安全扫描自动发现。</p>']
    meta = []
    if scan.tool:
        meta.append(f'扫描工具：{scan.tool}')
    meta.append(f'扫描类型：{SCAN_TYPE_LABELS.get(scan.scan_type, scan.scan_type)}')
    if finding.rule_id:
        meta.append(f'规则编号：{finding.rule_id}')
    if finding.location:
        meta.append(f'位置：{finding.location}')
    if meta:
        parts.append('<p>' + '<br>'.join(meta) + '</p>')
    if finding.detail:
        parts.append(f'<p>{finding.detail}</p>')
    parts.append('<p>请确认后按修复建议整改，整改完成提交复测。</p>')
    return ''.join(parts)


def _generate_scan_code():
    """扫描编号:SCAN-日期-序号，同日多条自动递增。"""
    today = datetime.utcnow().strftime('%Y%m%d')
    prefix = f'SCAN-{today}-'
    latest = (Scan.query.filter(Scan.scan_code.like(f'{prefix}%'))
              .order_by(Scan.scan_code.desc()).first())
    seq = 1
    if latest:
        try:
            seq = int(latest.scan_code.rsplit('-', 1)[1]) + 1
        except (IndexError, ValueError):
            seq = Scan.query.filter(Scan.scan_code.like(f'{prefix}%')).count() + 1
    return f'{prefix}{seq:04d}'
