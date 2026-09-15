import csv
import html as _html
import io
import json
import os
import re
import secrets
from datetime import datetime, timedelta
from html.parser import HTMLParser

from flask import (Blueprint, render_template, redirect, url_for, flash,
                   request, abort, send_file, jsonify, make_response, current_app)
from flask_login import login_required, current_user
from sqlalchemy import or_
from sqlalchemy.orm import joinedload
from app import db
from app.models import Vulnerability, Project, Task, TestCase, User
from app.forms import (
    VULN_SEVERITY_CHOICES, VULN_SEVERITY_VALUES, VULN_SOURCE_CHOICES,
    VULN_SOURCE_VALUES, VULN_TYPE_CHOICES, VULN_TYPE_VALUES, VulnerabilityForm,
)
from app.permissions import (
    PERM_VULN_ASSIGN, PERM_VULN_CREATE, PERM_VULN_DELETE, PERM_VULN_EDIT,
    PERM_VULN_EXPORT, PERM_VULN_MANAGE, ROLE_GUEST, apply_vuln_scope,
    can_access_testing, can_view_vulnerability, has_perm, is_admin
)
from app.services import (
    calculate_due_date, calculate_risk_score,
    generate_vuln_code, log_audit, safe_next_url
)
from app.state_machine import (
    ALL_STATUSES, STATUS_LABELS, TERMINAL_STATUSES, TRANSITIONS,
    apply_transition, available_actions, can_transition, is_authorized,
    status_label
)

bp = Blueprint('vulnerabilities', __name__, url_prefix='/vulnerabilities')

# ---- 截图存储 ----
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
#: 默认上传目录。实际取值走 Config.UPLOAD_DIR —— 测试会把它改到临时目录,
#: 否则跑一次测试就往仓库里写一堆图片。
_DEFAULT_UPLOAD_DIR = os.path.join(_ROOT, 'instance', 'uploads', 'vulns')


def upload_dir():
    return current_app.config.get('UPLOAD_DIR') or _DEFAULT_UPLOAD_DIR


ALLOWED_IMG = {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp'}
NAME_RE = re.compile(r'^[0-9a-f]{32}\.(png|jpg|jpeg|gif|webp|bmp)$')


def collect_referenced_screenshots(description_html, extra_files=None):
    """从描述 HTML 里解析出本漏洞引用的**本地**图片文件名。

    描述里的 `<img src>` 是唯一真相 —— 富文本编辑器插入图片时就直接写进
    description。`screenshots` 列存的是这个集合的派生缓存,用途只有一个:
    删除漏洞时知道该清理哪些文件。

    两个关键点:

    - 用 ``NAME_RE`` 过滤,只有本地上传生成的 32 位十六进制文件名能进来。
      外部 URL、`../` 路径穿越会被自然挡掉,不放松这条既有防线。
    - ``upload_image`` 在用户还在编辑时就调用了（粘贴即上传）,那时漏洞对象
      可能还不存在,所以不能在上传时写入 —— 只能在保存时统一派生。

    原实现里 `screenshots` 列只有一个写入点（`publish_from_case`）,
    且全项目没有任何渲染点,属于只写不读的死数据。
    """
    names = []
    for src in re.findall(r'<img[^>]+src="([^"]*)"', description_html or '', re.I):
        basename = os.path.basename(src.split('?')[0].split('#')[0])
        if NAME_RE.match(basename) and basename not in names:
            names.append(basename)
    for name in extra_files or []:
        if NAME_RE.match(name) and name not in names:
            names.append(name)
    return names


def sync_screenshots(vuln, extra_files=None):
    """按描述里的引用重建 vuln.screenshots。保存漏洞前调用。"""
    vuln.screenshots = json.dumps(
        collect_referenced_screenshots(vuln.description, extra_files),
        ensure_ascii=False
    )


def save_uploaded_screenshots(files):
    """把上传的图片文件落盘,返回保存后的文件名列表。"""
    saved = []
    if not files:
        return saved
    os.makedirs(upload_dir(), exist_ok=True)
    for f in files:
        if not f or not f.filename:
            continue
        ext = os.path.splitext(f.filename)[1].lower()
        if ext not in ALLOWED_IMG:
            continue
        name = secrets.token_hex(16) + ext
        f.save(os.path.join(upload_dir(), name))
        saved.append(name)
    return saved


@bp.route('/screenshot/<path:filename>')
@login_required
def screenshot(filename):
    """服务漏洞截图。

    两道约束:

    1. 只放行本地上传生成的 32 位十六进制文件名（``NAME_RE``）——
       这是这条链路上唯一的路径穿越防线,不要放宽;
    2. 必须登录。此前这个路由**没有** ``@login_required``（同文件其余 14 个
       路由都有）,未登录也能按文件名取图,是个真实的鉴权缺口。
    """
    if not NAME_RE.match(filename):
        abort(404)
    path = os.path.join(upload_dir(), filename)
    if not os.path.isfile(path):
        abort(404)
    return send_file(path)


# ---- 富文本描述(支持文字中穿插截图) ----
_RICH_TAGS = {
    'p', 'div', 'br', 'b', 'strong', 'i', 'em', 'u', 's', 'span',
    'a', 'ul', 'ol', 'li', 'blockquote', 'code', 'pre', 'img',
    'h1', 'h2', 'h3', 'h4', 'table', 'thead', 'tbody', 'tr', 'td', 'th',
}
_VOID_TAGS = {'img', 'br', 'hr'}


class _RichSanitizer(HTMLParser):
    """仅保留允许的标签/属性,文本一律转义,杜绝 XSS。"""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.open_tags = []
        self.suppress_tag = None  # script/style 等禁止标签:连带忽略其内容

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if self.suppress_tag:
            return
        if tag not in _RICH_TAGS:
            if tag in ('script', 'style', 'iframe', 'object', 'embed', 'svg', 'math', 'template'):
                self.suppress_tag = tag
            return
        allowed = []
        for key, value in attrs:
            key = key.lower()
            value = value or ''
            if tag == 'img' and key == 'src' and value.startswith(('/', 'http://', 'https://')):
                allowed.append((key, value))
            elif tag == 'img' and key == 'alt':
                allowed.append((key, value))
            elif tag == 'a' and key == 'href' and value.startswith(('/', 'http://', 'https://')):
                allowed.append((key, value))
        attr = ''.join(' %s="%s"' % (key, _html.escape(value, quote=True)) for key, value in allowed)
        self.parts.append('<%s%s>' % (tag, attr))
        if tag not in _VOID_TAGS:
            self.open_tags.append(tag)

    def handle_startendtag(self, tag, attrs):
        # <img/> <br/> 之类
        tag = tag.lower()
        if tag in _RICH_TAGS:
            self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        tag = tag.lower()
        if self.suppress_tag:
            if tag == self.suppress_tag:
                self.suppress_tag = None
            return
        if tag in _VOID_TAGS or tag not in self.open_tags:
            return
        for i in range(len(self.open_tags) - 1, -1, -1):
            if self.open_tags[i] == tag:
                self.open_tags.pop(i)
                break
        self.parts.append('</%s>' % tag)

    def handle_data(self, data):
        if self.suppress_tag:
            return
        # 换行转 <br>。textarea 里输入的多行描述若原样存储,经 HTML 渲染会被
        # 折叠成一行 —— 这是"rows 生效了但换行还是丢了"的成因。
        #
        # 放在文本节点里做（而不是存库后对整段 HTML 做 replace），是因为后者会
        # 连 <pre> 内的换行和标签属性一起改掉。存进去就是 <br>,编辑器回填时
        # contenteditable 也能正确还原成换行,来回保存不会累积。
        text = _html.escape(data).replace('\r\n', '\n').replace('\r', '\n')
        self.parts.append(text.replace('\n', '<br>'))


def sanitize_inline_html(source):
    """清洗富文本描述,只保留白名单标签与属性。"""
    if not source:
        return ''
    parser = _RichSanitizer()
    parser.feed(source)
    for tag in reversed(parser.open_tags):
        parser.parts.append('</%s>' % tag)
    return ''.join(parser.parts)


@bp.route('/upload-image', methods=['POST'])
@login_required
def upload_image():
    """富文本编辑器“插入截图”时即时上传,返回图片 URL。"""
    if not has_perm(current_user, PERM_VULN_CREATE):
        abort(403)
    files = request.files.getlist('image')
    file = files[0] if files else None
    saved = save_uploaded_screenshots([file]) if file else []
    if not saved:
        return jsonify(ok=False, error='仅支持图片文件(png/jpg/jpeg/gif/webp)'), 400
    return jsonify(ok=True, url=url_for('vulnerabilities.screenshot', filename=saved[0]))


PER_PAGE = 20

#: 未闭环的状态（用于"逾期未修复"筛选）
_OPEN_STATUSES = tuple(s for s in ALL_STATUSES if s not in TERMINAL_STATUSES)


def _parse_date(value):
    try:
        return datetime.strptime(value, '%Y-%m-%d')
    except (TypeError, ValueError):
        return None


def _build_vuln_query():
    """构造漏洞查询:上下文(任务/项目/用例/回收站) + 数据范围 + 全部筛选条件。

    列表页和 CSV 导出共用这一个函数。导出另写一份过滤逻辑会多出一个越权入口
    —— 导出的行必须和页面看到的行完全一致。
    返回 ``(query, context)``。
    """
    task_id = request.args.get('task_id', type=int)
    project_id = request.args.get('project_id', type=int)
    case_id = request.args.get('case_id', type=int)
    trash = request.args.get('trash', type=int) == 1  # 回收站:只看已删除

    query = Vulnerability.query.filter_by(is_deleted=trash)

    current_task = None
    if task_id:
        current_task = Task.query.get_or_404(task_id)
        if not is_admin(current_user) and current_task.tester_id != current_user.id:
            abort(403)
        query = query.filter(Vulnerability.task_id == task_id)

    current_project = Project.query.get(project_id) if project_id else None
    if project_id:
        query = query.filter(Vulnerability.project_id == project_id)

    # 定位到某个测试用例的漏洞列表(仅当从用例"新增漏洞/发布"跳转时带 case_id)
    current_test_case = None
    if case_id:
        case_query = TestCase.query
        if task_id:
            case_query = case_query.filter_by(task_id=task_id)
        current_test_case = case_query.filter_by(id=case_id).first()
        if not current_test_case:
            abort(404)
        query = query.filter(Vulnerability.test_case_id == case_id)

    # 数据范围:与详情页 can_view_vulnerability 同源
    query = apply_vuln_scope(query, current_user)

    filters = {
        'title': request.args.get('title', '').strip(),
        'status': request.args.get('status', '').strip(),
        'source': request.args.get('source', '').strip(),
        'severity': request.args.get('severity', '').strip(),
        'vuln_type': request.args.get('vuln_type', '').strip(),
        'assignee_id': request.args.get('assignee_id', type=int),
        'date_from': request.args.get('date_from', '').strip(),
        'date_to': request.args.get('date_to', '').strip(),
        'overdue': request.args.get('overdue', type=int) == 1,
    }

    if filters['title']:
        like = f"%{filters['title']}%"
        query = query.filter(or_(Vulnerability.title.ilike(like),
                                 Vulnerability.vuln_code.ilike(like)))
    if filters['status'] in STATUS_LABELS:
        query = query.filter(Vulnerability.status == filters['status'])
    if filters['source'] in VULN_SOURCE_VALUES:
        query = query.filter(Vulnerability.source == filters['source'])
    if filters['severity'] in VULN_SEVERITY_VALUES:
        query = query.filter(Vulnerability.severity == filters['severity'])
    if filters['vuln_type'] in VULN_TYPE_VALUES:
        query = query.filter(Vulnerability.vuln_type == filters['vuln_type'])
    if filters['assignee_id']:
        query = query.filter(Vulnerability.assignee_id == filters['assignee_id'])

    start = _parse_date(filters['date_from'])
    if start:
        query = query.filter(Vulnerability.created_at >= start)
    end = _parse_date(filters['date_to'])
    if end:
        query = query.filter(Vulnerability.created_at < end + timedelta(days=1))

    if filters['overdue']:
        # 已过 SLA 截止时间、且仍未闭环
        query = query.filter(Vulnerability.due_date.isnot(None),
                             Vulnerability.due_date < datetime.utcnow(),
                             Vulnerability.status.in_(_OPEN_STATUSES))

    context = {
        'current_task': current_task,
        'current_project': current_project,
        'current_test_case': current_test_case,
        'trash': trash,
    }
    return query, filters, context


def _csv_safe(value):
    """防 CSV 注入:以 = + - @ 开头的单元格前置单引号。

    Excel 会把这些内容当公式执行,是导出功能里的经典问题。
    """
    text = '' if value is None else str(value)
    if text[:1] in ('=', '+', '-', '@'):
        return "'" + text
    return text


def _export_csv(query):
    """导出当前筛选结果为 CSV。"""
    output = io.StringIO()
    # BOM 必须写进内容里。只设 Content-Type 的 charset=utf-8-sig 是没用的:
    # make_response() 已经把 body 按 UTF-8 编码完了,之后改 header 不会补 BOM,
    # Excel 打开中文依旧乱码。
    output.write('﻿')
    writer = csv.writer(output)
    writer.writerow(['漏洞编号', '漏洞标题', '严重等级', '风险评分', '状态', '漏洞类型',
                     '漏洞来源', '所属项目', '关联任务', '责任人', '创建人',
                     '创建时间', 'SLA 截止', '关闭时间'])
    for vuln in query.options(joinedload(Vulnerability.project),
                              joinedload(Vulnerability.task),
                              joinedload(Vulnerability.assignee),
                              joinedload(Vulnerability.creator)
                              ).order_by(Vulnerability.created_at.desc()).all():
        writer.writerow([
            _csv_safe(vuln.vuln_code),
            _csv_safe(vuln.title),
            _csv_safe(vuln.severity),
            vuln.risk_score if vuln.risk_score is not None else '',
            status_label(vuln.status),
            _csv_safe(dict(VULN_TYPE_CHOICES).get(vuln.vuln_type, vuln.vuln_type or '')),
            _csv_safe(dict(VULN_SOURCE_CHOICES).get(vuln.source, vuln.source or '')),
            _csv_safe(vuln.project.name if vuln.project else ''),
            _csv_safe(vuln.task.name if vuln.task else ''),
            _csv_safe(vuln.assignee.username if vuln.assignee else ''),
            _csv_safe(vuln.creator.username if vuln.creator else ''),
            vuln.created_at.strftime('%Y-%m-%d %H:%M') if vuln.created_at else '',
            vuln.due_date.strftime('%Y-%m-%d') if vuln.due_date else '',
            vuln.closed_at.strftime('%Y-%m-%d %H:%M') if vuln.closed_at else '',
        ])

    response = make_response(output.getvalue())
    # utf-8-sig 带 BOM,否则 Excel 打开中文全是乱码
    response.headers['Content-Type'] = 'text/csv; charset=utf-8-sig'
    response.headers['Content-Disposition'] = 'attachment; filename=vulnerabilities.csv'
    return response


@bp.route('/management')
@login_required
def management():
    """漏洞管理列表:检索筛选 + 分页 + 导出。

    权限:管理员/测试主管可查看全部;测试人员只能看到自己测出来的漏洞
    (数据范围统一由 permissions.apply_vuln_scope 决定)。
    """
    if not has_perm(current_user, PERM_VULN_MANAGE):
        abort(403)

    query, filters, context = _build_vuln_query()

    if request.args.get('export') == '1':
        log_audit(
            operator_id=current_user.id,
            resource_type='vulnerability',
            resource_id=0,
            action='export',
            detail='导出漏洞列表 CSV'
        )
        db.session.commit()
        return _export_csv(query)

    page = request.args.get('page', 1, type=int)
    pagination = (query.options(
        joinedload(Vulnerability.task),
        joinedload(Vulnerability.project),
        joinedload(Vulnerability.assignee)
    ).order_by(Vulnerability.created_at.desc())
     .paginate(page=page, per_page=PER_PAGE, error_out=False))

    assignees = (User.query.filter(User.role.in_(['developer', 'test_lead']))
                 .order_by(User.username.asc()).all())

    return render_template(
        'vulnerabilities/management.html',
        vulnerabilities=pagination.items,
        pagination=pagination,
        filters=filters,
        assignees=assignees,
        source_choices=VULN_SOURCE_CHOICES,
        severity_choices=VULN_SEVERITY_CHOICES,
        vuln_type_choices=VULN_TYPE_CHOICES,
        can_export=has_perm(current_user, PERM_VULN_EXPORT),
        **context
    )


@bp.route('/publish/<int:task_id>/<int:case_id>', methods=['GET', 'POST'])
@login_required
def publish_from_case(task_id, case_id):
    """从不通过测试用例发布漏洞。

    一个测试用例可关联多条漏洞,每次发布都会新增一条(标题/类型由发布人填写)。
    """
    if not has_perm(current_user, PERM_VULN_CREATE):
        abort(403)

    task = Task.query.get_or_404(task_id)
    test_case = TestCase.query.filter_by(id=case_id, task_id=task.id).first_or_404()
    if not is_admin(current_user) and task.tester_id != current_user.id:
        abort(403)
    if test_case.status != 'fail':
        flash('只有不通过的测试用例可以新增漏洞', 'warning')
        return redirect(url_for('projects.task_workflow', id=task.id))

    form = VulnerabilityForm()
    projects = Project.query.filter_by(status='active').order_by(Project.name.asc()).all()
    form.project_id.choices = [(project.id, project.name) for project in projects]
    form.task_id.choices = [(task.id, task.name)]
    form.assignee_id.validators = []
    form.assignee_id.choices = [(0, '待分配漏洞修复人')] + [(user.id, user.username) for user in User.query.filter(User.role.in_(['developer', 'test_lead'])).order_by(User.username.asc())]

    if request.method == 'GET':
        # 标题预填用例名,但允许发布人改成自定义标题
        form.title.data = test_case.name
        form.description.data = f'测试用例 No.{test_case.case_number}：{test_case.name} 未通过'
        form.project_id.data = task.project_id
        form.task_id.data = task.id
        form.source.data = 'manual'
        form.severity.data = '中危'

    if form.validate_on_submit():
        project = Project.query.get(form.project_id.data)
        if not project:
            abort(400)
        vulnerability = Vulnerability(
            vuln_code=generate_vuln_code(),
            title=form.title.data,
            description=sanitize_inline_html(form.description.data),
            project_id=project.id,
            task_id=task.id,
            test_case_id=test_case.id,
            source=form.source.data,
            severity=form.severity.data,
            vuln_type=form.vuln_type.data or None,
            risk_score=calculate_risk_score(form.severity.data, project.criticality),
            status='pending',
            creator_id=current_user.id,
            due_date=calculate_due_date(form.severity.data)
        )
        saved = save_uploaded_screenshots(request.files.getlist('screenshots'))
        sync_screenshots(vulnerability, extra_files=saved)
        db.session.add(vulnerability)
        db.session.commit()
        flash(f'漏洞“{vulnerability.title}”已发布', 'success')
        # 跳到该测试用例的漏洞列表
        return redirect(url_for(
            'vulnerabilities.management',
            task_id=task.id,
            case_id=test_case.id
        ))

    init_html = sanitize_inline_html(form.description.data or '')
    return render_template('vulnerabilities/publish.html', form=form, task=task, test_case=test_case, init_html=init_html, title='漏洞发布')


# 创建漏洞
@bp.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    """创建漏洞 - 测试人员、测试主管、管理员

    从“漏洞管理”带 task_id / project_id 进入时,预选对应的项目与任务;
    创建成功后跳回“漏洞管理”并定位到该漏洞所属的任务/项目,而不是跳到通用漏洞列表。
    """
    if not has_perm(current_user, PERM_VULN_CREATE):
        abort(403)

    task_id = request.args.get('task_id', type=int)
    project_id = request.args.get('project_id', type=int)

    form = VulnerabilityForm()
    # 填充项目、任务、用户下拉选项
    form.project_id.choices = [
        (p.id, p.name) for p in Project.query.filter_by(status='active').order_by(Project.name.asc()).all()
    ]
    task_query = Task.query
    if project_id:
        task_query = task_query.filter_by(project_id=project_id)
    # 补上"无关联任务":否则项目下一条任务都没有时,这个下拉没有任何可选值,
    # 表单永远提交不了。
    form.task_id.choices = [(0, '无关联任务')] + [
        (t.id, t.name) for t in task_query.order_by(Task.created_at.desc()).all()
    ]
    # 补上"待分配":责任人可以留空,后续在编辑页改派
    form.assignee_id.choices = [(0, '待分配漏洞修复人')] + [
        (u.id, u.username) for u in User.query.filter(User.role.in_(['developer', 'test_lead']))
    ]

    if request.method == 'GET':
        # 从管理页带来的筛选上下文:预选对应项目/任务
        if project_id and any(pid == project_id for pid, _ in form.project_id.choices):
            form.project_id.data = project_id
        if task_id and any(tid == task_id for tid, _ in form.task_id.choices):
            form.task_id.data = task_id

    if form.validate_on_submit():
        project = Project.query.get(form.project_id.data)
        # 计算风险评分
        risk_score = calculate_risk_score(form.severity.data, project.criticality)
        # 计算 SLA 截止日期
        due_date = calculate_due_date(form.severity.data)

        vuln = Vulnerability(
            vuln_code=generate_vuln_code(),
            title=form.title.data,
            description=sanitize_inline_html(form.description.data),
            project_id=form.project_id.data,
            # 0 是"无关联任务"的哨兵值,要落成 NULL 而不是外键 0
            task_id=form.task_id.data or None,
            source=form.source.data,
            severity=form.severity.data,
            # 原实现漏了 vuln_type,经这个入口建的漏洞类型恒为 NULL,
            # 看板的"漏洞类型分布"会全部落到"未分类"
            vuln_type=form.vuln_type.data or None,
            risk_score=risk_score,
            status='pending',
            creator_id=current_user.id,
            assignee_id=form.assignee_id.data or None,
            due_date=due_date
        )
        # 显式上传的附件先落盘,再连同描述里引用的图片一起派生 screenshots
        saved = save_uploaded_screenshots(request.files.getlist('screenshots'))
        sync_screenshots(vuln, extra_files=saved)

        db.session.add(vuln)
        db.session.flush()  # 先取 vuln.id 供审计日志使用

        # 写入审计日志
        log_audit(
            operator_id=current_user.id,
            resource_type='vulnerability',
            resource_id=vuln.id,
            action='create',
            detail=f'创建漏洞：{vuln.title}'
        )
        db.session.commit()

        flash(f'漏洞 {vuln.vuln_code} 创建成功！', 'success')
        # 回到漏洞管理并定位到新漏洞所属的任务/项目,使其能被看到
        back_kwargs = {}
        if vuln.task_id:
            back_kwargs['task_id'] = vuln.task_id
        elif vuln.project_id:
            back_kwargs['project_id'] = vuln.project_id
        return redirect(url_for('vulnerabilities.management', **back_kwargs))

    return render_template('vulnerabilities/form.html', form=form, title='创建漏洞')


# 漏洞详情
@bp.route('/<int:id>')
@login_required
def detail(id):
    """查看漏洞详情。

    可见性统一走 permissions.can_view_vulnerability —— 与列表页的
    apply_vuln_scope 同源,避免"列表里看得见、点进去 403"的死链:

    - 管理员 / 测试主管:全部
    - 测试人员:本人测试发现的
    - 开发人员:指派给本人的
    - 业务人员:本人名下项目的
    - 访客:仅已闭环
    """
    vuln = Vulnerability.query.get_or_404(id)

    # 回收站里的漏洞只对能进回收站的角色可见(否则软删除形同虚设)
    if vuln.is_deleted and not has_perm(current_user, PERM_VULN_DELETE):
        abort(404)

    if not can_view_vulnerability(vuln, current_user):
        # 记录越权访问尝试,便于审计追溯
        log_audit(
            operator_id=current_user.id,
            resource_type='vulnerability',
            resource_id=vuln.id,
            action='view_denied',
            detail=f'越权访问尝试：{vuln.vuln_code}'
        )
        db.session.commit()
        abort(403)

    management = can_access_testing(current_user)

    # “返回”按角色给合适列表:测试权限回漏洞管理;业务/开发回该项目漏洞列表
    if management:
        back_url = url_for('vulnerabilities.management')
    elif vuln.project_id:
        back_url = url_for('projects.vulnerabilities', id=vuln.project_id)
    else:
        back_url = url_for('main.business')
    description_html = sanitize_inline_html(vuln.description or '')
    return render_template('vulnerabilities/detail.html', vuln=vuln, management=management,
                           back_url=back_url, description_html=description_html)


# 编辑漏洞详情(仅管理端)
@bp.route('/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit(id):
    """编辑漏洞标题/描述/来源/等级/责任人;项目与任务只读,等级变化自动重算评分与 SLA。

    状态不在此处修改 —— 见 app.state_machine。
    """
    if not has_perm(current_user, PERM_VULN_EDIT):
        abort(403)

    vuln = Vulnerability.query.get_or_404(id)
    # 光有编辑权限不够,还得是这条漏洞的可见方,否则 developer 能凭 URL 改别人的漏洞
    if not can_view_vulnerability(vuln, current_user):
        abort(403)

    form = VulnerabilityForm()
    form.project_id.validators = []
    form.task_id.validators = []
    form.assignee_id.validators = []
    form.project_id.choices = [(vuln.project_id or 0, vuln.project.name if vuln.project else '未关联项目')]
    form.task_id.choices = [(0, '无关联任务')] + [
        (t.id, t.name) for t in Task.query.filter_by(project_id=vuln.project_id)
        .order_by(Task.created_at.desc()).all()
    ]
    form.assignee_id.choices = [(0, '待分配漏洞修复人')] + [
        (u.id, u.username) for u in User.query.filter(User.role.in_(['developer', 'test_lead']))
        .order_by(User.username.asc())
    ]

    if request.method == 'GET':
        form.title.data = vuln.title
        form.description.data = vuln.description
        form.source.data = vuln.source
        form.severity.data = vuln.severity
        form.vuln_type.data = vuln.vuln_type or ''
        form.project_id.data = vuln.project_id or 0
        form.task_id.data = vuln.task_id or 0
        form.assignee_id.data = vuln.assignee_id or 0

    if form.validate_on_submit():
        project = Project.query.get(form.project_id.data) if form.project_id.data else None
        new_task_id = form.task_id.data or None
        # 任务必须属于所选项目,否则保持原任务
        if project and new_task_id:
            if not Task.query.filter_by(id=new_task_id, project_id=project.id).first():
                new_task_id = vuln.task_id
        old_severity = vuln.severity
        vuln.title = form.title.data
        vuln.description = sanitize_inline_html(form.description.data)
        vuln.source = form.source.data
        vuln.severity = form.severity.data
        vuln.vuln_type = form.vuln_type.data or None
        vuln.project_id = project.id if project else vuln.project_id
        vuln.task_id = new_task_id
        vuln.risk_score = calculate_risk_score(form.severity.data, project.criticality if project else None)
        # 仅在等级真的变了时才重算 SLA。原实现每次保存都重算,
        # 改个标题就把截止日期推到"今天 + SLA 天数",逾期统计会恒为 0。
        if form.severity.data != old_severity:
            vuln.due_date = calculate_due_date(form.severity.data)

        # 注:状态**不在这里改**。漏洞状态只能经 vulnerabilities.transition()
        # 走 app.state_machine 的校验,避免绕过状态机。

        # 改派修复人。原实现模板里有个 hidden 的 assignee_id 但后端从不读取,
        # 等于漏洞一旦创建就再也换不了责任人。
        new_assignee_id = form.assignee_id.data or None
        if has_perm(current_user, PERM_VULN_ASSIGN) and new_assignee_id != vuln.assignee_id:
            old_assignee = vuln.assignee.username if vuln.assignee else '未分配'
            vuln.assignee_id = new_assignee_id
            new_assignee = vuln.assignee.username if vuln.assignee else '未分配'
            log_audit(
                operator_id=current_user.id,
                resource_type='vulnerability',
                resource_id=vuln.id,
                action='reassign',
                detail=f'改派修复人：{old_assignee} → {new_assignee}'
            )

        # 截图:描述里的 <img> 就是唯一真相,这里按引用重建 screenshots 缓存。
        #
        # 原实现在这里读 `request.files['screenshots']` 和 `remove_screenshot`,
        # 但 edit.html 里根本没有这两个控件（那个 file input 连 name 都没有,
        # 只给 JS 的即时上传用）,而且表单也没加 enctype —— 整段是**永远不执行**
        # 的死代码。现在改为统一派生,不再需要模板配合。
        saved_attachments = save_uploaded_screenshots(request.files.getlist('screenshots'))
        sync_screenshots(vuln, extra_files=saved_attachments)

        log_audit(
            operator_id=current_user.id,
            resource_type='vulnerability',
            resource_id=vuln.id,
            action='edit',
            detail=f'编辑漏洞：{vuln.title}'
        )
        db.session.commit()
        flash(f'漏洞“{vuln.title}”已更新', 'success')
        return redirect(url_for('vulnerabilities.detail', id=vuln.id))

    init_html = sanitize_inline_html(vuln.description or '')
    return render_template('vulnerabilities/edit.html', form=form, vuln=vuln, init_html=init_html, title='编辑漏洞详情')


# 状态转换（修复 / 复测 / 误报 / 忽略 / 重开）
@bp.route('/<int:id>/transition/<string:action>', methods=['POST'])
@login_required
def transition(id, action):
    """漏洞状态流转 —— 系统里唯一的状态变更入口。

    规则全部来自 app.state_machine,这里只做 HTTP 层的事:取参、校验、flash、重定向。
    详情页的按钮由 available_actions() 渲染,和服务端校验同源。
    """
    vuln = Vulnerability.query.get_or_404(id)

    trans = TRANSITIONS.get(action)
    if trans is None:
        flash('无效的操作', 'danger')
        return redirect(url_for('vulnerabilities.detail', id=vuln.id))

    # 授权失败(角色不对、不是责任人)属于越权,给 403;
    # 源状态不匹配则多半是页面过期,flash 提示后回详情页。
    if not is_authorized(vuln, action, current_user):
        abort(403)

    ok, reason = can_transition(vuln, action, current_user)
    if not ok:
        flash(reason, 'danger')
        return redirect(url_for('vulnerabilities.detail', id=vuln.id))

    comment = request.form.get('verification_comment', '').strip()
    old_status, new_status = apply_transition(vuln, action, current_user, comment or None)
    db.session.commit()

    flash(f'漏洞状态已更新：{status_label(old_status)} → {status_label(new_status)}', 'success')
    # 若来自列表行内操作(带 back_url),回到该列表;否则回详情
    back_url = safe_next_url(request.form.get('back_url'))
    return redirect(back_url or url_for('vulnerabilities.detail', id=vuln.id))


# 批量软删除(漏洞管理多选删除)
@bp.route('/batch-delete', methods=['POST'])
@login_required
def batch_delete():
    """批量把所选漏洞移入回收站,操作后仍停留在原漏洞管理列表。测试权限仅能删自己创建的。"""
    if not has_perm(current_user, PERM_VULN_CREATE):
        abort(403)

    ids = [int(v) for v in request.form.getlist('vuln_ids') if v.isdigit()]
    now = datetime.utcnow()
    if not ids:
        flash('请先勾选要删除的漏洞', 'warning')
    else:
        vuln_query = Vulnerability.query.filter(Vulnerability.id.in_(ids))
        if not is_admin(current_user):
            vuln_query = vuln_query.filter(Vulnerability.creator_id == current_user.id)
        vulns = vuln_query.all()
        for vuln in vulns:
            vuln.is_deleted = True
            vuln.deleted_at = now
            log_audit(
                operator_id=current_user.id,
                resource_type='vulnerability',
                resource_id=vuln.id,
                action='delete',
                detail=f'删除漏洞：{vuln.vuln_code}'
            )
        db.session.commit()
        flash(f'已将 {len(vulns)} 条漏洞移至回收站', 'success')

    # 回到原管理列表上下文
    back = {}
    for key in ('task_id', 'project_id', 'case_id'):
        value = request.form.get(key, type=int)
        if value:
            back[key] = value
    return redirect(url_for('vulnerabilities.management', **back))


# 软删除
@bp.route('/<int:id>/delete', methods=['POST'])
@login_required
def delete(id):
    """软删除漏洞(移入回收站)。测试权限仅能删自己创建的。"""
    if not has_perm(current_user, PERM_VULN_CREATE):
        abort(403)

    vuln = Vulnerability.query.get_or_404(id)
    if not is_admin(current_user) and vuln.creator_id != current_user.id:
        abort(403)
    vuln.is_deleted = True
    vuln.deleted_at = datetime.utcnow()

    log_audit(
        operator_id=current_user.id,
        resource_type='vulnerability',
        resource_id=vuln.id,
        action='delete',
        detail=f'删除漏洞：{vuln.vuln_code}'
    )
    db.session.commit()

    flash('漏洞已移至回收站', 'info')
    # 带管理列表上下文(任务/项目/用例)删除时,回到同一个管理列表
    back = {}
    for key in ('task_id', 'project_id', 'case_id'):
        value = request.form.get(key, type=int)
        if value:
            back[key] = value
    if back:
        return redirect(url_for('vulnerabilities.management', **back))
    return redirect(url_for('vulnerabilities.management'))


# 恢复漏洞
@bp.route('/<int:id>/restore', methods=['POST'])
@login_required
def restore(id):
    """从回收站恢复漏洞。测试权限仅能恢复自己创建的。"""
    if not has_perm(current_user, PERM_VULN_CREATE):
        abort(403)

    vuln = Vulnerability.query.get_or_404(id)
    if not is_admin(current_user) and vuln.creator_id != current_user.id:
        abort(403)
    vuln.is_deleted = False
    vuln.deleted_at = None

    log_audit(
        operator_id=current_user.id,
        resource_type='vulnerability',
        resource_id=vuln.id,
        action='restore',
        detail=f'恢复漏洞：{vuln.vuln_code}'
    )
    db.session.commit()

    flash('漏洞已恢复', 'success')
    # 从回收站恢复后,继续停留在回收站视图(带原上下文)
    back = {'trash': 1}
    for key in ('task_id', 'project_id', 'case_id'):
        value = request.form.get(key, type=int)
        if value:
            back[key] = value
    return redirect(url_for('vulnerabilities.management', **back))

@bp.route('/create-for-project/<int:project_id>', methods=['GET', 'POST'])
@login_required
def create_for_project(project_id):
    """为指定项目创建漏洞"""
    if not has_perm(current_user, PERM_VULN_CREATE):
        abort(403)
    
    project = Project.query.get_or_404(project_id)
    
    form = VulnerabilityForm()
    # 项目由 URL 固定,模板里只读展示,不渲染成表单控件。
    #
    # 原实现是把控件 disabled 掉,但**禁用控件不会随表单提交** ——
    # project_id 取不到值,DataRequired 必然失败,这个入口实际上从来提交不成功
    # （提交后只是原地重新渲染,HTTP 200 但漏洞没建出来）。
    #
    # 校验交给 URL 上的 project_id,所以这里要同时摘掉两层校验:
    # validators(DataRequired) 和 SelectField 自带的 pre_validate
    # （后者检查"值必须在 choices 里",光摘 validators 它是过不去的）。
    form.project_id.choices = [(project.id, project.name)]
    form.project_id.data = project.id
    form.project_id.validators = []
    form.project_id.validate_choice = False

    # 任务列表（可选）
    form.task_id.choices = [(0, '无关联任务')] + [(t.id, t.name) for t in Task.query.filter_by(project_id=project_id).all()]
    
    # 责任人列表
    form.assignee_id.choices = [(u.id, u.username) for u in User.query.filter(User.role.in_(['developer', 'test_lead', 'admin']))]
    
    if form.validate_on_submit():
        # 计算风险评分
        risk_score = calculate_risk_score(form.severity.data, project.criticality)
        due_date = calculate_due_date(form.severity.data)
        
        vuln = Vulnerability(
            vuln_code=generate_vuln_code(),
            title=form.title.data,
            description=sanitize_inline_html(form.description.data),
            project_id=project.id,
            task_id=form.task_id.data if form.task_id.data != 0 else None,
            source=form.source.data,
            severity=form.severity.data,
            vuln_type=form.vuln_type.data or None,
            risk_score=risk_score,
            status='pending',
            creator_id=current_user.id,
            assignee_id=form.assignee_id.data,
            due_date=due_date
        )
        saved = save_uploaded_screenshots(request.files.getlist('screenshots'))
        sync_screenshots(vuln, extra_files=saved)

        db.session.add(vuln)
        db.session.flush()  # 先取 vuln.id 供审计日志使用

        # 审计日志
        log_audit(
            operator_id=current_user.id,
            resource_type='vulnerability',
            resource_id=vuln.id,
            action='create',
            detail=f'为项目"{project.name}"创建漏洞：{vuln.title}'
        )
        db.session.commit()
        
        flash(f'漏洞 {vuln.vuln_code} 创建成功！', 'success')
        return redirect(url_for('projects.detail', id=project.id))
    
    return render_template('vulnerabilities/form_for_project.html', form=form, project=project, title='新建漏洞')