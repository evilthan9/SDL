"""页面渲染测试网。

在重构模板**之前**建立。断言的不只是状态码,还包括"页面结构是否正常"的弱信号:

- 该页的标志性元素存在（表格、表单、漏洞编号等）;
- 响应体里不出现异常标记（Traceback、未渲染的 Jinja 语法、jinja2 异常名）;
- 不出现"半成品痕迹"（英文占位符、裸枚举值）。

最后两条是重构模板时最容易碰坏、又最难靠状态码发现的东西。
"""
import re

import pytest

from app import db
from app.models import Vulnerability

#: 参与遍历的全部角色（与 conftest 的 seed 对应）
ROLES = ('admin', 'lead', 'tester', 'tester2', 'dev', 'dev2', 'biz', 'guest')

OK = 200
DENY = 403
REDIRECT = 302

#: 出现这些就说明渲染出了异常
ERROR_MARKERS = (
    'Traceback (most recent call last)',
    'jinja2.exceptions',
    'werkzeug.exceptions',
    'UndefinedError',
    'Internal Server Error',
)

#: 未渲染的 Jinja 语法。Jinja 的默认分隔符不该出现在最终 HTML 里
UNRENDERED = (re.compile(r'\{\{'), re.compile(r'\{%'))


def _pages(seed):
    """(名称, URL, {角色: 期望状态码}, 标志性元素) 列表。

    标志性元素是这个页面独有的、能证明"渲染到了正确模板"的字符串。
    """
    pending = seed.vuln_ids['pending']
    fixed = seed.vuln_ids['fixed']
    return [
        # 登录/注册页由匿名视角单独测（已登录访问会被重定向回首页）
        ('register_authed', '/auth/register', {
            # 管理员保留注册页以便建账号,其他已登录用户会被送回首页
            'admin': OK, 'lead': REDIRECT, 'tester': REDIRECT, 'tester2': REDIRECT,
            'dev': REDIRECT, 'dev2': REDIRECT, 'biz': REDIRECT, 'guest': REDIRECT,
        }, None),

        # 统计看板:除访客外都能看
        ('dashboard', '/', {
            'admin': OK, 'lead': OK, 'tester': OK, 'tester2': OK,
            'dev': OK, 'dev2': OK, 'biz': OK, 'guest': DENY,
        }, '漏洞统计看板'),

        # 业务端:测试角色会被重定向到测试端
        ('business', '/business', {
            'admin': OK, 'lead': REDIRECT, 'tester': REDIRECT, 'tester2': REDIRECT,
            'dev': OK, 'dev2': OK, 'biz': OK, 'guest': OK,
        }, None),
        ('business_level', '/business?stage=level', {
            'admin': OK, 'lead': REDIRECT, 'tester': REDIRECT, 'tester2': REDIRECT,
            'dev': OK, 'dev2': OK, 'biz': OK, 'guest': OK,
        }, None),
        ('business_development', '/business?stage=development', {
            'admin': OK, 'lead': REDIRECT, 'tester': REDIRECT, 'tester2': REDIRECT,
            'dev': OK, 'dev2': OK, 'biz': OK, 'guest': OK,
        }, None),
        ('business_release', '/business?stage=release', {
            'admin': OK, 'lead': REDIRECT, 'tester': REDIRECT, 'tester2': REDIRECT,
            'dev': OK, 'dev2': OK, 'biz': OK, 'guest': OK,
        }, None),

        # 测试端:业务/开发/访客会被送回业务端
        ('projects_list', '/projects/', {
            'admin': OK, 'lead': OK, 'tester': OK, 'tester2': OK,
            'dev': REDIRECT, 'dev2': REDIRECT, 'biz': REDIRECT, 'guest': REDIRECT,
        }, '任务列表'),

        # 项目详情:业务侧要求是项目 owner,测试侧不限
        ('project_detail', f'/projects/{seed.project_id}', {
            'admin': OK, 'lead': OK, 'tester': OK, 'tester2': OK,
            'dev': DENY, 'dev2': DENY, 'biz': OK, 'guest': DENY,
        }, None),

        ('project_edit', f'/projects/{seed.project_id}/edit', {
            # 编辑与"创建"共用权限点,外加项目归属校验(seed 项目的 owner 是 biz)
            'admin': OK, 'lead': DENY, 'tester': DENY, 'tester2': DENY,
            'dev': DENY, 'dev2': DENY, 'biz': OK, 'guest': DENY,
        }, '编辑项目'),

        ('project_vulns', f'/projects/{seed.project_id}/vulnerabilities', {
            'admin': OK, 'lead': OK, 'tester': OK, 'tester2': OK,
            'dev': OK, 'dev2': OK, 'biz': OK, 'guest': OK,
        }, '项目漏洞列表'),

        ('task_workflow', f'/projects/task/{seed.task_id}/workflow', {
            'admin': OK, 'lead': OK, 'tester': OK,
            'tester2': DENY, 'dev': DENY, 'dev2': DENY, 'biz': DENY, 'guest': DENY,
        }, None),

        # 漏洞管理:仅测试角色与管理员
        ('vuln_management', '/vulnerabilities/management', {
            'admin': OK, 'lead': OK, 'tester': OK, 'tester2': OK,
            'dev': DENY, 'dev2': DENY, 'biz': DENY, 'guest': DENY,
        }, None),
        ('vuln_management_trash', '/vulnerabilities/management?trash=1', {
            'admin': OK, 'lead': OK, 'tester': OK, 'tester2': OK,
            'dev': DENY, 'dev2': DENY, 'biz': DENY, 'guest': DENY,
        }, None),

        ('vuln_create', '/vulnerabilities/create', {
            'admin': OK, 'lead': OK, 'tester': OK, 'tester2': OK,
            'dev': DENY, 'dev2': DENY, 'biz': DENY, 'guest': DENY,
        }, None),

        # 漏洞详情:按数据范围
        ('vuln_detail_assigned_dev', f'/vulnerabilities/{pending}', {
            'admin': OK, 'lead': OK, 'tester': OK,      # 创建人
            'tester2': DENY, 'dev': OK,                 # 责任人
            'dev2': DENY, 'biz': OK,                    # 项目 owner
            'guest': DENY,
        }, None),
        ('vuln_detail_closed', f'/vulnerabilities/{fixed}', {
            'admin': OK, 'lead': OK, 'tester': OK,
            'tester2': DENY, 'dev': OK, 'dev2': DENY, 'biz': OK, 'guest': DENY,
        }, None),

        # 编辑权限按 PERMISSIONS 矩阵:业务人员有自己的 vuln.edit + 项目归属
        ('vuln_edit', f'/vulnerabilities/{pending}/edit', {
            'admin': OK, 'lead': OK, 'tester': OK,
            'tester2': DENY, 'dev': DENY, 'dev2': DENY, 'biz': OK, 'guest': DENY,
        }, None),

        # 发布要求是该任务的处理人,所以 test_lead 也不行(既有规则)
        ('vuln_publish', f'/vulnerabilities/publish/{seed.task_id}/{seed.case_id}', {
            'admin': OK, 'lead': DENY, 'tester': OK, 'tester2': DENY,
            'dev': DENY, 'dev2': DENY, 'biz': DENY, 'guest': DENY,
        }, '漏洞发布'),
        ('vuln_create_for_project', f'/vulnerabilities/create-for-project/{seed.project_id}', {
            'admin': OK, 'lead': OK, 'tester': OK, 'tester2': OK,
            'dev': DENY, 'dev2': DENY, 'biz': DENY, 'guest': DENY,
        }, None),

        # 各表单页(此前没有任何测试渲染过它们)
        # 创建项目走 PERM_PROJECT_CREATE:只有业务人员与管理员。
        # 开发者是修复方、访客只读,都不建项目。
        ('projects_create', '/projects/create', {
            'admin': OK, 'lead': DENY, 'tester': DENY, 'tester2': DENY,
            'dev': DENY, 'dev2': DENY, 'biz': OK, 'guest': DENY,
        }, None),
        # 创建迭代落库的就是 Project,与"创建项目"同一权限点
        ('iteration_create', '/business/requirements/iterations/create', {
            'admin': OK, 'lead': DENY, 'tester': DENY, 'tester2': DENY,
            'dev': DENY, 'dev2': DENY, 'biz': OK, 'guest': DENY,
        }, None),
        ('testing_task_create', '/business/testing/tasks/create', {
            'admin': OK, 'lead': OK, 'tester': OK, 'tester2': OK,
            'dev': DENY, 'dev2': DENY, 'biz': DENY, 'guest': DENY,
        }, None),
        ('assessment', '/business/assessment', {
            'admin': OK, 'lead': DENY, 'tester': DENY, 'tester2': DENY,
            'dev': OK, 'dev2': OK, 'biz': OK, 'guest': OK,
        }, None),

        # 安全扫描:按业界做法,开发/业务只读且只看自己参与的项目
        ('scan_list', '/scans/', {
            'admin': OK, 'lead': OK, 'tester': OK, 'tester2': OK,
            'dev': OK, 'dev2': OK, 'biz': OK, 'guest': DENY,
        }, '安全扫描'),
        ('scan_create', '/scans/create', {
            'admin': OK, 'lead': OK, 'tester': OK, 'tester2': OK,
            'dev': DENY, 'dev2': DENY, 'biz': DENY, 'guest': DENY,
        }, '录入扫描记录'),
        ('scan_detail', f'/scans/{seed.scan_id}', {
            # 种子扫描挂在"演示项目"(owner=biz)下,创建人是 tester,
            # dev 在该项目里被指派了漏洞 → 算"参与";dev2 完全不参与 → 拒绝
            'admin': OK, 'lead': OK, 'tester': OK, 'tester2': OK,
            'dev': OK, 'dev2': DENY, 'biz': OK, 'guest': DENY,
        }, '发现明细'),

        # 个人自助页面:所有已登录角色都能访问自己的
        ('profile', '/auth/profile', {r: OK for r in ROLES}, '个人资料'),
        ('change_password', '/auth/password', {r: OK for r in ROLES}, '修改密码'),

        # 管理类页面
        ('users', '/auth/users', {
            'admin': OK, 'lead': DENY, 'tester': DENY, 'tester2': DENY,
            'dev': DENY, 'dev2': DENY, 'biz': DENY, 'guest': DENY,
        }, '用户权限管理'),
        ('audit', '/audit/logs', {
            'admin': OK, 'lead': OK, 'tester': DENY, 'tester2': DENY,
            'dev': DENY, 'dev2': DENY, 'biz': DENY, 'guest': DENY,
        }, '审计日志'),

        # 错误页自身
        ('error_404', '/vulnerabilities/999999', {r: 404 for r in ROLES}, None),
    ]


def _assert_clean_body(name, role, body):
    """重构模板时最容易碰坏、又最难靠状态码发现的几类问题。"""
    for marker in ERROR_MARKERS:
        assert marker not in body, f'{name} as {role}: 响应体出现异常标记「{marker}」'
    for pattern in UNRENDERED:
        assert not pattern.search(body), (
            f'{name} as {role}: 响应体出现未渲染的 Jinja 语法「{pattern.pattern}」'
        )


def test_anonymous_pages_render(app, client, seed):
    """未登录时能看到登录页与注册页;受保护页面跳登录。"""
    for url, marker in (('/auth/login', '用户登录'), ('/auth/register', '注册')):
        resp = client.get(url)
        assert resp.status_code == OK, url
        assert marker in resp.get_data(as_text=True), url

    for url in ('/', '/vulnerabilities/management', '/projects/', '/audit/logs'):
        resp = client.get(url)
        assert resp.status_code == REDIRECT, f'{url} 未登录应跳转登录页'
        assert '/auth/login' in resp.headers.get('Location', ''), url


@pytest.mark.parametrize('role', ROLES)
def test_all_pages_render_cleanly(app, client, seed, as_user, role):
    """逐页 × 逐角色:状态码正确 + 标志性元素存在 + 响应体无异常标记。"""
    failures = []
    for name, url, expected, marker in _pages(seed):
        as_user(seed.user_ids[role])
        resp = client.get(url, follow_redirects=False)
        want = expected[role]

        if resp.status_code != want:
            failures.append(f'{name} ({url}) 期望 {want} 实际 {resp.status_code}')
            continue
        if want != OK:
            continue

        body = resp.get_data(as_text=True)
        if marker and marker not in body:
            failures.append(f'{name} ({url}) 缺少标志性元素「{marker}」')
        try:
            _assert_clean_body(name, role, body)
        except AssertionError as exc:
            failures.append(str(exc))

    assert not failures, '\n'.join(failures)


#: 数据库里的枚举值。它们出现在**可见文本**里就是 UI 没做本地化。
_ENUM_VALUES = ('penetration_test', 'compliance_test', 'security_scan', 'security_test',
                'in_progress', 'false_positive', 'test_lead', 'test_tester',
                'assigned', 'retest', 'archived')


def _visible_text(html):
    """剥掉标签与属性，只留渲染给用户看的文本。

    枚举值出现在 URL（`/transition/mark_false_positive`）或表单值
    （`<option value="mark_false_positive">`）里是**正常的** —— 那是程序接口，
    不是给用户看的。只有落在可见文本里才说明没做本地化。
    """
    without_tags = re.sub(r'<[^>]*>', ' ', html)
    without_scripts = re.sub(r'<script\b.*?</script>', ' ', without_tags, flags=re.S | re.I)
    return without_scripts


def test_no_raw_enum_leaks_into_pages(app, client, seed, as_user):
    """界面的**可见文本**里不该出现数据库枚举原值。

    回归:projects/list.html 曾直接渲染 `{{ task.test_type }}`,页面上就出现
    `penetration_test` 这种英文枚举值;task_workflow 的"测试类型"字段同样如此。
    """
    offenders = []
    for name, url, expected, _marker in _pages(seed):
        as_user(seed.user_ids['admin'])
        if expected['admin'] != OK:
            continue
        body = client.get(url, follow_redirects=False).get_data(as_text=True)
        text = _visible_text(body)
        for value in _ENUM_VALUES:
            if value in text:
                offenders.append(f'{name}: 可见文本里出现裸枚举值「{value}」')
    assert not offenders, '\n'.join(offenders)


def test_no_english_placeholders(app, client, seed, as_user):
    """中文界面里不该出现英文占位符。

    回归:projects/list.html 有三处 `no plan time`。
    """
    as_user(seed.user_ids['admin'])
    for name, url, expected, _marker in _pages(seed):
        if expected['admin'] != OK:
            continue
        body = client.get(url, follow_redirects=False).get_data(as_text=True)
        assert 'no plan time' not in body, f'{name} 出现英文占位符 no plan time'


def test_dashboard_keeps_static_fallback(app, client, seed, as_user):
    """看板断网降级不能被后续改动碰掉。"""
    as_user(seed.user_ids['admin'])
    body = client.get('/').get_data(as_text=True)
    assert 'fbSeverity' in body
    assert '图表库未能加载' in body


# ---------------------------------------------------------------- 覆盖率守卫


def test_every_get_endpoint_is_covered_by_the_matrix(app, seed):
    """每个无参数的 GET 端点都必须出现在 _pages 里。

    没有这条断言,渲染矩阵会随着新增路由悄悄退化 —— 新页面没人测,
    而套件依然是绿的。
    """
    excluded = {
        'static',                  # Flask 内置静态文件
        'auth.logout',             # 会清 session,单独测
        'vulnerabilities.screenshot',  # 按文件名取图,不属于页面
        'auth.login',              # 已登录会被重定向,由 test_anonymous_pages_render 覆盖
    }

    # 用 url_map 直接把 URL 解析成 endpoint。test_request_context 不会主动做 URL
    # 匹配，request.endpoint 在那里是 None，会把所有端点都误报成"未覆盖"。
    url_map = app.url_map.bind('localhost')
    covered = set()
    for _name, url, _expected, _marker in _pages(seed):
        endpoint, _args = url_map.match(url.split('?')[0])
        covered.add(endpoint)

    missing = []
    for rule in app.url_map.iter_rules():
        if 'GET' not in rule.methods or rule.endpoint in excluded:
            continue
        if rule.arguments:
            continue  # 带路径参数的规则由矩阵里拼好的 URL 覆盖
        if rule.endpoint in covered:
            continue
        missing.append(f'{rule.endpoint}  ({rule.rule})')

    assert not missing, '以下 GET 端点没有被渲染矩阵覆盖：\n' + '\n'.join(sorted(missing))


#: 本项目实际用到的 Bootstrap 5 类名。自定义类必须自己定义,不受此白名单豁免。
BOOTSTRAP_ALLOWLIST = {
    'btn', 'btn-primary', 'btn-secondary', 'btn-light', 'btn-dark', 'btn-sm', 'btn-lg',
    'btn-outline-primary', 'btn-outline-secondary', 'btn-outline-danger', 'btn-outline-success',
    'btn-close', 'btn-block',
    'card', 'card-header', 'card-body', 'card-footer', 'card-title',
    'table', 'table-hover', 'table-light', 'table-dark', 'table-responsive', 'align-middle',
    'badge', 'bg-primary', 'bg-secondary', 'bg-success', 'bg-danger', 'bg-warning',
    'bg-info', 'bg-light', 'bg-dark', 'text-white', 'text-muted', 'text-danger',
    'alert', 'alert-info', 'alert-warning', 'alert-danger', 'alert-success',
    'alert-dismissible', 'fade', 'show',
    'form-control', 'form-select', 'form-label', 'form-check', 'form-check-input',
    'form-check-label', 'form-control-sm', 'form-select-sm',
    'row', 'col-md-6', 'col-md-8', 'col-lg-4', 'container', 'py-3', 'py-4',
    'd-flex', 'd-inline', 'd-inline-flex', 'd-inline-block', 'justify-content-between',
    'justify-content-center', 'justify-content-end', 'align-items-center', 'flex-wrap',
    'gap-1', 'gap-2', 'gap-3', 'mb-0', 'mb-2', 'mb-3', 'mb-4', 'mt-3', 'mt-4',
    'ms-1', 'me-1', 'me-2', 'py-3', 'py-4', 'p-0', 'p-3', 'w-100', 'h-100',
    'shadow', 'shadow-sm', 'small', 'modal', 'modal-dialog', 'modal-content',
    'modal-header', 'modal-body', 'modal-footer', 'modal-title',
    'col-6', 'g-2', 'form-text', 'btn-success', 'btn-outline-warning',
    'text-center', 'fw-bold', 'border-top', 'display-inline',
    # 顶栏用户下拉（base.html 用 Bootstrap 的 dropdown 组件，只有它豁免 Bootstrap 类）
    'dropdown', 'dropdown-toggle', 'dropdown-menu', 'dropdown-menu-end',
    'dropdown-item', 'dropdown-divider',
}


def _defined_classes():
    """全项目 CSS 里定义过的类名（模板 <style> 块 + static 下的 .css）。"""
    import pathlib

    defined = set()
    root = pathlib.Path(app_root())
    sources = list((root / 'app' / 'templates').rglob('*.html'))
    sources += list((root / 'app' / 'static').rglob('*.css'))
    for path in sources:
        text = path.read_text(encoding='utf-8')
        for match in re.finditer(r'\.([a-zA-Z][\w-]*)', text):
            defined.add(match.group(1))
    return defined


def app_root():
    import pathlib
    return pathlib.Path(__file__).resolve().parent.parent


def test_no_undefined_css_classes(app, client, seed, as_user):
    """页面上用到的每个 class 都必须有地方定义。

    这条能机械发现两类肉眼很难看出的问题：

    - **跨页 CSS 依赖**:某个页面用了只在别的页面 `<style>` 里定义的类
      （如 dashboard 用了只在 management.html 定义的 `vuln-pending`）;
    - **未定义的裸 class**:标记里写了但全项目没有对应规则,渲染出来是无样式裸 HTML
      （business.html 有约 20 个这种类）。
    """
    defined = _defined_classes() | BOOTSTRAP_ALLOWLIST
    offenders = []

    for name, url, expected, _marker in _pages(seed):
        if expected['admin'] != OK:
            continue
        as_user(seed.user_ids['admin'])
        body = client.get(url, follow_redirects=False).get_data(as_text=True)
        for match in re.finditer(r'class="([^"]*)"', body):
            for cls in match.group(1).split():
                # Jinja 表达式没渲染干净时会留下 {{ }} / {% %},单独由别的断言管
                if cls.startswith('{') or cls.startswith('%'):
                    continue
                if cls not in defined:
                    offenders.append(f'{name}: 未定义的 class「{cls}」')

    unique = sorted(set(offenders))
    assert not unique, f'共 {len(unique)} 个未定义的 class：\n' + '\n'.join(unique)
