"""检索筛选、分页、导出的测试。

重点:导出必须和页面看到的是同一批数据 —— 导出另写一份可见性过滤会多出一个越权入口。
"""
import pytest

from app import db
from app.models import User, Vulnerability
from app.routes.vulnerabilities import _csv_safe


def _make_vulns(app, seed, count, **overrides):
    """批量造数据,用于分页测试。"""
    with app.app_context():
        from datetime import datetime
        for index in range(count):
            fields = {
                'vuln_code': f'VUL-BULK-{index:03d}',
                'title': f'批量漏洞 {index:03d}',
                'description': 'x',
                'project_id': seed.project_id,
                'source': 'manual',
                'severity': '低危',
                'status': 'pending',
                'creator_id': seed.user_ids['tester'],
                'assignee_id': seed.user_ids['dev'],
            }
            fields.update(overrides)
            db.session.add(Vulnerability(**fields))
        db.session.commit()


# ---------------------------------------------------------------- 筛选

def test_severity_filter(app, client, seed, as_user):
    _make_vulns(app, seed, 3, severity='严重')
    as_user(seed.user_ids['admin'])

    body = client.get('/vulnerabilities/management?severity=严重').get_data(as_text=True)
    assert '批量漏洞' in body
    assert '接口存在 SQL 注入' not in body  # 种子里那条是中危


def test_status_filter(app, client, seed, as_user):
    as_user(seed.user_ids['admin'])
    body = client.get('/vulnerabilities/management?status=closed').get_data(as_text=True)
    assert '越权查看他人订单' in body
    assert '接口存在 SQL 注入' not in body


def test_title_filter_matches_code_too(app, client, seed, as_user):
    as_user(seed.user_ids['admin'])
    # 编号筛选:VUL-TEST-003 是种子里那条"已闭环"
    body = client.get('/vulnerabilities/management?title=VUL-TEST-003').get_data(as_text=True)
    assert '越权查看他人订单' in body
    assert '接口存在 SQL 注入' not in body


def test_overdue_filter(app, client, seed, as_user):
    """逾期 = 过了 SLA 截止且仍未闭环。回归:原实现编辑会重置 due_date,逾期恒为 0。"""
    with app.app_context():
        from datetime import datetime, timedelta
        vuln = db.session.get(Vulnerability, seed.vuln_ids['pending'])
        vuln.due_date = datetime.utcnow() - timedelta(days=5)
        # 已闭环的不算逾期,给它一个同样过期的截止时间作为反例
        closed = db.session.get(Vulnerability, seed.vuln_ids['closed'])
        closed.due_date = datetime.utcnow() - timedelta(days=5)
        db.session.commit()

    as_user(seed.user_ids['admin'])
    body = client.get('/vulnerabilities/management?overdue=1').get_data(as_text=True)
    assert '接口存在 SQL 注入' in body
    assert '越权查看他人订单' not in body


# ---------------------------------------------------------------- 分页

def test_pagination_splits_results(app, client, seed, as_user):
    _make_vulns(app, seed, 30)
    as_user(seed.user_ids['admin'])

    first = client.get('/vulnerabilities/management?page=1').get_data(as_text=True)
    second = client.get('/vulnerabilities/management?page=2').get_data(as_text=True)

    assert '第 1 /' in first
    assert '第 2 /' in second

    # 两页不应有重复条目
    import re
    codes_1 = set(re.findall(r'VUL-BULK-\d{3}', first))
    codes_2 = set(re.findall(r'VUL-BULK-\d{3}', second))
    assert codes_1 and codes_2
    assert not (codes_1 & codes_2), '分页出现重复数据'


def test_pagination_keeps_filters(app, client, seed, as_user):
    _make_vulns(app, seed, 30, severity='严重')
    as_user(seed.user_ids['admin'])

    body = client.get('/vulnerabilities/management?severity=严重&page=2').get_data(as_text=True)
    assert '第 2 /' in body
    # 翻页链接里必须带上 severity,否则一翻页筛选就丢
    assert 'severity=' in body


# ---------------------------------------------------------------- 导出

def test_export_has_bom_for_excel(app, client, seed, as_user):
    as_user(seed.user_ids['admin'])
    raw = client.get('/vulnerabilities/management?export=1').data
    assert raw[:3] == b'\xef\xbb\xbf', '缺少 BOM,Excel 打开中文会乱码'


def test_export_respects_data_scope(app, client, seed, as_user):
    """导出的行数必须等于导出者能看到的行数,不能借导出绕过数据范围。

    用 tester 做样本:它有 vuln.export 权限,同时数据范围被限制在"本人创建的"。
    (developer 连导出权限都没有,拿它测不到这一层。)
    """
    # 这批漏洞的创建人是 tester2,tester 不该看到
    _make_vulns(app, seed, 5, creator_id=seed.user_ids['tester2'], assignee_id=None)

    as_user(seed.user_ids['tester'])
    raw = client.get('/vulnerabilities/management?export=1').data.decode('utf-8-sig')
    exported_rows = [line for line in raw.splitlines() if line.strip()][1:]  # 去掉表头

    with app.app_context():
        from app.permissions import apply_vuln_scope
        tester = db.session.get(User, seed.user_ids['tester'])
        expected = apply_vuln_scope(Vulnerability.query.filter_by(is_deleted=False), tester).count()

    assert len(exported_rows) == expected
    assert '批量漏洞' not in raw, '导出泄露了他人创建的漏洞'


def test_csv_injection_is_neutralised():
    """以 = + - @ 开头的单元格必须前置单引号,否则 Excel 会当公式执行。"""
    assert _csv_safe('=cmd|calc') == "'=cmd|calc"
    assert _csv_safe('+1+1') == "'+1+1"
    assert _csv_safe('@SUM(A1)') == "'@SUM(A1)"
    assert _csv_safe('-2+3') == "'-2+3"
    assert _csv_safe('正常标题') == '正常标题'
    assert _csv_safe(None) == ''


def test_export_requires_permission(app, client, seed, as_user):
    """developer 没有 vuln.export 权限。"""
    as_user(seed.user_ids['dev'])
    resp = client.get('/vulnerabilities/management?export=1')
    assert resp.status_code == 403


def test_management_requires_permission(app, client, seed, as_user):
    for name in ('biz', 'guest', 'dev'):
        as_user(seed.user_ids[name])
        assert client.get('/vulnerabilities/management').status_code == 403, name
