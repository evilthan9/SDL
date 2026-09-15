"""安全扫描（SAST / 组件 / 容器镜像）。

覆盖三件事:

1. **权限分层**（参照业界做法）：开发/业务只读且只看自己参与的项目；
   录入与处置是安全团队；编辑删除收口到 test_lead / admin。
2. **发现解析**：粘贴扫描器输出能正确落库。
3. **转漏洞闭环**：勾选发现 → 生成漏洞记录 → 回填关联，接上现有的状态流转。
"""
import pytest

from app import db
from app.models import AuditLog, Project, Scan, ScanFinding, User, Vulnerability
from app.routes.scans import parse_findings, sync_finding_counts


# ---------------------------------------------------------------- 解析


def test_parse_findings_accepts_pipe_format():
    text = '\n'.join([
        '严重|CWE-89|用户中心接口 SQL 注入|src/user/dao.py:88',
        '高危|CWE-79|订单备注未转义|templates/order.html:42',
        'Medium|CWE-200|错误页泄漏堆栈',
        '低危',
    ])
    parsed, skipped = parse_findings(text)
    # "低危" 这行只有等级没有标题 —— 会被跳过并计数,不做静默丢弃
    assert len(parsed) == 3
    assert skipped == 1
    assert parsed[0] == {'severity': '严重', 'rule_id': 'CWE-89',
                         'title': '用户中心接口 SQL 注入', 'location': 'src/user/dao.py:88'}
    # 三段:规则 + 标题,没有位置
    assert parsed[2]['severity'] == '中危'
    assert parsed[2]['rule_id'] == 'CWE-200'
    assert parsed[2]['title'] == '错误页泄漏堆栈'
    assert parsed[2]['location'] == ''
    assert parsed[0]['title'] == '用户中心接口 SQL 注入'
    assert parsed[0]['location'] == 'src/user/dao.py:88'


def test_parse_findings_accepts_fullwidth_and_tab():
    parsed, _ = parse_findings('高危｜CWE-22｜目录穿越｜a/b.py:1\n中危\tCWE-79\tXSS')
    assert parsed[0]['severity'] == '高危' and parsed[0]['title'] == '目录穿越'
    assert parsed[1]['severity'] == '中危'


def test_parse_findings_treats_unknown_head_as_title():
    parsed, _ = parse_findings('这行没有等级信息')
    assert parsed[0]['severity'] == '中危'
    assert parsed[0]['title'] == '这行没有等级信息'


def test_parse_findings_skips_blank_lines():
    parsed, skipped = parse_findings('\n\n高危|CWE-79|XSS\n\n\n')
    assert len(parsed) == 1 and skipped == 0


# ---------------------------------------------------------------- 权限


def test_scan_list_visibility(app, client, seed, as_user):
    """访客看不到扫描;其余角色都能进（数据范围另行收窄）。"""
    as_user(seed.user_ids['guest'])
    assert client.get('/scans/').status_code == 403
    for name in ('admin', 'lead', 'tester', 'dev', 'biz'):
        as_user(seed.user_ids[name])
        assert client.get('/scans/').status_code == 200, name


def test_only_security_team_can_create_scans(app, client, seed, as_user):
    """开发与业务只读 —— 业界一致做法是"发现由安全团队录入"。"""
    for name in ('dev', 'dev2', 'biz', 'guest'):
        as_user(seed.user_ids[name])
        assert client.get('/scans/create').status_code == 403, name
    for name in ('admin', 'lead', 'tester'):
        as_user(seed.user_ids[name])
        assert client.get('/scans/create').status_code == 200, name


def test_developer_scope_is_own_projects_only(app, client, seed, as_user):
    """种子扫描挂在"演示项目"(owner=biz),dev 在该项目被指派了漏洞 → 可见;
    dev2 完全不参与 → 拒绝。这是本次权限设计的核心。"""
    scan_id = seed.scan_id

    as_user(seed.user_ids['dev'])
    assert client.get(f'/scans/{scan_id}').status_code == 200

    as_user(seed.user_ids['dev2'])
    assert client.get(f'/scans/{scan_id}').status_code == 403


def test_business_sees_own_project_scans(app, client, seed, as_user):
    as_user(seed.user_ids['biz'])
    assert client.get(f'/scans/{seed.scan_id}').status_code == 200

    # 造一条挂在别人项目下的扫描,biz 不该看到
    with app.app_context():
        other = db.session.get(Project, seed.other_project_id)
        scan = Scan(scan_code='SCAN-TEST-9999', scan_type='sca', project_id=other.id,
                    creator_id=seed.user_ids['admin'], status='completed')
        db.session.add(scan)
        db.session.commit()
        other_scan_id = scan.id

    assert client.get(f'/scans/{other_scan_id}').status_code == 403


def test_guest_cannot_open_scan_detail(app, client, seed, as_user):
    as_user(seed.user_ids['guest'])
    assert client.get(f'/scans/{seed.scan_id}').status_code == 403


def test_only_lead_and_admin_can_delete(app, client, seed, as_user):
    for name in ('tester', 'dev', 'biz'):
        as_user(seed.user_ids[name])
        assert client.post(f'/scans/{seed.scan_id}/delete').status_code == 403, name

    as_user(seed.user_ids['admin'])
    assert client.post(f'/scans/{seed.scan_id}/delete', follow_redirects=False).status_code == 302
    with app.app_context():
        assert db.session.get(Scan, seed.scan_id).is_deleted is True


# ---------------------------------------------------------------- 录入


def test_create_scan_with_pasted_findings(app, client, seed, as_user):
    as_user(seed.user_ids['tester'])
    resp = client.post('/scans/create', data={
        'scan_type': 'sast',
        'project_id': str(seed.project_id),
        'tool': 'SonarQube',
        'target': 'git@example.com:demo/backend.git',
        'status': 'completed',
        'findings_text': '严重|CWE-89|SQL 注入|a.py:1\n高危|CWE-79|XSS|b.html:2',
    }, follow_redirects=False)
    assert resp.status_code == 302, resp.get_data(as_text=True)[:400]

    with app.app_context():
        scan = Scan.query.filter_by(target='git@example.com:demo/backend.git').first()
        assert scan is not None
        assert scan.total_findings == 2
        assert scan.critical_count == 1 and scan.high_count == 1
        assert len(scan.findings) == 2
        assert AuditLog.query.filter_by(action='create', resource_type='scan').count() == 1


def test_create_scan_without_project_is_allowed(app, client, seed, as_user):
    """不关联项目也能先记录,只是之后不能转漏洞。"""
    as_user(seed.user_ids['tester'])
    resp = client.post('/scans/create', data={
        'scan_type': 'sca', 'project_id': '0', 'status': 'completed',
        'tool': 'Trivy', 'target': 'requirements.txt',
        'findings_text': '中危|CVE-2021-1234|依赖过旧',
    }, follow_redirects=False)
    assert resp.status_code == 302
    with app.app_context():
        scan = Scan.query.filter_by(tool='Trivy').first()
        assert scan.project_id is None and scan.total_findings == 1


# ---------------------------------------------------------------- 转漏洞


def test_convert_findings_creates_vulnerabilities(app, client, seed, as_user):
    """SDL 的关键闭环:扫描发现 → 漏洞记录 → 走状态流转。"""
    as_user(seed.user_ids['tester'])
    finding_ids = seed.finding_ids

    resp = client.post(f'/scans/{seed.scan_id}/convert', data={
        'finding_ids': [str(fid) for fid in finding_ids],
        'assignee_id': str(seed.user_ids['dev']),
    }, follow_redirects=False)
    assert resp.status_code == 302

    with app.app_context():
        for fid in finding_ids:
            finding = db.session.get(ScanFinding, fid)
            assert finding.status == 'converted'
            assert finding.vulnerability_id is not None
            vuln = db.session.get(Vulnerability, finding.vulnerability_id)
            assert vuln is not None
            assert vuln.title == finding.title
            assert vuln.severity == finding.severity
            assert vuln.project_id == seed.project_id
            assert vuln.assignee_id == seed.user_ids['dev']
            # 来源要标成扫描,便于追溯
            assert vuln.source == 'sast'
            # 类型由规则编号推断:CWE-89 -> SQL 注入
            if finding.rule_id == 'CWE-89':
                assert vuln.vuln_type == 'sqli'

        assert AuditLog.query.filter_by(action='convert_findings').count() == 1


def test_convert_is_manual_not_automatic(app, client, seed, as_user):
    """只转勾选的,不是全转 —— 避免低危噪音一股脑倒给开发。"""
    as_user(seed.user_ids['tester'])
    client.post(f'/scans/{seed.scan_id}/convert',
                data={'finding_ids': [str(seed.finding_ids[0])]})

    with app.app_context():
        statuses = [db.session.get(ScanFinding, fid).status for fid in seed.finding_ids]
        assert statuses == ['converted', 'open'], statuses


def test_convert_without_selection_warns(app, client, seed, as_user):
    as_user(seed.user_ids['tester'])
    resp = client.post(f'/scans/{seed.scan_id}/convert', data={}, follow_redirects=False)
    assert resp.status_code == 302
    with app.app_context():
        assert Vulnerability.query.filter_by(source='sast').count() == 0


def test_cannot_convert_without_project(app, client, seed, as_user):
    with app.app_context():
        scan = Scan(scan_code='SCAN-NOPROJ', scan_type='sast', project_id=None,
                    creator_id=seed.user_ids['tester'], status='completed')
        db.session.add(scan)
        db.session.flush()
        finding = ScanFinding(scan_id=scan.id, severity='高危', title='无项目发现',
                              status='open')
        db.session.add(finding)
        db.session.commit()
        scan_id, finding_id = scan.id, finding.id

    as_user(seed.user_ids['tester'])
    client.post(f'/scans/{scan_id}/convert', data={'finding_ids': [str(finding_id)]})

    with app.app_context():
        assert db.session.get(ScanFinding, finding_id).status == 'open', '没有项目不该能转'
        assert Vulnerability.query.filter_by(title='无项目发现').count() == 0


def test_developer_cannot_convert(app, client, seed, as_user):
    """开发只读 —— 转漏洞会把发现变成"要自己修的任务",不该由开发触发。"""
    as_user(seed.user_ids['dev'])
    resp = client.post(f'/scans/{seed.scan_id}/convert',
                       data={'finding_ids': [str(seed.finding_ids[0])]})
    assert resp.status_code == 403


# ---------------------------------------------------------------- 处置


def test_ignore_and_reopen_finding(app, client, seed, as_user):
    fid = seed.finding_ids[0]
    as_user(seed.user_ids['tester'])

    assert client.post(f'/scans/finding/{fid}/ignore', follow_redirects=False).status_code == 302
    with app.app_context():
        assert db.session.get(ScanFinding, fid).status == 'ignored'
        assert AuditLog.query.filter_by(action='ignore_finding').count() == 1

    assert client.post(f'/scans/finding/{fid}/reopen', follow_redirects=False).status_code == 302
    with app.app_context():
        assert db.session.get(ScanFinding, fid).status == 'open'


def test_cannot_ignore_converted_finding(app, client, seed, as_user):
    fid = seed.finding_ids[0]
    as_user(seed.user_ids['tester'])
    client.post(f'/scans/{seed.scan_id}/convert', data={'finding_ids': [str(fid)]})

    resp = client.post(f'/scans/finding/{fid}/ignore', follow_redirects=False)
    assert resp.status_code == 302
    with app.app_context():
        assert db.session.get(ScanFinding, fid).status == 'converted'


def test_developer_cannot_ignore(app, client, seed, as_user):
    as_user(seed.user_ids['dev'])
    assert client.post(f'/scans/finding/{seed.finding_ids[0]}/ignore').status_code == 403


# ---------------------------------------------------------------- 业务端嵌入


def test_business_development_shows_scan_section(app, client, seed, as_user):
    """扫描结果要出现在业务端"研发控制"下面。"""
    as_user(seed.user_ids['admin'])
    body = client.get('/business?stage=development').get_data(as_text=True)
    assert '安全扫描结果' in body
    assert '源代码扫描' in body
    assert '已发现未跟进' in body


def test_business_development_scan_counts_respect_scope(app, client, seed, as_user):
    """dev2 不参与任何项目,业务端看到的扫描统计应为空。"""
    as_user(seed.user_ids['dev2'])
    body = client.get('/business?stage=development').get_data(as_text=True)
    assert '尚未开展此类扫描' in body


# ---------------------------------------------------------------- 计数同步


def test_sync_finding_counts(app, seed):
    with app.app_context():
        scan = db.session.get(Scan, seed.scan_id)
        scan.critical_count = scan.high_count = 99
        scan.total_findings = 999
        sync_finding_counts(scan)
        db.session.commit()
        assert scan.critical_count == 1
        assert scan.high_count == 1
        assert scan.medium_count == 0
        assert scan.total_findings == 2
