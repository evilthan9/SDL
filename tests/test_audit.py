"""审计追溯测试:页面可达性、权限、IP 采集、埋点覆盖。

改造前 audit_logs 表有数据但没有任何页面能查看,ip_address 字段也因调用点
从不传参而永远为空。
"""
import pytest

from app import db
from app.models import AuditLog, User, Vulnerability
from app.services import client_ip


def test_audit_page_requires_privilege(app, client, seed, as_user):
    """只有 admin 和 test_lead 能看审计日志。"""
    for name in ('tester', 'dev', 'biz', 'guest'):
        as_user(seed.user_ids[name])
        assert client.get('/audit/logs').status_code == 403, name

    for name in ('admin', 'lead'):
        as_user(seed.user_ids[name])
        assert client.get('/audit/logs').status_code == 200, name


def test_audit_page_renders_with_empty_data(app, client, seed, as_user):
    as_user(seed.user_ids['admin'])
    resp = client.get('/audit/logs')
    assert resp.status_code == 200
    assert '没有符合条件的审计记录' in resp.get_data(as_text=True)


def test_transition_is_recorded_and_visible(app, client, seed, as_user):
    """状态流转应写审计,并在页面上查得到,且 IP 非空。"""
    vuln_id = seed.vuln_ids['pending']

    as_user(seed.user_ids['dev'])
    client.post(f'/vulnerabilities/{vuln_id}/transition/fix')

    as_user(seed.user_ids['admin'])
    page = client.get('/audit/logs').get_data(as_text=True)
    assert '提交修复' in page
    assert '待修复 → 已修复待复测' in page

    with app.app_context():
        row = AuditLog.query.filter_by(action='fix').first()
        assert row is not None
        assert row.from_status == 'pending'
        assert row.to_status == 'fixed'
        assert row.ip_address, 'IP 没有被采集'


def test_view_denied_is_audited(app, client, seed, as_user):
    """越权访问尝试要留痕。"""
    as_user(seed.user_ids['dev2'])
    assert client.get(f'/vulnerabilities/{seed.vuln_ids["pending"]}').status_code == 403

    with app.app_context():
        row = AuditLog.query.filter_by(action='view_denied').first()
        assert row is not None


def test_task_lifecycle_is_audited(app, client, seed, as_user):
    """任务分配 / 开始 / 审核原先完全没有埋点。"""
    as_user(seed.user_ids['admin'])

    resp = client.post(f'/projects/task/{seed.task_id}/assign',
                       data={'tester_id': seed.user_ids['tester']})
    assert resp.status_code == 302

    as_user(seed.user_ids['tester'])
    client.post(f'/projects/task/{seed.task_id}/start', data={'start': 'yes'})
    client.post(f'/projects/task/{seed.task_id}/review', data={'result': 'pass'})

    with app.app_context():
        actions = {row.action for row in AuditLog.query.all()}
        assert 'task_assign' in actions
        assert 'task_start' in actions
        assert 'task_review' in actions


def test_reassign_is_audited(app, client, seed, as_user):
    """改派修复人:原先模板有隐藏域但后端不读,功能是空的。"""
    vuln_id = seed.vuln_ids['pending']

    with app.app_context():
        vuln = db.session.get(Vulnerability, vuln_id)
        payload = {
            'title': vuln.title,
            'description': vuln.description or 'x',
            'project_id': str(vuln.project_id),
            'task_id': str(vuln.task_id or 0),
            'source': vuln.source or 'manual',
            'severity': vuln.severity or '中危',
            'vuln_type': vuln.vuln_type or '',
            'assignee_id': str(seed.user_ids['dev2']),
        }

    as_user(seed.user_ids['admin'])
    client.post(f'/vulnerabilities/{vuln_id}/edit', data=payload)

    with app.app_context():
        vuln = db.session.get(Vulnerability, vuln_id)
        assert vuln.assignee_id == seed.user_ids['dev2'], '改派没生效'
        assert AuditLog.query.filter_by(action='reassign').count() == 1


def test_filters_narrow_results(app, client, seed, as_user):
    vuln_id = seed.vuln_ids['pending']
    as_user(seed.user_ids['dev'])
    client.post(f'/vulnerabilities/{vuln_id}/transition/fix')

    as_user(seed.user_ids['admin'])
    # 注意：动作中文名也出现在筛选下拉的 <option> 里,不能拿它当断言依据。
    # '状态转换：' 只出现在结果行的"详情"列。
    assert '状态转换：' in client.get('/audit/logs?action=fix').get_data(as_text=True)
    assert '状态转换：' not in client.get('/audit/logs?action=create').get_data(as_text=True)


def test_client_ip_handles_no_request_context(app):
    """没有请求上下文时不应抛异常（例如在脚本或定时任务里写审计）。"""
    with app.app_context():
        assert client_ip() is None


# ---------------------------------------------------------------- 用户管理入审计


def test_role_change_is_audited(app, client, seed, as_user):
    """回归:角色变更此前完全不写审计,而审计页却有"用户"筛选项。"""
    as_user(seed.user_ids['admin'])
    resp = client.post('/auth/users',
                       data={f'role_{seed.user_ids["guest"]}': 'tester'},
                       follow_redirects=False)
    assert resp.status_code == 302

    with app.app_context():
        row = AuditLog.query.filter_by(action='user_role_change').first()
        assert row is not None, '角色变更没有写审计'
        assert row.resource_type == 'user'
        assert row.resource_id == seed.user_ids['guest']
        assert row.from_status == 'guest'
        assert row.to_status == 'tester'
        assert row.operator_id == seed.user_ids['admin']


def test_role_change_shows_up_under_user_filter(app, client, seed, as_user):
    """审计页的"用户"筛选项必须真能查到结果。"""
    as_user(seed.user_ids['admin'])
    client.post('/auth/users', data={f'role_{seed.user_ids["guest"]}': 'tester'})

    body = client.get('/audit/logs?resource_type=user').get_data(as_text=True)
    assert '调整用户角色' in body
    assert '没有符合条件的审计记录' not in body


def test_delete_user_is_audited(app, client, seed, as_user):
    as_user(seed.user_ids['admin'])
    victim_id = seed.user_ids['tester2']
    resp = client.post(f'/auth/users/{victim_id}/delete', follow_redirects=False)
    assert resp.status_code == 302

    with app.app_context():
        row = AuditLog.query.filter_by(action='user_delete').first()
        assert row is not None, '删除用户没有写审计'
        assert row.resource_type == 'user'
        assert row.resource_id == victim_id
        assert row.operator_id == seed.user_ids['admin']
        assert 'tester2' in (row.detail or '')
        # 操作者本身不能被误伤
        assert db.session.get(User, seed.user_ids['admin']) is not None


def test_unchanged_role_writes_no_audit(app, client, seed, as_user):
    """没变动的角色不该产生噪音记录。"""
    as_user(seed.user_ids['admin'])
    client.post('/auth/users',
                data={f'role_{seed.user_ids["guest"]}': 'guest'},  # 原本就是 guest
                follow_redirects=False)

    with app.app_context():
        assert AuditLog.query.filter_by(action='user_role_change').count() == 0


def test_audit_actions_have_labels():
    """每个会写入的动作都该在审计页显示成中文,而不是裸英文标识。"""
    from app.models import AuditLog as _AuditLog  # noqa: F401
    from app.routes.audit import ACTION_LABELS, action_label

    for action in ('user_role_change', 'user_delete', 'view_denied', 'export',
                   'fix', 'verify_pass', 'task_assign'):
        assert action in ACTION_LABELS, f'{action} 没有中文标签'
        assert action_label(action) != action


def test_deleted_user_audit_still_renders(app, client, seed, as_user):
    """用户被删后其历史审计的 operator 会变 NULL,页面要能正常显示而不是报错。"""
    as_user(seed.user_ids['admin'])
    client.post(f'/auth/users/{seed.user_ids["tester2"]}/delete')

    resp = client.get('/audit/logs?resource_type=user')
    assert resp.status_code == 200
    assert '—' in resp.get_data(as_text=True)
