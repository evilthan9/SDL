"""状态机测试:转换表、角色白名单、归属校验、以及"edit 旁路已被堵死"的回归。"""
import json

import pytest

from app import db
from app.models import AuditLog, User, Vulnerability
from app.state_machine import (
    ALL_STATUSES, TERMINAL_STATUSES, TRANSITIONS, available_actions,
    can_transition, status_label,
)

ALL_ROLES = ('guest', 'business', 'developer', 'tester', 'test_lead', 'admin')


class _FakeUser:
    def __init__(self, role, uid=999):
        self.role = role
        self.id = uid
        self.username = role
        self.is_authenticated = True


class _FakeVuln:
    def __init__(self, status, assignee_id=None):
        self.status = status
        self.assignee_id = assignee_id


# ---------------------------------------------------------------- 转换表本身


def test_transition_table_is_wellformed():
    """每个动作的目标状态必须是合法状态,源状态集合非空。"""
    for action, trans in TRANSITIONS.items():
        assert trans.to_state in ALL_STATUSES, action
        assert trans.from_states, action
        for state in trans.from_states:
            assert state in ALL_STATUSES, (action, state)
        assert trans.roles, action


def test_full_matrix_never_leaks():
    """6 动作 × 5 状态 × 6 角色,放行的组合必须严格符合转换表。"""
    for action, trans in TRANSITIONS.items():
        for status in ALL_STATUSES:
            for role in ALL_ROLES:
                ok, _ = can_transition(_FakeVuln(status), action, _FakeUser(role))
                if ok:
                    assert status in trans.from_states, (action, status)
                    assert role in trans.roles, (action, role)


@pytest.mark.parametrize('terminal', sorted(TERMINAL_STATUSES))
def test_terminal_states_reject_fix(terminal):
    """终止态不能再直接提交修复,只能 reopen。"""
    dev = _FakeUser('developer')
    ok, reason = can_transition(_FakeVuln(terminal), 'fix', dev)
    assert not ok
    assert '无法执行' in reason
    assert can_transition(_FakeVuln(terminal), 'reopen', _FakeUser('admin'))[0]


def test_business_cannot_verify():
    """业务方是修复方,不能自己复测通过。"""
    ok, reason = can_transition(_FakeVuln('fixed'), 'verify_pass', _FakeUser('business'))
    assert not ok
    assert '无权' in reason


def test_developer_cannot_mark_false_positive():
    """职责分离:修复方不能自行判定误报。"""
    assert not can_transition(_FakeVuln('pending'), 'mark_false_positive', _FakeUser('developer'))[0]


def test_assignee_scope_blocks_other_developer():
    vuln = _FakeVuln('pending', assignee_id=7)
    ok, reason = can_transition(vuln, 'fix', _FakeUser('developer', uid=8))
    assert not ok
    assert '责任人' in reason


def test_is_authorized_matches_denial_kind():
    """is_authorized 只看授权,不看源状态 —— 调用方靠它区分 403 与"页面过期"。"""
    from app.state_machine import is_authorized

    # 角色不匹配:任何状态下都不授权
    assert not is_authorized(_FakeVuln('fixed'), 'verify_pass', _FakeUser('business'))
    # 角色匹配但状态不对:仍应"已授权",由 can_transition 再判状态
    assert is_authorized(_FakeVuln('pending'), 'verify_pass', _FakeUser('tester'))
    assert not can_transition(_FakeVuln('pending'), 'verify_pass', _FakeUser('tester'))[0]
    # 归属不匹配:不授权
    assert not is_authorized(_FakeVuln('pending', assignee_id=7), 'fix', _FakeUser('developer', uid=8))


def test_assignee_scope_falls_back_when_unassigned():
    """存量数据里 assignee_id 大量为空,严格限制会让"提交修复"永远 403。"""
    assert can_transition(_FakeVuln('pending', assignee_id=None), 'fix', _FakeUser('developer'))[0]


def test_anonymous_never_allowed():
    class Anon:
        is_authenticated = False

    for action in TRANSITIONS:
        ok, _ = can_transition(_FakeVuln('pending'), action, Anon())
        assert not ok


def test_unknown_status_label_does_not_raise():
    assert status_label('weird_status') == 'weird_status'
    assert status_label(None) == '未知'


def test_available_actions_matches_can_transition():
    """UI 按钮和服务端校验必须同源。"""
    for status in ALL_STATUSES:
        for role in ALL_ROLES:
            vuln, user = _FakeVuln(status), _FakeUser(role)
            listed = {action for action, _ in available_actions(vuln, user)}
            allowed = {a for a in TRANSITIONS if can_transition(vuln, a, user)[0]}
            assert listed == allowed, (status, role)


# ---------------------------------------------------------------- HTTP 层


def _post_transition(client, vuln_id, action, comment=None):
    data = {}
    if comment:
        data['verification_comment'] = comment
    return client.post(f'/vulnerabilities/{vuln_id}/transition/{action}', data=data)


def test_fix_then_verify_pass_end_to_end(app, client, seed, as_user):
    """主链 pending → fixed → closed,时间戳、复测历史、审计都要对。"""
    vuln_id = seed.vuln_ids['pending']
    dev_id = seed.user_ids['dev']
    tester_id = seed.user_ids['tester']

    as_user(dev_id)
    assert _post_transition(client, vuln_id, 'fix').status_code == 302

    with app.app_context():
        vuln = db.session.get(Vulnerability, vuln_id)
        assert vuln.status == 'fixed'
        assert vuln.fixed_at is not None

    as_user(tester_id)
    assert _post_transition(client, vuln_id, 'verify_pass', '已复测通过').status_code == 302

    with app.app_context():
        vuln = db.session.get(Vulnerability, vuln_id)
        assert vuln.status == 'closed'
        assert vuln.closed_at is not None
        assert vuln.verification_result == 'pass'

        history = json.loads(vuln.verification_history or '[]')
        assert len(history) == 1
        assert history[0]['result'] == 'pass'

        logs = AuditLog.query.filter_by(resource_id=vuln_id).order_by(AuditLog.id).all()
        transitions = [row for row in logs if row.action == 'verify_pass']
        assert len(transitions) == 1
        assert transitions[0].from_status == 'fixed'
        assert transitions[0].to_status == 'closed'


def test_verify_fail_returns_to_pending(app, client, seed, as_user):
    vuln_id = seed.vuln_ids['fixed']
    as_user(seed.user_ids['tester'])
    assert _post_transition(client, vuln_id, 'verify_fail', '仍有问题').status_code == 302

    with app.app_context():
        vuln = db.session.get(Vulnerability, vuln_id)
        assert vuln.status == 'pending'
        assert vuln.closed_at is None
        assert vuln.verification_result == 'fail'


def test_wrong_role_gets_403(app, client, seed, as_user):
    """developer 不能执行复测。"""
    as_user(seed.user_ids['dev'])
    assert _post_transition(client, seed.vuln_ids['fixed'], 'verify_pass').status_code == 403


def test_non_assignee_developer_gets_403(app, client, seed, as_user):
    """不是责任人的开发人员提交修复属于越权,应 403 而不是静默跳转。

    种子数据里漏洞都指派给 dev,dev2 不是责任人。
    """
    as_user(seed.user_ids['dev2'])
    resp = _post_transition(client, seed.vuln_ids['pending'], 'fix')
    assert resp.status_code == 403


def test_stale_state_flashes_instead_of_403(app, client, seed, as_user):
    """页面过期（源状态已变）给友好提示,不是 403。"""
    as_user(seed.user_ids['tester'])
    resp = _post_transition(client, seed.vuln_ids['pending'], 'verify_pass')
    assert resp.status_code == 302


def test_verification_history_is_rendered(app, client, seed, as_user):
    """回归:状态机一直在写 verification_history,但全站没有任何模板渲染它。

    数据只写不读,「复测历史」这个能力等于不存在。
    """
    vuln_id = seed.vuln_ids['pending']

    as_user(seed.user_ids['dev'])
    client.post(f'/vulnerabilities/{vuln_id}/transition/fix')
    as_user(seed.user_ids['tester'])
    client.post(f'/vulnerabilities/{vuln_id}/transition/verify_fail',
                data={'verification_comment': '仍有残留，请继续整改'})
    as_user(seed.user_ids['dev'])
    client.post(f'/vulnerabilities/{vuln_id}/transition/fix')
    as_user(seed.user_ids['tester'])
    client.post(f'/vulnerabilities/{vuln_id}/transition/verify_pass',
                data={'verification_comment': '已确认修复'})

    body = client.get(f'/vulnerabilities/{vuln_id}').get_data(as_text=True)
    assert '流转与复测历史' in body, '详情页没有渲染复测历史'
    assert '复测通过' in body and '复测不通过' in body
    # 操作人与说明都要能看到
    assert '操作人' in body
    assert '仍有残留，请继续整改' in body
    assert '已确认修复' in body


def test_history_is_newest_first(app, client, seed, as_user):
    """时间线按时间倒序,最近一次流转排在最上面。"""
    vuln_id = seed.vuln_ids['pending']
    as_user(seed.user_ids['dev'])
    client.post(f'/vulnerabilities/{vuln_id}/transition/fix')
    as_user(seed.user_ids['tester'])
    client.post(f'/vulnerabilities/{vuln_id}/transition/verify_fail',
                data={'verification_comment': '第一次退回'})
    as_user(seed.user_ids['dev'])
    client.post(f'/vulnerabilities/{vuln_id}/transition/fix')
    as_user(seed.user_ids['tester'])
    client.post(f'/vulnerabilities/{vuln_id}/transition/verify_fail',
                data={'verification_comment': '第二次退回'})

    body = client.get(f'/vulnerabilities/{vuln_id}').get_data(as_text=True)
    assert body.index('第二次退回') < body.index('第一次退回'), '时间线没有倒序'


def test_edit_cannot_bypass_state_machine(app, client, seed, as_user):
    """回归:改造前 edit() 能直接把状态写成 closed,绕过全部校验。

    现在 edit 表单里根本没有 status 字段,提交 status=closed 必须无效。
    """
    vuln_id = seed.vuln_ids['pending']
    as_user(seed.user_ids['tester'])

    with app.app_context():
        vuln = db.session.get(Vulnerability, vuln_id)
        payload = {
            'title': '被改过的标题',
            'description': vuln.description or 'x',
            'project_id': str(vuln.project_id),
            'task_id': str(vuln.task_id or 0),
            'source': vuln.source or 'manual',
            'severity': vuln.severity or '中危',
            'vuln_type': vuln.vuln_type or '',
            'assignee_id': str(vuln.assignee_id or 0),
            'status': 'closed',          # 旁路尝试
        }

    client.post(f'/vulnerabilities/{vuln_id}/edit', data=payload)

    with app.app_context():
        vuln = db.session.get(Vulnerability, vuln_id)
        # 先证明这次编辑确实生效了,否则下面的断言是空过
        assert vuln.title == '被改过的标题', '编辑根本没生效,本用例无意义'
        assert vuln.status == 'pending', 'edit 仍能改状态,旁路没堵住'


def test_edit_does_not_reset_due_date_when_severity_unchanged(app, client, seed, as_user):
    """回归:原实现每次保存都重算 SLA,会让逾期统计恒为 0。"""
    vuln_id = seed.vuln_ids['pending']
    as_user(seed.user_ids['tester'])

    with app.app_context():
        vuln = db.session.get(Vulnerability, vuln_id)
        from app.services import calculate_due_date
        vuln.due_date = calculate_due_date('中危')
        db.session.commit()
        original_due = vuln.due_date
        payload = {
            'title': '改个标题而已',
            'description': vuln.description or 'x',
            'project_id': str(vuln.project_id),
            'task_id': str(vuln.task_id or 0),
            'source': vuln.source or 'manual',
            'severity': vuln.severity or '中危',
            'vuln_type': vuln.vuln_type or '',
            'assignee_id': str(vuln.assignee_id or 0),
        }

    client.post(f'/vulnerabilities/{vuln_id}/edit', data=payload)

    with app.app_context():
        vuln = db.session.get(Vulnerability, vuln_id)
        assert vuln.due_date == original_due, '等级没变却重置了 SLA 截止时间'
