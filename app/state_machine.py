"""漏洞状态机 —— 系统里**唯一**允许修改 ``Vulnerability.status`` 的地方。

一条主链 + 两个终止分支 + 一个回退::

    pending ──fix──> fixed ──verify_pass──> closed
       ^               │                      │
       │               │ verify_fail          │ reopen
       └───────────────┘                      │
       ^                                      │
       ├──────────────────────────────────────┘
       │
    false_positive / ignored ──reopen──> pending

主链 ``pending → fixed → closed`` 就是任务书要求的「三态流转」;误报/忽略是主链上
任一非终止态可以转出的**终止分支**;``reopen`` 是三个终止态唯一的回退路径。

改造前的状况:严格状态机虽然存在（``vulnerabilities.transition()``），但没有任何模板
调用它,是个从 UI 不可达的孤儿路由;真正生效的改状态入口是 ``edit()`` 里直接读表单
``status`` 字段写库,不校验源状态、不校验角色。本模块把规则收拢成单一事实来源后,
UI 按钮（``available_actions``）与服务端校验（``can_transition``）用的是同一份数据,
不可能出现"按钮能点、点了报错"或反过来"能改但没按钮"。
"""
import collections

from app.permissions import (
    ROLE_ADMIN, ROLE_BUSINESS, ROLE_DEVELOPER, ROLE_TESTER, ROLE_TEST_LEAD,
)

# ---------------------------------------------------------------- 状态

STATUS_PENDING = 'pending'
STATUS_FIXED = 'fixed'
STATUS_CLOSED = 'closed'
STATUS_FALSE_POSITIVE = 'false_positive'
STATUS_IGNORED = 'ignored'

STATUS_LABELS = {
    STATUS_PENDING: '待修复',
    STATUS_FIXED: '已修复待复测',
    STATUS_CLOSED: '已闭环',
    STATUS_FALSE_POSITIVE: '误报',
    STATUS_IGNORED: '已忽略',
}

ALL_STATUSES = tuple(STATUS_LABELS)

#: 终止态:不能再直接提交修复,必须先 reopen
TERMINAL_STATUSES = frozenset({STATUS_CLOSED, STATUS_FALSE_POSITIVE, STATUS_IGNORED})

#: 状态徽章的配色类（供模板统一取用,避免各页面各写一份 if/elif）。
#: 定义在 app/static/css/app.css —— 原先是 `vuln-pending` 这类名字,
#: 只在 management.html 的局部样式里定义过,导致别的页面（如看板）取到类名却
#: 没有对应规则、徽章没底色。
STATUS_BADGE_CLASSES = {
    STATUS_PENDING: 'ui-badge--pending',
    STATUS_FIXED: 'ui-badge--fixed',
    STATUS_CLOSED: 'ui-badge--closed',
    STATUS_FALSE_POSITIVE: 'ui-badge--false-positive',
    STATUS_IGNORED: 'ui-badge--ignored',
}


def status_label(status):
    """状态值 -> 中文标签。未知值原样返回,不抛 KeyError。"""
    return STATUS_LABELS.get(status, status or '未知')


#: verification_history 里 result 字段 -> 展示名。
#: apply_transition 每执行一次流转就往这个数组里追加一条,详情页据此渲染时间线。
VERIFICATION_ACTION_LABELS = {
    'pass': '复测通过',
    'fail': '复测不通过',
    'reopen': '重新打开',
    'false_positive': '判定误报',
    'ignored': '风险接受',
}

VERIFICATION_ACTION_CLASSES = {
    'pass': 'ui-badge--closed',
    'fail': 'ui-badge--critical',
    'reopen': 'ui-badge--pending',
    'false_positive': 'ui-badge--false-positive',
    'ignored': 'ui-badge--ignored',
}


def verification_action_label(result):
    return VERIFICATION_ACTION_LABELS.get(result, result or '流转')


def verification_action_class(result):
    return VERIFICATION_ACTION_CLASSES.get(result, 'ui-badge--low')


# ---------------------------------------------------------------- 转换表

#: scope 取值:
#:   'any'      —— 角色白名单内任何人都可执行
#:   'assignee' —— 仅漏洞责任人本人;但 assignee_id 为空时放宽到角色白名单
#:                 (存量数据大量为空,严格限制会让「提交修复」永远 403)
Transition = collections.namedtuple(
    'Transition', 'action label from_states to_state roles scope'
)

TRANSITIONS = {
    'fix': Transition(
        'fix', '提交修复', frozenset({STATUS_PENDING}), STATUS_FIXED,
        frozenset({ROLE_DEVELOPER, ROLE_BUSINESS, ROLE_TEST_LEAD, ROLE_ADMIN}),
        'assignee',
    ),
    'verify_pass': Transition(
        'verify_pass', '复测通过', frozenset({STATUS_FIXED}), STATUS_CLOSED,
        frozenset({ROLE_TESTER, ROLE_TEST_LEAD, ROLE_ADMIN}),
        'any',
    ),
    'verify_fail': Transition(
        'verify_fail', '复测不通过', frozenset({STATUS_FIXED}), STATUS_PENDING,
        frozenset({ROLE_TESTER, ROLE_TEST_LEAD, ROLE_ADMIN}),
        'any',
    ),
    'mark_false_positive': Transition(
        'mark_false_positive', '判定误报',
        frozenset({STATUS_PENDING, STATUS_FIXED}), STATUS_FALSE_POSITIVE,
        frozenset({ROLE_TESTER, ROLE_TEST_LEAD, ROLE_ADMIN}),
        'any',
    ),
    'mark_ignored': Transition(
        'mark_ignored', '风险接受', frozenset({STATUS_PENDING, STATUS_FIXED}), STATUS_IGNORED,
        frozenset({ROLE_BUSINESS, ROLE_TEST_LEAD, ROLE_ADMIN}),
        'any',
    ),
    'reopen': Transition(
        'reopen', '重新打开', TERMINAL_STATUSES, STATUS_PENDING,
        frozenset({ROLE_TEST_LEAD, ROLE_ADMIN}),
        'any',
    ),
}


# ---------------------------------------------------------------- 校验


def is_authorized(vuln, action, user):
    """**只**判断授权(角色白名单 + 归属),不看源状态。

    单独拆出来是为了让调用方能区分两类拒绝:
    - 授权失败(角色不对/不是责任人) —— 属于越权,应答 403;
    - 源状态不匹配 —— 多半是页面过期,应 flash 提示后回详情页。

    归属规则同时被 ``can_transition`` 使用,不存在两处规则漂移。
    """
    if not getattr(user, 'is_authenticated', False):
        return False
    trans = TRANSITIONS.get(action)
    if trans is None:
        return False
    if user.role not in trans.roles:
        return False
    # assignee_id 为空时不限制(存量数据大量为空,否则"提交修复"会永远失败)
    if trans.scope == 'assignee' and vuln.assignee_id and vuln.assignee_id != user.id:
        return False
    return True


def can_transition(vuln, action, user):
    """能否对该漏洞执行该动作。返回 ``(ok, reason)``,reason 是可直接 flash 的中文。

    UI 渲染按钮和服务端校验都调这个函数,保证两者永不脱节。
    """
    if not getattr(user, 'is_authenticated', False):
        return False, '请先登录'

    trans = TRANSITIONS.get(action)
    if trans is None:
        return False, '无效的操作'

    if not is_authorized(vuln, action, user):
        if user.role not in trans.roles:
            return False, f'当前角色无权执行「{trans.label}」'
        return False, '仅该漏洞的责任人可提交修复'

    if vuln.status not in trans.from_states:
        return False, f'当前状态为「{status_label(vuln.status)}」，无法执行「{trans.label}」'

    return True, ''


def available_actions(vuln, user):
    """该用户此刻能对这个漏洞执行的动作列表,供详情页渲染按钮。

    返回 ``[(action, label), ...]``,顺序即展示顺序。
    """
    return [
        (action, TRANSITIONS[action].label)
        for action in TRANSITIONS
        if can_transition(vuln, action, user)[0]
    ]


def is_terminal(status):
    return status in TERMINAL_STATUSES


# ---------------------------------------------------------------- 执行


def apply_transition(vuln, action, user, comment=None):
    """执行状态转换:改状态、盖时间戳、写复测历史与审计。

    调用方负责 ``db.session.commit()``（与 ``services.log_audit`` 的约定一致,
    便于把状态变更和其他改动放进同一个事务）。

    调用前**必须**先过 ``can_transition``;这里不再重复校验,以免两处规则漂移。
    """
    from datetime import datetime

    from app.services import append_verification_history, log_audit

    trans = TRANSITIONS[action]
    old_status = vuln.status
    new_status = trans.to_state
    now = datetime.utcnow()

    vuln.status = new_status

    if action == 'fix':
        vuln.fixed_at = now

    elif action == 'verify_pass':
        vuln.fixed_at = vuln.fixed_at or now
        vuln.closed_at = now
        vuln.verification_result = 'pass'
        vuln.verification_comment = comment or '复测通过'
        append_verification_history(vuln, 'pass', vuln.verification_comment, user.username)

    elif action == 'verify_fail':
        # 保留 fixed_at 作为历史,只把 closed_at 清掉
        vuln.closed_at = None
        vuln.verification_result = 'fail'
        vuln.verification_comment = comment or '复测不通过，请继续整改'
        append_verification_history(vuln, 'fail', vuln.verification_comment, user.username)

    elif action == 'reopen':
        vuln.closed_at = None
        vuln.verification_comment = comment or None
        append_verification_history(vuln, 'reopen', comment or '重新打开', user.username)

    elif action == 'mark_false_positive':
        vuln.closed_at = None
        vuln.verification_comment = comment or None
        append_verification_history(vuln, 'false_positive', comment or '判定为误报', user.username)

    elif action == 'mark_ignored':
        vuln.closed_at = None
        vuln.verification_comment = comment or None
        append_verification_history(vuln, 'ignored', comment or '风险接受', user.username)

    log_audit(
        operator_id=user.id,
        resource_type='vulnerability',
        resource_id=vuln.id,
        action=action,
        from_status=old_status,
        to_status=new_status,
        detail=f'状态转换：{status_label(old_status)} → {status_label(new_status)}'
               + (f'（{comment}）' if comment else ''),
    )
    return old_status, new_status


def seed_default_status():
    """新建漏洞的初始状态。"""
    return STATUS_PENDING
