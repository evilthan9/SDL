"""集中式权限控制。

分两个**正交**维度,论文里可以各自成节:

- **功能权限**（``PERMISSIONS``）:这个角色能做哪些操作。
- **数据范围**（``apply_vuln_scope`` / ``can_view_vulnerability``）:这个角色能看到谁的数据。

原实现只有三个布尔函数,且各路由里散落 11 处 ``role in [...]`` 硬编码
（``detail.html:82`` 甚至写成 ``role in ['admin','test_lead','tester'] or
role in ['developer','business']``,五个角色全列一遍,等价于"所有非 guest"）。
"""
from functools import wraps

from flask import abort
from flask_login import current_user
from sqlalchemy import or_

# ---------------------------------------------------------------- 角色

ROLE_GUEST = 'guest'
ROLE_BUSINESS = 'business'
ROLE_DEVELOPER = 'developer'
ROLE_TESTER = 'tester'
ROLE_TEST_LEAD = 'test_lead'
ROLE_ADMIN = 'admin'

#: 权限分配时可选的完整角色列表（顺序即展示顺序）
ALL_ROLES = (
    ROLE_GUEST, ROLE_BUSINESS, ROLE_DEVELOPER,
    ROLE_TESTER, ROLE_TEST_LEAD, ROLE_ADMIN,
)

ROLE_LABELS = {
    ROLE_GUEST: '访客',
    ROLE_BUSINESS: '业务人员',
    ROLE_DEVELOPER: '开发人员',
    ROLE_TESTER: '测试人员',
    ROLE_TEST_LEAD: '测试主管',
    ROLE_ADMIN: '管理员',
}

# ---------------------------------------------------------------- 权限点

PERM_DASHBOARD_VIEW = 'dashboard.view'      # 统计看板
PERM_VULN_VIEW = 'vuln.view'                # 漏洞详情
PERM_VULN_CREATE = 'vuln.create'            # 漏洞录入
PERM_VULN_EDIT = 'vuln.edit'                # 编辑漏洞字段
PERM_VULN_ASSIGN = 'vuln.assign'            # 指派/改派修复人
PERM_VULN_DELETE = 'vuln.delete'            # 删除/恢复(回收站)
PERM_VULN_EXPORT = 'vuln.export'            # 导出 CSV
PERM_VULN_MANAGE = 'vuln.manage'            # 进入漏洞管理列表
PERM_TASK_ASSIGN = 'task.assign'            # 分配测试任务
PERM_TASK_DELETE = 'task.delete'            # 删除测试任务
PERM_CASE_UPDATE = 'case.update'            # 测试用例状态变更
PERM_PROJECT_CREATE = 'project.create'      # 创建项目/迭代
PERM_ITERATION_MANAGE = 'iteration.manage'  # 迭代推送/删除
PERM_USER_MANAGE = 'user.manage'            # 用户权限管理
PERM_AUDIT_VIEW = 'audit.view'              # 查看审计日志

# ---- 安全扫描（SAST / SCA / 容器镜像）----
# 权限划分参照业界通行做法（GitHub Advanced Security / Prisma Cloud /
# Semgrep / Invicti 等）：发现默认受限,开发人员**只读且只看自己项目**,
# 安全团队负责录入与分级处置,策略与删除收口到更高一层。
PERM_SCAN_VIEW = 'scan.view'                # 查看扫描结果
PERM_SCAN_CREATE = 'scan.create'            # 录入扫描记录
PERM_SCAN_TRIAGE = 'scan.triage'            # 处置发现（忽略/标记）
PERM_SCAN_CONVERT = 'scan.convert'          # 把发现转为漏洞
PERM_SCAN_MANAGE = 'scan.manage'            # 编辑/删除扫描记录

PERMISSION_LABELS = {
    PERM_DASHBOARD_VIEW: '统计看板',
    PERM_VULN_VIEW: '查看漏洞',
    PERM_VULN_CREATE: '漏洞录入',
    PERM_VULN_EDIT: '编辑漏洞',
    PERM_VULN_ASSIGN: '指派修复人',
    PERM_VULN_DELETE: '删除/恢复漏洞',
    PERM_VULN_EXPORT: '导出漏洞',
    PERM_VULN_MANAGE: '漏洞管理列表',
    PERM_TASK_ASSIGN: '分配测试任务',
    PERM_TASK_DELETE: '删除测试任务',
    PERM_CASE_UPDATE: '用例状态变更',
    PERM_PROJECT_CREATE: '创建项目/迭代',
    PERM_ITERATION_MANAGE: '迭代推送/删除',
    PERM_USER_MANAGE: '用户权限管理',
    PERM_AUDIT_VIEW: '查看审计日志',
    PERM_SCAN_VIEW: '查看扫描结果',
    PERM_SCAN_CREATE: '录入扫描记录',
    PERM_SCAN_TRIAGE: '处置扫描发现',
    PERM_SCAN_CONVERT: '扫描发现转漏洞',
    PERM_SCAN_MANAGE: '编辑/删除扫描',
}

#: 扫描相关权限的默认授予（与下面的 PERMISSIONS 保持一致）
_SCAN_READONLY = {PERM_SCAN_VIEW}
_SCAN_OPERATOR = {PERM_SCAN_VIEW, PERM_SCAN_CREATE, PERM_SCAN_TRIAGE, PERM_SCAN_CONVERT}
_SCAN_MANAGER = _SCAN_OPERATOR | {PERM_SCAN_MANAGE}

#: 功能权限矩阵:角色 -> 允许的权限点集合。
#: 注意"能做什么"与"能看到谁的数据"是两回事,后者见 apply_vuln_scope。
PERMISSIONS = {
    # 访客可以"查看漏洞"这个操作,但数据范围被 apply_vuln_scope 收窄到仅 closed。
    # 功能权限与数据范围两层是正交的,别在这里重复限制。
    ROLE_GUEST: frozenset({PERM_VULN_VIEW}),

    # 业务人员:产品的只读视角（扫描结果只看自己名下项目）
    ROLE_BUSINESS: frozenset({
        PERM_DASHBOARD_VIEW, PERM_VULN_VIEW, PERM_VULN_EDIT,
        PERM_PROJECT_CREATE, PERM_ITERATION_MANAGE,
    }) | _SCAN_READONLY,

    # 开发人员:修复方。扫描结果**只读**,且只看自己参与的项目 ——
    # 这是业界一致的做法（不给开发开处置/配置权限,也不让他们看到无关项目）。
    ROLE_DEVELOPER: frozenset({
        PERM_DASHBOARD_VIEW, PERM_VULN_VIEW,
    }) | _SCAN_READONLY,

    ROLE_TESTER: frozenset({
        PERM_DASHBOARD_VIEW, PERM_VULN_VIEW, PERM_VULN_CREATE, PERM_VULN_EDIT,
        PERM_VULN_DELETE, PERM_VULN_EXPORT, PERM_VULN_MANAGE, PERM_CASE_UPDATE,
    }) | _SCAN_OPERATOR,

    ROLE_TEST_LEAD: frozenset({
        PERM_DASHBOARD_VIEW, PERM_VULN_VIEW, PERM_VULN_CREATE, PERM_VULN_EDIT,
        PERM_VULN_ASSIGN, PERM_VULN_DELETE, PERM_VULN_EXPORT, PERM_VULN_MANAGE,
        PERM_CASE_UPDATE, PERM_AUDIT_VIEW,
    }) | _SCAN_MANAGER,

    ROLE_ADMIN: frozenset({
        PERM_DASHBOARD_VIEW, PERM_VULN_VIEW, PERM_VULN_CREATE, PERM_VULN_EDIT,
        PERM_VULN_ASSIGN, PERM_VULN_DELETE, PERM_VULN_EXPORT, PERM_VULN_MANAGE,
        PERM_TASK_ASSIGN, PERM_TASK_DELETE, PERM_CASE_UPDATE, PERM_PROJECT_CREATE,
        PERM_ITERATION_MANAGE, PERM_USER_MANAGE, PERM_AUDIT_VIEW,
    }) | _SCAN_MANAGER,
}

#: 角色 -> 一句话数据范围说明（展示在页面和论文里）
SCOPE_LABELS = {
    ROLE_ADMIN: '全部漏洞',
    ROLE_TEST_LEAD: '全部漏洞',
    ROLE_TESTER: '本人测试发现的漏洞',
    ROLE_DEVELOPER: '指派给本人的漏洞',
    ROLE_BUSINESS: '本人名下项目的漏洞',
    ROLE_GUEST: '仅已闭环漏洞',
}

# ---------------------------------------------------------------- 判定


def has_perm(user, permission):
    """该用户是否拥有某个功能权限。未登录一律 False（匿名用户没有 role 属性）。"""
    if not getattr(user, 'is_authenticated', False):
        return False
    return permission in PERMISSIONS.get(user.role, frozenset())


def require_perm(permission):
    """路由装饰器:缺少权限则 403。

    必须**写在 @login_required 下面**（即更贴近视图函数），让 login_required 先处理
    匿名用户的重定向::

        @bp.route('/x')
        @login_required
        @require_perm(PERM_AUDIT_VIEW)
        def x(): ...

    顺序反了的话,匿名用户会走到这里拿到 403 而不是跳登录页。
    """

    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if not getattr(current_user, 'is_authenticated', False):
                abort(401)
            if not has_perm(current_user, permission):
                abort(403)
            return view(*args, **kwargs)
        return wrapper
    return decorator


# ---------------------------------------------------------------- 数据范围


def apply_vuln_scope(query, user):
    """把漏洞查询收窄到该用户可见的数据范围。

    列表页、导出、统计看板都应走这里,避免各写一份过滤条件 ——
    多写一份就是一个新的越权入口。
    """
    from app.models import Project, Vulnerability

    if user.role in (ROLE_ADMIN, ROLE_TEST_LEAD):
        return query
    if user.role == ROLE_TESTER:
        return query.filter(Vulnerability.creator_id == user.id)
    if user.role == ROLE_DEVELOPER:
        return query.filter(Vulnerability.assignee_id == user.id)
    if user.role == ROLE_BUSINESS:
        return query.filter(Vulnerability.project.has(Project.owner_id == user.id))
    if user.role == ROLE_GUEST:
        return query.filter(Vulnerability.status == 'closed')
    # 未知角色：一条都不给
    return query.filter(Vulnerability.id.is_(None))


def can_view_vulnerability(vuln, user):
    """单个漏洞的可见性判断,与 apply_vuln_scope 的规则保持一致。

    详情页用这个;列表页用 apply_vuln_scope。两者必须同步,
    否则列表里点进去就是死链。
    """
    if not getattr(user, 'is_authenticated', False):
        return False
    role = user.role
    if role in (ROLE_ADMIN, ROLE_TEST_LEAD):
        return True
    if role == ROLE_TESTER:
        return vuln.creator_id == user.id
    if role == ROLE_DEVELOPER:
        return vuln.assignee_id == user.id
    if role == ROLE_BUSINESS:
        return bool(vuln.project and vuln.project.owner_id == user.id)
    if role == ROLE_GUEST:
        return vuln.status == 'closed'
    return False


def apply_scan_scope(query, user):
    """把扫描查询收窄到该用户可见的范围。

    与漏洞的范围规则**不同**,这点是有意的,也符合业界做法:

    - 安全团队（admin / test_lead / tester）跨切面,看全部扫描结果;
    - 业务人员看自己名下项目的扫描;
    - 开发人员看**自己参与的项目**的扫描 —— "参与"定义为:自己是项目负责人、
      或该项目里有指派给自己的漏洞、或这次扫描就是自己录的。
      开发人员看不到与自己无关的项目扫描结果,这是 Securosis 等明确建议的
      "让开发只看到自己名下的资产"。
    - 访客一条都看不到。

    列表页、详情页、业务端嵌入块都应走这里,避免各写一份过滤条件。
    """
    from app import db
    from app.models import Project, Scan, Vulnerability

    if user.role in (ROLE_ADMIN, ROLE_TEST_LEAD, ROLE_TESTER):
        return query
    if user.role == ROLE_BUSINESS:
        return query.filter(Scan.project.has(Project.owner_id == user.id))
    if user.role == ROLE_DEVELOPER:
        involved_project_ids = db.session.query(Vulnerability.project_id).filter(
            Vulnerability.assignee_id == user.id,
            Vulnerability.project_id.isnot(None),
        )
        return query.filter(or_(
            Scan.creator_id == user.id,
            Scan.project.has(Project.owner_id == user.id),
            Scan.project_id.in_(involved_project_ids),
        ))
    # 访客与未知角色：一条都不给
    return query.filter(Scan.id.is_(None))


def can_view_scan(scan, user):
    """单个扫描记录的可见性,与 apply_scan_scope 保持一致（防死链）。"""
    from app.models import Vulnerability

    if not getattr(user, 'is_authenticated', False):
        return False
    role = user.role
    if role in (ROLE_ADMIN, ROLE_TEST_LEAD, ROLE_TESTER):
        return True
    if role == ROLE_BUSINESS:
        return bool(scan.project and scan.project.owner_id == user.id)
    if role == ROLE_DEVELOPER:
        if scan.creator_id == user.id:
            return True
        if scan.project and scan.project.owner_id == user.id:
            return True
        return any(v.assignee_id == user.id for v in scan.project.vulnerabilities) \
            if scan.project else False
    return False


def scan_scope_is_global(user):
    """该角色的扫描可见范围是否是全局的（安全团队与管理员）。

    单独抽出来是因为"录入扫描时能选哪些项目"要与"能看哪些扫描"用**同一条**规则。
    早先这里用 ``PERM_SCAN_MANAGE`` 判断,结果 tester（负责录入但没有 manage 权限）
    打开录入页时项目下拉是空的,根本选不了项目。
    """
    return user.role in (ROLE_ADMIN, ROLE_TEST_LEAD, ROLE_TESTER)


def scan_scope_label(user):
    return {
        ROLE_ADMIN: '全部扫描结果',
        ROLE_TEST_LEAD: '全部扫描结果',
        ROLE_TESTER: '全部扫描结果',
        ROLE_BUSINESS: '本人名下项目的扫描结果',
        ROLE_DEVELOPER: '本人参与项目的扫描结果',
    }.get(user.role, '无可见范围')


# ---------------------------------------------------------------- 旧接口兼容
# 以下三个函数是原 permissions.py 的全部内容,保留为兼容包装,
# 内部改查上面的矩阵,避免逐个调用点一次性替换时的空窗期。


def is_admin(user):
    return user.is_authenticated and user.role == ROLE_ADMIN


def can_access_business(user):
    """业务端（SDLC 流程页）的准入。admin 与业务/开发/访客均可。"""
    if not user.is_authenticated:
        return False
    return user.role in (ROLE_ADMIN, ROLE_BUSINESS, ROLE_DEVELOPER, ROLE_GUEST)


def can_access_testing(user):
    """测试端（项目/任务/用例）的准入。admin 与测试角色。"""
    if not user.is_authenticated:
        return False
    return user.role in (ROLE_ADMIN, ROLE_TESTER, ROLE_TEST_LEAD)
