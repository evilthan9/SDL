"""权限测试:功能权限矩阵 + 数据可见范围。

重点覆盖改造前的越权读缺陷:``detail()`` 的注释写着"开发者只能看指派给自己的",
但代码里没有任何过滤,任意 developer 能读任意漏洞。
"""
import re

import pytest

from app import db
from app.models import User, Vulnerability
from app.permissions import (
    PERMISSIONS, apply_vuln_scope, can_view_vulnerability, has_perm,
)


# ---------------------------------------------------------------- 数据范围

def test_guest_scope_is_closed_only(app, seed):
    with app.app_context():
        guest = db.session.get(User, seed.user_ids['guest'])
        visible = apply_vuln_scope(Vulnerability.query, guest).all()
        assert visible, '访客应至少能看到已闭环漏洞'
        assert {v.status for v in visible} == {'closed'}


def test_developer_scope_is_assigned_only(app, seed):
    """回归:改造前 developer 能看到全部漏洞。"""
    with app.app_context():
        dev = db.session.get(User, seed.user_ids['dev'])
        visible = apply_vuln_scope(Vulnerability.query, dev).all()
        assert visible, 'dev 是被指派人,应能看到漏洞'
        assert all(v.assignee_id == dev.id for v in visible)


def test_developer2_sees_nothing_when_unassigned(app, seed):
    with app.app_context():
        dev2 = db.session.get(User, seed.user_ids['dev2'])
        assert apply_vuln_scope(Vulnerability.query, dev2).all() == []


def test_tester_scope_is_own_cases(app, seed):
    with app.app_context():
        tester = db.session.get(User, seed.user_ids['tester'])
        visible = apply_vuln_scope(Vulnerability.query, tester).all()
        assert visible
        assert all(v.creator_id == tester.id for v in visible)

        tester2 = db.session.get(User, seed.user_ids['tester2'])
        assert apply_vuln_scope(Vulnerability.query, tester2).all() == []


def test_business_scope_is_owned_projects(app, seed):
    with app.app_context():
        biz = db.session.get(User, seed.user_ids['biz'])
        visible = apply_vuln_scope(Vulnerability.query, biz).all()
        assert visible
        assert all(v.project.owner_id == biz.id for v in visible)


def test_admin_and_lead_see_everything(app, seed):
    with app.app_context():
        everything = Vulnerability.query.count()
        for name in ('admin', 'lead'):
            user = db.session.get(User, seed.user_ids[name])
            assert apply_vuln_scope(Vulnerability.query, user).count() == everything


def test_single_object_scope_matches_query_scope(app, seed):
    """详情页判断和列表页过滤必须一致,否则会出现死链。"""
    with app.app_context():
        all_vulns = Vulnerability.query.all()
        for name, uid in seed.user_ids.items():
            user = db.session.get(User, uid)
            listed = {v.id for v in apply_vuln_scope(Vulnerability.query, user).all()}
            single = {v.id for v in all_vulns if can_view_vulnerability(v, user)}
            assert listed == single, f'{name} 的列表与详情可见范围不一致'


# ---------------------------------------------------------------- 功能权限矩阵

def test_matrix_direction_is_sane():
    """admin 的权限必须是其余所有角色的超集;guest 不能有写权限。"""
    admin_perms = PERMISSIONS['admin']
    for role, perms in PERMISSIONS.items():
        if role == 'admin':
            continue
        assert perms <= admin_perms, f'{role} 有 admin 没有的权限'
    assert PERMISSIONS['guest'] <= {'vuln.view'}


def test_every_permission_point_is_enforced_somewhere():
    """矩阵里声明的每个权限点都必须在路由层真正被检查。

    改造前有 7 个权限点只声明不检查（实际用 can_access_testing() / 硬编码角色
    代替），矩阵与执行是两套真相 —— 论文里"基于权限矩阵的 RBAC"一节就站不住。
    这条断言让"声明了却没人用"的权限点无处藏身。
    """
    import pathlib
    import re

    from app import permissions

    declared = {
        name for name in dir(permissions)
        if name.startswith('PERM_') and name.isupper()
    }
    assert declared, '没有解析到任何权限点常量'

    routes_dir = pathlib.Path(__file__).resolve().parent.parent / 'app' / 'routes'
    sources = '\n'.join(
        path.read_text(encoding='utf-8') for path in routes_dir.glob('*.py')
    )

    # 必须出现在 has_perm(...) / require_perm(...) 的**调用**里。
    # 只查"名字是否在文件里出现"是不够的 —— import 行就会让它通过,
    # 而权限点被删掉后 import 通常还留着。
    unused = sorted(
        name for name in declared
        if not re.search(
            r'(?:has_perm|require_perm)\s*\(\s*(?:current_user\s*,\s*)?' + re.escape(name) + r'\b',
            sources,
        )
    )
    assert not unused, (
        '以下权限点在 PERMISSIONS 矩阵里声明了，但没有任何路由检查它们'
        '（只在 import 里出现不算）：\n' + '\n'.join(unused)
    )


def test_screenshot_requires_login(app, client, seed):
    """回归:这个路由此前没有 @login_required,未登录也能按文件名取图。"""
    filename = 'a' * 32 + '.png'
    resp = client.get(f'/vulnerabilities/screenshot/{filename}')
    assert resp.status_code in (302, 401), \
        f'未登录取图应当被拦下，实际 {resp.status_code}'


def test_screenshot_rejects_path_traversal(app, client, seed, as_user):
    """NAME_RE 是这条链路上唯一的路径穿越防线。"""
    as_user(seed.user_ids['admin'])
    for bad in ('../../etc/passwd', '..%2f..%2fapp.py', 'notahexname.png'):
        resp = client.get(f'/vulnerabilities/screenshot/{bad}')
        assert resp.status_code == 404, bad


def test_anonymous_has_no_permission():
    class Anon:
        is_authenticated = False
        role = None

    assert not has_perm(Anon(), 'vuln.view')


# ---------------------------------------------------------------- HTTP 层

def test_developer_cannot_read_unassigned_vulnerability(app, client, seed, as_user):
    """越权读回归:dev2 没有指派到任何漏洞,直接敲 URL 应被拒。"""
    vuln_id = seed.vuln_ids['pending']
    as_user(seed.user_ids['dev2'])
    resp = client.get(f'/vulnerabilities/{vuln_id}')
    assert resp.status_code == 403


def test_assigned_developer_can_read(app, client, seed, as_user):
    as_user(seed.user_ids['dev'])
    assert client.get(f'/vulnerabilities/{seed.vuln_ids["pending"]}').status_code == 200


def test_guest_cannot_read_pending_but_can_read_closed(app, client, seed, as_user):
    as_user(seed.user_ids['guest'])
    assert client.get(f'/vulnerabilities/{seed.vuln_ids["pending"]}').status_code == 403
    assert client.get(f'/vulnerabilities/{seed.vuln_ids["closed"]}').status_code == 200


def test_developer_cannot_edit_others_vulnerability(app, client, seed, as_user):
    """越权写回归:edit 原先只判角色、不判归属。"""
    as_user(seed.user_ids['dev2'])
    editor = client.get(f'/vulnerabilities/{seed.vuln_ids["pending"]}/edit')
    assert editor.status_code == 403


def test_unauthorized_role_cannot_transition(app, client, seed, as_user):
    as_user(seed.user_ids['biz'])
    resp = client.post(f'/vulnerabilities/{seed.vuln_ids["fixed"]}/transition/verify_pass')
    assert resp.status_code == 403


def test_non_admin_cannot_open_user_admin(app, client, seed, as_user):
    for name in ('tester', 'dev', 'biz', 'guest', 'lead'):
        as_user(seed.user_ids[name])
        assert client.get('/auth/users').status_code == 403, name


def test_project_vulnerability_list_has_no_dead_links(app, client, seed, as_user):
    """列表里给出的每条漏洞,点进去都必须能打开。"""
    as_user(seed.user_ids['dev'])
    resp = client.get(f'/projects/{seed.project_id}/vulnerabilities')
    assert resp.status_code == 200

    with app.app_context():
        dev = db.session.get(User, seed.user_ids['dev'])
        visible_ids = [
            v.id for v in apply_vuln_scope(
                Vulnerability.query.filter_by(project_id=seed.project_id), dev
            ).all()
        ]

    for vuln_id in visible_ids:
        assert client.get(f'/vulnerabilities/{vuln_id}').status_code == 200
