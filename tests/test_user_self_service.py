"""用户的个人资料与密码管理。

改造前全站**没有任何改密入口** —— 用户忘记密码后，唯一的补救手段是直接改
``instance/sdl.db`` 里的 ``users.password_hash``。也没有任何改资料的途径。
"""
import pytest
from werkzeug.security import check_password_hash

from app import db
from app.models import AuditLog, User
from tests.conftest import PASSWORD


def _password_of(user_id):
    return db.session.get(User, user_id).password_hash


# ---------------------------------------------------------------- 修改密码


def test_change_password(app, client, seed, as_user):
    user_id = seed.user_ids['tester']
    as_user(user_id)

    resp = client.post('/auth/password', data={
        'current_password': PASSWORD,
        'new_password': 'brand-new-pass',
        'confirm_password': 'brand-new-pass',
    }, follow_redirects=False)
    assert resp.status_code == 302

    with app.app_context():
        assert check_password_hash(_password_of(user_id), 'brand-new-pass')
        row = AuditLog.query.filter_by(action='user_password_change').first()
        assert row is not None
        assert row.operator_id == user_id


def test_new_password_actually_works_for_login(app, client, seed, as_user):
    user_id = seed.user_ids['tester']
    as_user(user_id)
    client.post('/auth/password', data={
        'current_password': PASSWORD, 'new_password': 'brand-new-pass',
        'confirm_password': 'brand-new-pass'})

    client.get('/auth/logout')

    assert client.post('/auth/login', data={
        'username': 'tester', 'password': 'brand-new-pass'},
        follow_redirects=False).status_code == 302
    client.get('/auth/logout')
    assert client.post('/auth/login', data={
        'username': 'tester', 'password': PASSWORD},
        follow_redirects=False).status_code == 200, '旧密码不该还能登录'


def test_change_password_rejects_wrong_current(app, client, seed, as_user):
    user_id = seed.user_ids['tester']
    before = None
    with app.app_context():
        before = _password_of(user_id)

    as_user(user_id)
    resp = client.post('/auth/password', data={
        'current_password': 'wrong-password',
        'new_password': 'brand-new-pass',
        'confirm_password': 'brand-new-pass',
    }, follow_redirects=False)

    assert resp.status_code == 200, '当前密码不对应当重新渲染表单'
    assert '当前密码不正确' in resp.get_data(as_text=True)

    with app.app_context():
        assert _password_of(user_id) == before, '密码不该被改掉'


def test_change_password_rejects_same_password(app, client, seed, as_user):
    as_user(seed.user_ids['tester'])
    resp = client.post('/auth/password', data={
        'current_password': PASSWORD,
        'new_password': PASSWORD,
        'confirm_password': PASSWORD,
    }, follow_redirects=False)
    assert resp.status_code == 200
    assert '不能与当前密码相同' in resp.get_data(as_text=True)


def test_change_password_rejects_mismatch(app, client, seed, as_user):
    as_user(seed.user_ids['tester'])
    resp = client.post('/auth/password', data={
        'current_password': PASSWORD,
        'new_password': 'brand-new-pass',
        'confirm_password': 'different-pass',
    }, follow_redirects=False)
    assert resp.status_code == 200
    assert '不一致' in resp.get_data(as_text=True)


def test_change_password_rejects_too_short(app, client, seed, as_user):
    user_id = seed.user_ids['tester']
    before = None
    with app.app_context():
        before = _password_of(user_id)

    as_user(user_id)
    client.post('/auth/password', data={
        'current_password': PASSWORD, 'new_password': 'abc',
        'confirm_password': 'abc'})

    with app.app_context():
        assert _password_of(user_id) == before


def test_anonymous_cannot_change_password(app, client, seed):
    resp = client.post('/auth/password', data={
        'current_password': 'x', 'new_password': 'yyyyyy', 'confirm_password': 'yyyyyy'})
    assert resp.status_code in (302, 401)


# ---------------------------------------------------------------- 个人资料


def test_update_profile_email(app, client, seed, as_user):
    user_id = seed.user_ids['tester']
    as_user(user_id)

    resp = client.post('/auth/profile', data={'email': 'new-address@corp.local'},
                       follow_redirects=False)
    assert resp.status_code == 302

    with app.app_context():
        assert db.session.get(User, user_id).email == 'new-address@corp.local'
        row = AuditLog.query.filter_by(action='user_profile_update').first()
        assert row is not None and 'new-address@corp.local' in row.detail


def test_profile_rejects_email_taken_by_others(app, client, seed, as_user):
    """种子里每个账号的邮箱是 <username>@test.local。"""
    user_id = seed.user_ids['tester']
    as_user(user_id)

    resp = client.post('/auth/profile', data={'email': 'admin@test.local'},
                       follow_redirects=False)
    assert resp.status_code == 200
    assert '已被其他账号使用' in resp.get_data(as_text=True)

    with app.app_context():
        assert db.session.get(User, user_id).email != 'admin@test.local'


def test_profile_rejects_invalid_email(app, client, seed, as_user):
    user_id = seed.user_ids['tester']
    before = None
    with app.app_context():
        before = db.session.get(User, user_id).email

    as_user(user_id)
    client.post('/auth/profile', data={'email': 'not-an-email'})

    with app.app_context():
        assert db.session.get(User, user_id).email == before


def test_profile_cannot_change_username(app, client, seed, as_user):
    """用户名是登录凭据且被审计引用，界面不给改，这里确认后端也不认。"""
    user_id = seed.user_ids['tester']
    as_user(user_id)
    client.post('/auth/profile', data={'email': 'ok@corp.local', 'username': 'hacker'})

    with app.app_context():
        assert db.session.get(User, user_id).username == 'tester'


# ---------------------------------------------------------------- 管理员重置


def test_admin_can_reset_other_password(app, client, seed, as_user):
    target_id = seed.user_ids['tester']
    as_user(seed.user_ids['admin'])

    resp = client.post(f'/auth/users/{target_id}/reset-password',
                       data={'new_password': 'reset-by-admin'}, follow_redirects=False)
    assert resp.status_code == 302

    with app.app_context():
        assert check_password_hash(_password_of(target_id), 'reset-by-admin')
        row = AuditLog.query.filter_by(action='user_password_reset').first()
        assert row is not None
        assert row.resource_id == target_id
        assert row.operator_id == seed.user_ids['admin']


def test_non_admin_cannot_reset_password(app, client, seed, as_user):
    target_id = seed.user_ids['tester']
    before = None
    with app.app_context():
        before = _password_of(target_id)

    for name in ('tester', 'dev', 'biz', 'guest', 'lead'):
        as_user(seed.user_ids[name])
        assert client.post(f'/auth/users/{target_id}/reset-password',
                           data={'new_password': 'hacked-pass'}).status_code == 403, name

    with app.app_context():
        assert _password_of(target_id) == before


def test_reset_password_rejects_too_short(app, client, seed, as_user):
    target_id = seed.user_ids['tester']
    before = None
    with app.app_context():
        before = _password_of(target_id)

    as_user(seed.user_ids['admin'])
    client.post(f'/auth/users/{target_id}/reset-password', data={'new_password': 'abc'})

    with app.app_context():
        assert _password_of(target_id) == before
