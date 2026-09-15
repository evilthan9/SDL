"""注册流程测试。

此前没有任何测试**提交**过注册表单（只 GET 过页面），所以两个 bug 都溜了过去:

1. ``RegistrationForm`` 有一个 ``role`` 下拉,但 ``register.html`` 从未渲染它 ——
   字段不随表单提交,而 SelectField 的 ``pre_validate`` 要求"值必须在 choices 里",
   于是表单永远校验不过:点注册不报错,只是原地重渲染,**用户建不出来**;
2. WTForms 的 ``Email()`` 校验器依赖可选的 ``email_validator`` 包,缺了会在
   **校验时**抛异常 —— 注册页直接 500。
"""
import pytest

from app import db
from app.models import User

VALID = {
    'username': 'newcomer',
    'email': 'newcomer@example.com',
    'password': 'secret123',
    'confirm_password': 'secret123',
}


def _count_users():
    return User.query.count()


def test_register_creates_user(app, client):
    """回归:注册表单此前永远提交不成功。"""
    with app.app_context():
        before = _count_users()

    resp = client.post('/auth/register', data=VALID, follow_redirects=False)
    assert resp.status_code == 302, '注册应当成功并跳转'

    with app.app_context():
        assert _count_users() == before + 1
        user = User.query.filter_by(username='newcomer').first()
        assert user is not None
        assert user.role == 'guest', '自助注册一律是访客,角色由管理员分配'
        assert user.email == 'newcomer@example.com'


def test_registered_user_can_log_in(app, client):
    client.post('/auth/register', data=VALID, follow_redirects=False)
    resp = client.post('/auth/login',
                       data={'username': 'newcomer', 'password': 'secret123'},
                       follow_redirects=False)
    assert resp.status_code == 302


def test_register_rejects_duplicate_username(app, client, seed):
    resp = client.post('/auth/register', data=dict(VALID, username='tester'),
                       follow_redirects=False)
    assert resp.status_code == 200, '重复用户名应当重新渲染表单而不是跳转'
    body = resp.get_data(as_text=True)
    assert '已被使用' in body or '已被注册' in body


def test_register_rejects_mismatched_password(app, client):
    resp = client.post('/auth/register',
                       data=dict(VALID, confirm_password='different'),
                       follow_redirects=False)
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert 'Field must be equal' in body or '不一致' in body


def test_register_rejects_invalid_email(app, client):
    resp = client.post('/auth/register', data=dict(VALID, email='not-an-email'),
                       follow_redirects=False)
    assert resp.status_code == 200
    with app.app_context():
        assert User.query.filter_by(username='newcomer').first() is None


def test_register_form_has_no_dead_role_field(app):
    """回归:role 字段既没渲染也没被后端读取,留着只会让表单校验失败。"""
    from app.forms import RegistrationForm
    assert not hasattr(RegistrationForm, 'role'), \
        'RegistrationForm 不应再有 role 字段'


def test_email_fallback_works_without_email_validator(monkeypatch):
    """缺 email_validator 时应当降级成形状检查,而不是让注册页 500。

    用户实际踩到的就是这个:换了个没装该依赖的解释器（比如忘了激活 venv）,
    点注册直接 500。
    """
    from app import forms

    monkeypatch.setattr(forms, '_HAS_EMAIL_VALIDATOR', False)
    validator = forms.EmailAddress()

    class _Field:
        def __init__(self, data):
            self.data = data

    from wtforms.validators import ValidationError

    # 正常邮箱放行
    validator(None, _Field('someone@example.com'))

    # 明显不合法的一律拦下
    for bad in ('not-an-email', 'a@b', 'no-at-sign.com', '', ' a b@c.com'):
        with pytest.raises(ValidationError):
            validator(None, _Field(bad))


def test_internal_domain_emails_are_accepted(app, client):
    """内网保留域名（.local 等）必须能注册。

    本系统是车企内网工具,`zhangsan@corp.local` 是正常的工号邮箱;
    email_validator 默认会拒掉这些 TLD,而种子数据的演示账号用的就是
    @demo.local —— 不放开就自相矛盾。
    """
    resp = client.post('/auth/register',
                       data=dict(VALID, username='intranet', email='zhangsan@corp.local'),
                       follow_redirects=False)
    assert resp.status_code == 302, resp.get_data(as_text=True)[:300]
    with app.app_context():
        assert User.query.filter_by(username='intranet').first() is not None


def test_email_validator_dependency_is_declared():
    """Email() 校验器依赖 email_validator,必须声明在 requirements 里。

    它不会在导入时报错,只在**校验时**炸,所以缺了很难排查。
    """
    import pathlib
    requirements = (pathlib.Path(__file__).resolve().parent.parent
                    / 'requirements.txt').read_text(encoding='utf-8')
    assert 'email_validator' in requirements, \
        'requirements.txt 里必须声明 email_validator'
