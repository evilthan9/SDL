import re
from datetime import datetime

from flask_login import current_user
from flask_wtf import FlaskForm
from wtforms import (BooleanField, DateField, PasswordField, SelectField,
                     StringField, SubmitField, TextAreaField)
from wtforms.validators import (
    DataRequired, Email, EqualTo, InputRequired, Length, ValidationError,
)
from werkzeug.security import check_password_hash

from app.models import User

try:  # pragma: no cover - 取决于运行环境是否装了可选依赖
    import email_validator as _email_validator  # noqa: F401
    _HAS_EMAIL_VALIDATOR = True
except ImportError:  # pragma: no cover
    _HAS_EMAIL_VALIDATOR = False


#: 兜底用的宽松形状检查:有 @、两边非空白、域名带点
_EMAIL_SHAPE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')

#: 内网保留顶级域名。
#:
#: 这些域名不能交给 email_validator:`local` / `internal` / `invalid` 等都在它的
#: SPECIAL_USE_DOMAIN_NAMES 里被**硬拒**,而它的 test_environment 开关只豁免
#: `test` 一个值（见 syntax.py 里那句 `if d == "test" and test_environment`），
#: 其余一个都放不开。
#:
#: 本系统是车企内网工具,`zhangsan@corp.local` 是正常的工号邮箱,
#: 种子数据里的演示账号用的也正是 @demo.local。
_INTERNAL_TLDS = frozenset({'local', 'internal', 'lan', 'corp', 'home', 'intra'})


def EmailAddress(message='邮箱格式不正确'):
    """邮箱校验,缺 email_validator 依赖时自动降级。

    WTForms 的 ``Email()`` 对 ``email_validator`` 是延迟导入:没装的话不会在
    启动时报错,而是在**校验时**抛一个裸 ``Exception`` —— 用户看到的是注册页
    一个信息量为零的 500,而且换了 Python 解释器（比如没激活 venv）才会出现,
    极难排查。

    这里装了就用完整校验,没装就退化成形状检查。宁可校验宽松一点,
    也不要因为缺一个可选依赖让整个页面挂掉。
    """
    if _HAS_EMAIL_VALIDATOR:
        return _InternalEmail(message)
    return _ShapeEmail(message)


class _InternalEmail:
    """邮箱校验:内网域名走形状检查,其余交给 email_validator。

    分成两条路是因为 email_validator 对内网保留域名是硬拒的,没有开关能放开
    （详见 _INTERNAL_TLDS 的注释）。对公网域名仍走完整校验,不放松。
    """

    def __init__(self, message):
        self.message = message

    def __call__(self, form, field):
        value = (field.data or '').strip()

        domain = value.rsplit('@', 1)[-1].lower()
        if domain.rsplit('.', 1)[-1] in _INTERNAL_TLDS:
            if not _EMAIL_SHAPE.match(value):
                raise ValidationError(self.message)
            return

        from email_validator import EmailNotValidError, validate_email

        try:
            validate_email(value, check_deliverability=False)
        except EmailNotValidError:
            raise ValidationError(self.message)


class _ShapeEmail:
    """email_validator 缺席时的替代校验器。"""

    def __init__(self, message):
        self.message = message

    def __call__(self, form, field):
        value = (field.data or '').strip()
        if not _EMAIL_SHAPE.match(value):
            raise ValidationError(self.message)


class QuickDateField(DateField):
    """可留空的日期字段。

    WTForms 的 DateField 对空串也会抛 “Not a valid date value.”。
    这里允许留空(返回 None),格式错误时报中文提示。
    """

    def process_formdata(self, valuelist):
        if not valuelist or not valuelist[0].strip():
            self.data = None
            return
        raw = valuelist[0].strip()
        formats = self.format if isinstance(self.format, list) else [self.format]
        for fmt in formats:
            try:
                self.data = datetime.strptime(raw, fmt).date()
                return
            except ValueError:
                continue
        self.data = None
        raise ValueError('日期格式不正确，应为 YYYY-MM-DD')


class RegistrationForm(FlaskForm):
    """自助注册。

    刻意**没有** role 字段:注册一律创建访客,角色由管理员在「用户权限」里分配。
    原先这里有一个 role 下拉,但 `register.html` 从未渲染它 —— 字段不会随表单
    提交,而 SelectField 的 pre_validate 又要求"值必须在 choices 里",
    于是整个表单永远校验不过:点注册没有报错,只是原地重渲染,用户建不出来。
    """
    username = StringField('用户名', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('邮箱', validators=[DataRequired(), EmailAddress()])
    password = PasswordField('密码', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('确认密码', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('注册')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('用户名已被使用')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('邮箱已被注册')


class LoginForm(FlaskForm):
    username = StringField('用户名', validators=[DataRequired()])
    password = PasswordField('密码', validators=[DataRequired()])
    remember = BooleanField('记住我')
    submit = SubmitField('登录')


VULN_SOURCE_CHOICES = [
    ('manual', '人工测试'),
    ('sast', 'SAST'),
    ('sca', 'SCA'),
    ('penetration_test', '渗透测试'),
    ('security_scan', '安全扫描'),
    ('container', '容器镜像扫描'),
    ('incident', '安全事件'),
]

VULN_SEVERITY_CHOICES = [
    ('严重', '严重'),
    ('高危', '高危'),
    ('中危', '中危'),
    ('低危', '低危'),
]

#: 列表页筛选用的取值集合（与上面的 choices 保持同源）
VULN_SOURCE_VALUES = tuple(value for value, _ in VULN_SOURCE_CHOICES)
VULN_SEVERITY_VALUES = tuple(value for value, _ in VULN_SEVERITY_CHOICES)


VULN_TYPE_CHOICES = [
    ('sqli', 'SQL注入'),
    ('xss', 'XSS跨站脚本'),
    ('auth_bypass', '越权访问/认证绕过'),
    ('info_leak', '信息泄露'),
    ('csrf', 'CSRF'),
    ('ssrf', 'SSRF'),
    ('file_vuln', '文件上传/下载漏洞'),
    ('deserialize', '反序列化'),
    ('weak_password', '弱口令'),
    ('logic', '业务逻辑漏洞'),
    ('other', '其他'),
]

#: 漏洞类型筛选用的取值集合
VULN_TYPE_VALUES = tuple(value for value, _ in VULN_TYPE_CHOICES)


class VulnerabilityForm(FlaskForm):
    title = StringField('漏洞标题', validators=[DataRequired(), Length(max=200)])
    # 必须是 TextAreaField:原先用 StringField 会渲染成单行 <input>,
    # 模板里的 rows=4 被浏览器直接忽略,用户输入的换行会被压成一行。
    # 加长度上限是因为 sanitize_inline_html() 会对每个未闭合标签补一个闭合标签,
    # 不设限的话大量标签会放大成数倍体积。
    description = TextAreaField('漏洞描述',
                                validators=[DataRequired(), Length(max=20000)])
    project_id = SelectField('所属项目', validators=[DataRequired()], coerce=int)
    # 用 InputRequired 而不是 DataRequired:后者的实现是 `if not field.data`,
    # 会把合法的 0（"无关联任务"）判成"未填写",导致选 0 永远校验失败。
    # InputRequired 只检查字段是否真的提交了。
    task_id = SelectField('关联任务', validators=[InputRequired()], coerce=int)
    source = SelectField('漏洞来源', choices=VULN_SOURCE_CHOICES, validators=[DataRequired()])
    severity = SelectField('严重等级', choices=VULN_SEVERITY_CHOICES, validators=[DataRequired()])
    vuln_type = SelectField('漏洞类型', choices=[('', '请选择漏洞类型')] + VULN_TYPE_CHOICES, default='')
    # 同上:choices 里含 (0, '待分配') 的取值,0 是合法值
    assignee_id = SelectField('责任人', validators=[InputRequired()], coerce=int)
    submit = SubmitField('提交')

class ChangePasswordForm(FlaskForm):
    """自助修改密码。

    改造前全站没有任何改密入口 —— 忘了密码只能直接改数据库。
    """
    current_password = PasswordField('当前密码', validators=[DataRequired()])
    new_password = PasswordField('新密码',
                                 validators=[DataRequired(), Length(min=6, max=128)])
    confirm_password = PasswordField(
        '确认新密码',
        validators=[DataRequired(), EqualTo('new_password', message='两次输入的新密码不一致')])
    submit = SubmitField('修改密码')

    def validate_current_password(self, field):
        if not check_password_hash(current_user.password_hash, field.data):
            raise ValidationError('当前密码不正确')

    def validate_new_password(self, field):
        if field.data == self.current_password.data:
            raise ValidationError('新密码不能与当前密码相同')


class ProfileForm(FlaskForm):
    """编辑个人资料。用户名不允许改（它是登录凭据，且被审计日志引用）。"""
    email = StringField('邮箱', validators=[DataRequired(), EmailAddress()])
    submit = SubmitField('保存资料')

    def validate_email(self, field):
        existing = User.query.filter(User.email == field.data,
                                     User.id != current_user.id).first()
        if existing:
            raise ValidationError('该邮箱已被其他账号使用')


class ResetPasswordForm(FlaskForm):
    """管理员重置他人密码。"""
    new_password = PasswordField('新密码',
                                 validators=[DataRequired(), Length(min=6, max=128)])
    submit = SubmitField('重置密码')


class ScanForm(FlaskForm):
    """录入 / 编辑一次安全扫描。"""
    scan_type = SelectField('扫描类型', choices=[
        ('sast', '源代码扫描'),
        ('sca', '组件扫描'),
        ('container', '容器（镜像）扫描'),
    ], validators=[DataRequired()])

    project_id = SelectField('关联项目', coerce=int, default=0)
    tool = StringField('扫描工具', validators=[Length(max=60)])
    target = StringField('扫描对象', validators=[Length(max=300)])

    status = SelectField('执行状态', choices=[
        ('completed', '已完成'),
        ('running', '执行中'),
        ('pending', '待执行'),
        ('failed', '执行失败'),
    ], validators=[DataRequired()])

    started_at = QuickDateField('开始时间', format='%Y-%m-%d')
    finished_at = QuickDateField('结束时间', format='%Y-%m-%d')

    findings_text = TextAreaField('发现明细（每行一条，可留空）',
                                  validators=[Length(max=60000)])
    note = TextAreaField('备注', validators=[Length(max=2000)])
    submit = SubmitField('保存')


class ProjectForm(FlaskForm):
    name = StringField('项目名称', validators=[DataRequired(), Length(max=100)])
    project_type = SelectField('项目类型', choices=[
        ('embedded', '嵌入式'),
        ('web', 'Web应用'),
        ('mobile', '移动应用'),
        ('backend', '后台服务'),
        ('other', '其他')
    ], validators=[DataRequired()])
    department = StringField('所属部门', validators=[Length(max=50)])
    environment = SelectField('运行环境', choices=[
        ('development', '开发环境'),
        ('testing', '测试环境'),
        ('production', '生产环境')
    ], validators=[DataRequired()])
    criticality = SelectField('重要等级', choices=[
        ('普通', '普通'),
        ('重要', '重要'),
        ('核心', '核心')
    ], validators=[DataRequired()])
    description = StringField('项目描述')
    submit = SubmitField('提交')


class TaskForm(FlaskForm):
    name = StringField('任务名称', validators=[DataRequired(), Length(max=100)])
    test_type = SelectField('测试类型', choices=[
        ('penetration_test', '渗透测试'),
        ('compliance_test', '合规测试'),
        ('security_scan', '安全扫描')
    ], validators=[DataRequired()])
    project_id = SelectField('关联项目', coerce=lambda value: int(value) if value else None)
    assets = TextAreaField('提测资产', validators=[DataRequired()])
    expected_release_date = DateField('预计上线时间', format='%Y-%m-%d')
    manual_test_start = DateField('人工测试开始', format='%Y-%m-%d')
    manual_test_end = DateField('人工测试结束', format='%Y-%m-%d')
    submit = SubmitField('创建任务')


class QuickTaskForm(FlaskForm):
    """测试控制页右侧面板的快捷建任务表单(可关联需求控制迭代)。"""
    iteration_id = SelectField('关联需求迭代', coerce=lambda value: int(value) if value else None)
    test_type = SelectField('测试类型', choices=[
        ('penetration_test', '渗透测试'),
        ('compliance_test', '合规测试'),
        ('security_scan', '安全扫描')
    ], validators=[DataRequired('请选择测试类型')])
    name = StringField('任务名称（选填，留空自动生成）', validators=[Length(max=100)])
    start_date = QuickDateField('计划开始', format='%Y-%m-%d')
    end_date = QuickDateField('计划结束', format='%Y-%m-%d')
    submit = SubmitField('创建任务')


class IterationForm(FlaskForm):
    name = StringField('迭代名称', validators=[DataRequired(), Length(max=100)])
    system_version = SelectField('系统版本', choices=[
        ('V5.0', 'V5.0'),
        ('V4.0', 'V4.0')
    ], validators=[DataRequired()])
    start_date = DateField('开始日期', format='%Y-%m-%d', validators=[DataRequired()])
    end_date = DateField('结束日期', format='%Y-%m-%d', validators=[DataRequired()])
    status = SelectField('迭代状态', choices=[
        ('planned', '待规划'),
        ('in_progress', '进行中'),
        ('completed', '已完成')
    ], validators=[DataRequired()])
    description = TextAreaField('迭代描述', validators=[DataRequired()])
    is_mobile = BooleanField('是否是移动App项目')
    is_new_system = BooleanField('是否是新立项的信息系统')
    has_recent_test = BooleanField('近12个月内是否开展过整体安全测试', default=True)
    target_type = SelectField('评估对象', choices=[
        ('system', '系统'),
        ('application', '应用')
    ], validators=[DataRequired()])
    has_release = BooleanField('是否涉及大版本的发布')
    submit = SubmitField('保存')


class AssessmentForm(FlaskForm):
    project_id = SelectField('评估项目', coerce=int, validators=[DataRequired()])
    importance = SelectField('软件服务重要性', choices=[
        ('一般', '一般（100万以内）'),
        ('中型', '中型（100-1000万）'),
        ('大型', '大型（>1000万）')
    ], validators=[DataRequired()])
    is_new_system = BooleanField('是否是新立项的信息系统')
    requires_test = BooleanField('是否需要安全测试')
    submit = SubmitField('保存问卷')