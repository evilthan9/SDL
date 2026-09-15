from app import db
from flask_login import UserMixin
from datetime import datetime

# 用户表
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='developer')  # admin / test_lead / tester / developer / guest
    email = db.Column(db.String(120))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# 项目表
class Project(db.Model):
    __tablename__ = 'projects'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    project_type = db.Column(db.String(50))
    department = db.Column(db.String(50))
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    environment = db.Column(db.String(20))
    criticality = db.Column(db.String(20), default='普通')  # 普通 / 重要 / 核心
    description = db.Column(db.Text)
    status = db.Column(db.String(20), default='active')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    security_test_required = db.Column(db.Boolean, default=False)
    requirements_pushed = db.Column(db.Boolean, default=False)
    questionnaire_completed = db.Column(db.Boolean, default=False)

    owner = db.relationship('User', backref='projects')

# 测试任务表
class Task(db.Model):
    __tablename__ = 'tasks'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), index=True)
    test_type = db.Column(db.String(50))
    creator_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    tester_id = db.Column(db.Integer, db.ForeignKey('users.id'), index=True)
    start_date = db.Column(db.DateTime)
    end_date = db.Column(db.DateTime)
    status = db.Column(db.String(20), default='scheduled')  # scheduled / in_progress / archived
    submission_status = db.Column(db.String(20), default='draft')  # draft / submitted
    assets = db.Column(db.Text)
    expected_release_date = db.Column(db.DateTime)
    manual_test_start = db.Column(db.DateTime)
    manual_test_end = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    project = db.relationship('Project', backref='tasks')
    creator = db.relationship('User', foreign_keys=[creator_id], backref='created_tasks')
    tester = db.relationship('User', foreign_keys=[tester_id], backref='tasks')


class TestCase(db.Model):
    __tablename__ = 'test_cases'
    #: 告诉 pytest 这不是测试类。它的类名正好匹配 pytest 的 test_* 收集规则,
    #: 被 import 进测试文件时会触发 PytestCollectionWarning。
    __test__ = False
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('tasks.id'), nullable=False, index=True)
    case_number = db.Column(db.Integer, nullable=False)
    name = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(20), default='disabled', nullable=False)
    detail = db.Column(db.String(200))
    version = db.Column(db.String(20), default='1.0')
    vulnerability_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    task = db.relationship('Task', backref='test_cases')

# 漏洞表（核心）
class Vulnerability(db.Model):
    __tablename__ = 'vulnerabilities'
    id = db.Column(db.Integer, primary_key=True)
    vuln_code = db.Column(db.String(20), unique=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)

    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), index=True)
    task_id = db.Column(db.Integer, db.ForeignKey('tasks.id'), index=True)
    test_case_id = db.Column(db.Integer, db.ForeignKey('test_cases.id'))  # 来源测试用例(可空)

    vuln_type = db.Column(db.String(30))  # 漏洞类型:sqli/xss/越权/信息泄露…(见 forms.VULN_TYPE_CHOICES)
    screenshots = db.Column(db.Text, default='[]')  # 截图文件名列表(JSON),存于 instance/uploads/vulns
    source = db.Column(db.String(30))  # manual / sast / sca / penetration_test
    severity = db.Column(db.String(20), index=True)  # 严重 / 高危 / 中危 / 低危
    risk_score = db.Column(db.Float)
    # pending / fixed / closed / false_positive / ignored(见 state_machine.VULN_STATUSES)
    status = db.Column(db.String(20), default='pending', index=True)

    creator_id = db.Column(db.Integer, db.ForeignKey('users.id'), index=True)
    assignee_id = db.Column(db.Integer, db.ForeignKey('users.id'), index=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    due_date = db.Column(db.DateTime)  # SLA 截止日期
    fixed_at = db.Column(db.DateTime)
    closed_at = db.Column(db.DateTime)

    verification_result = db.Column(db.String(20))  # pass / fail
    verification_comment = db.Column(db.Text)
    verification_history = db.Column(db.Text, default='[]')  # 存储复测历史

    is_deleted = db.Column(db.Boolean, default=False, index=True)
    deleted_at = db.Column(db.DateTime)

    project = db.relationship('Project', backref='vulnerabilities')
    task = db.relationship('Task', backref='vulnerabilities')
    test_case = db.relationship('TestCase', backref='vulnerabilities')
    creator = db.relationship('User', foreign_keys=[creator_id], backref='created_vulns')
    assignee = db.relationship('User', foreign_keys=[assignee_id], backref='assigned_vulns')

# 安全扫描（SAST / SCA / 容器镜像）
class Scan(db.Model):
    """一次安全扫描记录。

    对应 SDL 里"研发控制"阶段的自动化检测环节。三类扫描共用一张表,
    用 ``scan_type`` 区分 —— 它们的字段结构完全一致（工具、目标、时间、发现数）。

    发现明细在 :class:`ScanFinding`,各等级计数由明细聚合而来（``sync_counts``）。
    """
    __tablename__ = 'scans'
    __test__ = False

    id = db.Column(db.Integer, primary_key=True)
    scan_code = db.Column(db.String(40), unique=True)
    scan_type = db.Column(db.String(20), nullable=False, index=True)  # sast / sca / container

    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), index=True)
    task_id = db.Column(db.Integer, db.ForeignKey('tasks.id'))
    creator_id = db.Column(db.Integer, db.ForeignKey('users.id'), index=True)

    tool = db.Column(db.String(60))          # SonarQube / Trivy / Snyk …
    target = db.Column(db.String(300))       # 代码仓地址 / 依赖清单 / 镜像名:tag
    status = db.Column(db.String(20), default='completed', index=True)
    started_at = db.Column(db.DateTime)
    finished_at = db.Column(db.DateTime)
    note = db.Column(db.Text)

    # 各等级计数,由 ScanFinding 聚合
    total_findings = db.Column(db.Integer, default=0)
    critical_count = db.Column(db.Integer, default=0)
    high_count = db.Column(db.Integer, default=0)
    medium_count = db.Column(db.Integer, default=0)
    low_count = db.Column(db.Integer, default=0)

    is_deleted = db.Column(db.Boolean, default=False, index=True)
    deleted_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    project = db.relationship('Project', backref='scans')
    task = db.relationship('Task', backref='scans')
    creator = db.relationship('User', foreign_keys=[creator_id], backref='scans')


class ScanFinding(db.Model):
    """扫描发现的一条问题。

    与漏洞的关系:发现默认只是"待梳理"的数据,勾选后才通过
    ``扫描详情页 → 转为漏洞`` 生成 :class:`Vulnerability` 记录并回填
    ``vulnerability_id``。这样"检测 → 梳理 → 分派修复 → 复测闭环"接得上,
    又不会把低危噪音一股脑倒给开发。
    """
    __tablename__ = 'scan_findings'
    __test__ = False

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False, index=True)

    rule_id = db.Column(db.String(80))       # CWE-89 / CVE-2021-44228 / 规则编号
    title = db.Column(db.String(200), nullable=False)
    severity = db.Column(db.String(20), index=True)   # 严重/高危/中危/低危
    location = db.Column(db.String(300))     # 文件:行号 / 组件:版本 / 镜像层
    detail = db.Column(db.Text)

    # open 待处理 / converted 已转漏洞 / ignored 已忽略
    status = db.Column(db.String(20), default='open', index=True)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey('vulnerabilities.id'))
    handled_by_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    handled_at = db.Column(db.DateTime)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    scan = db.relationship('Scan', backref=db.backref('findings', lazy='select'))
    vulnerability = db.relationship('Vulnerability', foreign_keys=[vulnerability_id])
    handled_by = db.relationship('User', foreign_keys=[handled_by_id])


# 审计日志表
class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True)
    operator_id = db.Column(db.Integer, db.ForeignKey('users.id'), index=True)
    resource_type = db.Column(db.String(50), index=True)
    resource_id = db.Column(db.Integer)
    action = db.Column(db.String(50))
    from_status = db.Column(db.String(20))
    to_status = db.Column(db.String(20))
    detail = db.Column(db.Text)
    ip_address = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    operator = db.relationship('User', backref='audit_logs')