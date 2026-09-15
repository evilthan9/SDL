"""pytest 公共夹具。

关键点:``create_app()`` 内部会自己跑迁移和 ``db.create_all()``,所以临时库的 URI
必须在**调用 create_app() 之前**就改掉,否则会连到真实的 ``instance/sdl.db``,
测试就会往生产库写数据。
"""
import os
import sys

import pytest
from werkzeug.security import generate_password_hash

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from app import db as _db
from app.config import Config as AppConfig
from app.models import Project, Scan, ScanFinding, Task, TestCase, User, Vulnerability

PASSWORD = 'test-pass-123'


def _make_user(username, role):
    return User(
        username=username,
        email=f'{username}@test.local',
        password_hash=generate_password_hash(PASSWORD),
        role=role,
    )


@pytest.fixture
def app(tmp_path, monkeypatch):
    """每个测试一个独立的临时 SQLite 库。

    默认关掉 CSRF 便于写功能测试;CSRF 本身的行为由 test_csrf.py 单独开启验证。
    """
    db_path = tmp_path / 'test.db'
    monkeypatch.setattr(AppConfig, 'SQLALCHEMY_DATABASE_URI', f'sqlite:///{db_path.as_posix()}')
    monkeypatch.setattr(AppConfig, 'WTF_CSRF_ENABLED', False, raising=False)
    # 上传目录也要指向临时目录：否则测试上传的图片会真的写进仓库的
    # instance/uploads/vulns，跑几轮就积一堆。
    monkeypatch.setattr(AppConfig, 'UPLOAD_DIR', str(tmp_path / 'uploads'), raising=False)

    application = create_app()
    application.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    yield application

    with application.app_context():
        _db.session.remove()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def seed(app):
    """一套覆盖全部 6 个角色与 5 种漏洞状态的固定数据。

    返回一个简单的命名空间,方便测试里直接取 id。
    """
    with app.app_context():
        users = {
            'admin': _make_user('admin', 'admin'),
            'lead': _make_user('lead', 'test_lead'),
            'tester': _make_user('tester', 'tester'),
            'tester2': _make_user('tester2', 'tester'),
            'dev': _make_user('dev', 'developer'),
            'dev2': _make_user('dev2', 'developer'),
            'biz': _make_user('biz', 'business'),
            'guest': _make_user('guest', 'guest'),
        }
        _db.session.add_all(users.values())
        _db.session.flush()

        project = Project(name='演示项目', owner_id=users['biz'].id,
                          criticality='核心', status='active')
        other_project = Project(name='他人项目', owner_id=users['dev'].id,
                                criticality='普通', status='active')
        _db.session.add_all([project, other_project])
        _db.session.flush()

        task = Task(name='演示任务', project_id=project.id, test_type='penetration_test',
                    creator_id=users['lead'].id, tester_id=users['tester'].id,
                    status='in_progress', submission_status='submitted')
        _db.session.add(task)
        _db.session.flush()

        # 状态设为 fail:只有不通过的用例才能进入"新增漏洞"发布页,
        # 这样该页面才可能被渲染测试覆盖到
        test_case = TestCase(task_id=task.id, case_number=1, name='SQL注入 (SQL Injection)',
                             status='fail', version='1.0', vulnerability_count=0)
        _db.session.add(test_case)
        _db.session.flush()

        # 五种状态各一条。created=admin, assignee 视场景而定
        # 标题用真实中文,不要拿状态枚举当名字 —— 否则页面上会出现
        # false_positive 这种裸枚举值,分不清是数据还是 UI 泄漏
        titles = {
            'pending': '接口存在 SQL 注入',
            'fixed': '订单页反射型 XSS',
            'closed': '越权查看他人订单',
            'false_positive': '缓存导致的假阳性（已判定误报）',
            'ignored': '低危信息泄露（已接受风险）',
        }
        vulns = {}
        for index, status in enumerate(('pending', 'fixed', 'closed',
                                        'false_positive', 'ignored'), start=1):
            vuln = Vulnerability(
                vuln_code=f'VUL-TEST-{index:03d}',
                title=titles[status],
                description='测试用漏洞',
                project_id=project.id,
                task_id=task.id,
                source='manual',
                severity='中危',
                status=status,
                creator_id=users['tester'].id,
                assignee_id=users['dev'].id,
            )
            _db.session.add(vuln)
            vulns[status] = vuln
        _db.session.flush()

        # 一条源代码扫描 + 两条发现。创建人是 tester 而不是 dev,
        # 用来验证"开发人员只看自己参与的项目"这条范围规则。
        scan = Scan(
            scan_code='SCAN-TEST-0001', scan_type='sast',
            project_id=project.id, creator_id=users['tester'].id,
            tool='SonarQube', target='git@example.com:demo/backend.git',
            status='completed', total_findings=2,
            critical_count=1, high_count=1, medium_count=0, low_count=0,
        )
        _db.session.add(scan)
        _db.session.flush()
        findings = [
            ScanFinding(scan_id=scan.id, severity='严重', rule_id='CWE-89',
                        title='用户中心接口 SQL 注入', location='src/user/dao.py:88',
                        status='open'),
            ScanFinding(scan_id=scan.id, severity='高危', rule_id='CWE-79',
                        title='订单备注未转义', location='templates/order.html:42',
                        status='open'),
        ]
        _db.session.add_all(findings)
        _db.session.flush()

        ids = {name: user.id for name, user in users.items()}
        result = type('Seed', (), {
            'user_ids': ids,
            'project_id': project.id,
            'other_project_id': other_project.id,
            'task_id': task.id,
            'case_id': test_case.id,
            'scan_id': scan.id,
            'finding_ids': [f.id for f in findings],
            'vuln_ids': {status: vuln.id for status, vuln in vulns.items()},
        })
        _db.session.commit()
        return result


def login(client, user_id):
    """直接把用户塞进 session,跳过登录表单。

    Flask-Login 0.6 从 session 里读的 key 是 ``_user_id``,且要求是字符串。
    """
    with client.session_transaction() as sess:
        sess['_user_id'] = str(user_id)
        sess['_fresh'] = True


@pytest.fixture
def as_user(client):
    """用法:``as_user(seed.user_ids['dev'])`` 之后再发请求。"""

    def _login(user_id):
        login(client, user_id)
        return client

    return _login


@pytest.fixture
def make_csrf_app(tmp_path, monkeypatch):
    """需要验证 CSRF 时用它建一个开启校验的应用。"""

    def _build():
        db_path = tmp_path / 'csrf.db'
        monkeypatch.setattr(AppConfig, 'SQLALCHEMY_DATABASE_URI', f'sqlite:///{db_path.as_posix()}')
        monkeypatch.setattr(AppConfig, 'WTF_CSRF_ENABLED', True, raising=False)
        application = create_app()
        application.config.update(TESTING=True, WTF_CSRF_ENABLED=True)
        return application

    return _build
