"""生成脱敏演示数据。

用途:论文/答辩里"用真实漏洞数据(脱敏)验证系统功能完整性与可用性"这一条。
现有 ``instance/sdl.db`` 只有 20 条漏洞、且状态只覆盖 pending/fixed 两态,
误报/忽略两条终止分支一条数据都没有,看板和新状态机演示会很单薄。

**默认写到 ``instance/sdl_demo.db``,不碰正在用的库。** 要写入别的库请显式指定:

    python seed_demo.py                          # -> instance/sdl_demo.db
    python seed_demo.py --db instance/sdl.db     # 覆盖现有库(会先自动备份)
    python seed_demo.py --force                  # 目标已存在时直接覆盖

所有账号的演示密码统一为 ``demo123456``。
运行方式(用它启动服务):

    set SDL_DB=instance/sdl_demo.db && python run.py
"""
import argparse
import os
import random
import shutil
import sys
from datetime import datetime, timedelta

from sqlalchemy import func

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.config import Config as AppConfig

DEMO_PASSWORD = 'demo123456'
RANDOM_SEED = 20260914

#: 各等级 -> (SLA 天数, 风险基数)
SEVERITY_SLA = {'严重': (7, 9.0), '高危': (14, 7.0), '中危': (30, 5.0), '低危': (60, 3.0)}
CRITICALITY_COEF = {'普通': 1.0, '重要': 1.2, '核心': 1.5}

VULN_TITLES = [
    '用户中心接口存在 SQL 注入', '订单查询页反射型 XSS', '越权查看他人订单详情',
    '接口返回未脱敏手机号', '文件上传未校验类型可传脚本', 'URL 重定向未做白名单',
    'SSRF 可探测内网服务', '登录接口可暴力破解', '敏感配置硬编码在客户端',
    'JWT 签名未校验可伪造', '后台管理页面未做访问控制', '短信验证码可重复使用',
    '日志打印包含完整身份证号', 'API 缺少频率限制', '反序列化接口可构造恶意对象',
    'SourceMap 文件未清理导致源码泄露', 'Cookie 未设置 HttpOnly',
    '密码重置流程可绕过校验', '导出接口存在越权', '缓存未隔离导致数据串号',
    '上传接口路径穿越可写任意目录', '支付金额可被前端篡改', '调试接口未下线',
    '第三方组件存在已知高危漏洞', '数据库连接串明文存储',
]

VULN_TYPES = ['sqli', 'xss', 'auth_bypass', 'info_leak', 'csrf', 'ssrf',
              'file_vuln', 'deserialize', 'weak_password', 'logic', 'other']

SOURCES = ['manual', 'sast', 'sca', 'penetration_test', 'security_scan', 'incident']


def _reset_target(db_path, force):
    """决定是否清空目标库。"""
    if os.path.exists(db_path):
        if not force:
            answer = input(f'{db_path} 已存在，继续将清空其中的演示数据。确认？[y/N] ').strip().lower()
            if answer != 'y':
                print('已取消。')
                sys.exit(0)
        # 覆盖前先备份,避免误删手工造的数据
        backup = f'{db_path}.bak-{datetime.now():%Y%m%d-%H%M%S}'
        shutil.copy2(db_path, backup)
        print(f'已备份原库 -> {backup}')
        os.remove(db_path)


def _build_users(db, User):
    from werkzeug.security import generate_password_hash

    password_hash = generate_password_hash(DEMO_PASSWORD)
    specs = [
        ('admin', 'admin', '安全管理员'),
        ('lead01', 'test_lead', '测试主管'),
        ('tester01', 'tester', '安全测试工程师'),
        ('tester02', 'tester', '安全测试工程师'),
        ('dev01', 'developer', '开发工程师'),
        ('dev02', 'developer', '开发工程师'),
        ('dev03', 'developer', '开发工程师'),
        ('biz01', 'business', '业务负责人'),
        ('biz02', 'business', '业务负责人'),
        ('guest01', 'guest', '访客'),
    ]
    users = {}
    for index, (username, role, _title) in enumerate(specs):
        user = User(
            username=username,
            email=f'{username}@demo.local',
            password_hash=password_hash,
            role=role,
            created_at=datetime.utcnow() - timedelta(days=180 - index),
        )
        db.session.add(user)
        users[username] = user
    db.session.flush()
    return users


def _build_projects(db, Project, Task, users):
    specs = [
        ('车载网关固件 V3.2', 'embedded', '智能网联部', '核心', 'biz01', 'production'),
        ('车主 App 安卓端 V5.1', 'mobile', '用户运营部', '重要', 'biz01', 'production'),
        ('售后诊断云平台 V1.4', 'web', '售后服务部', '重要', 'biz02', 'testing'),
        ('内部运维后台 V2.0', 'backend', '基础架构部', '普通', 'biz02', 'development'),
        ('车联网数据中台 V1.0', 'backend', '数据平台部', '核心', 'biz01', 'testing'),
    ]
    projects, tasks = [], []
    for index, (name, ptype, dept, criticality, owner, env) in enumerate(specs):
        project = Project(
            name=name,
            project_type=ptype,
            department=dept,
            owner_id=users[owner].id,
            environment=env,
            criticality=criticality,
            description=f'{dept}负责的{name}，本期完成安全测试与整改。',
            status='active',
            security_test_required=True,
            requirements_pushed=True,
            questionnaire_completed=True,
            created_at=datetime.utcnow() - timedelta(days=90 - index * 10),
        )
        db.session.add(project)
        db.session.flush()
        projects.append(project)

        status = ['archived', 'retest', 'in_progress', 'assigned', 'scheduled'][index]
        task = Task(
            name=f'{name} - 安全测试',
            project_id=project.id,
            test_type=['penetration_test', 'compliance_test', 'security_scan'][index % 3],
            creator_id=users['lead01'].id,
            tester_id=users['tester01' if index % 2 == 0 else 'tester02'].id,
            status=status,
            submission_status='submitted',
            start_date=datetime.utcnow() - timedelta(days=60 - index * 8),
            end_date=datetime.utcnow() - timedelta(days=30 - index * 5),
            assets=f'https://{ptype}.demo.local\n10.20.{index}.0/24',
            created_at=datetime.utcnow() - timedelta(days=88 - index * 10),
        )
        db.session.add(task)
        db.session.flush()
        tasks.append(task)
    return projects, tasks


def _build_vulnerabilities(db, Vulnerability, users, projects, tasks, count=64):
    """按最近 12 周铺开,覆盖全部 5 种状态与 4 个等级。"""
    rng = random.Random(RANDOM_SEED)
    developers = [users['dev01'], users['dev02'], users['dev03']]
    testers = [users['tester01'], users['tester02']]
    now = datetime.utcnow()

    #: 状态配比,保证五个状态都有可观数量
    status_pool = (['pending'] * 9 + ['fixed'] * 4 + ['closed'] * 8
                   + ['false_positive'] * 2 + ['ignored'] * 1)
    severity_pool = ['严重'] * 2 + ['高危'] * 5 + ['中危'] * 8 + ['低危'] * 5

    created = []
    for index in range(count):
        project = projects[index % len(projects)]
        task = tasks[index % len(tasks)]
        tester = testers[index % len(testers)]
        severity = rng.choice(severity_pool)
        status = rng.choice(status_pool)

        # 创建时间铺满最近 12 周
        days_ago = rng.randint(0, 83)
        created_at = now - timedelta(days=days_ago, hours=rng.randint(0, 23))
        sla_days = SEVERITY_SLA[severity][0]
        due_date = created_at + timedelta(days=sla_days)

        vuln = Vulnerability(
            vuln_code=f'VUL-DEMO-{index + 1:04d}',
            title=VULN_TITLES[index % len(VULN_TITLES)],
            description=(
                f'<p>在对「{project.name}」开展安全测试时发现该问题。</p>'
                f'<p>测试人员通过构造异常请求，可在未授权的情况下复现该缺陷。</p>'
                f'<p>建议按修复方案整改后提交复测。</p>'
            ),
            vuln_type=VULN_TYPES[index % len(VULN_TYPES)],
            source=rng.choice(SOURCES),
            severity=severity,
            risk_score=round(SEVERITY_SLA[severity][1] * CRITICALITY_COEF[project.criticality], 2),
            status=status,
            project_id=project.id,
            task_id=task.id,
            creator_id=tester.id,
            assignee_id=developers[index % len(developers)].id,
            created_at=created_at,
            updated_at=created_at,
            due_date=due_date,
        )

        # 让 closed 的漏洞有闭环时间,并让一部分 pending 变成"逾期"
        if status in ('closed', 'false_positive', 'ignored'):
            fixed_at = created_at + timedelta(days=rng.randint(1, max(2, sla_days)))
            vuln.fixed_at = fixed_at
            vuln.closed_at = fixed_at + timedelta(days=rng.randint(1, 5))
            vuln.verification_result = 'pass' if status == 'closed' else None
            vuln.verification_comment = '复测通过，问题已闭环' if status == 'closed' else None
        elif status == 'fixed':
            vuln.fixed_at = created_at + timedelta(days=rng.randint(1, max(2, sla_days)))

        db.session.add(vuln)
        created.append(vuln)
    db.session.flush()
    return created


def _build_scans(db, Scan, ScanFinding, users, projects, tasks):
    """三类扫描各造几条记录，发现明细覆盖各等级与各种处置状态。"""
    rng = random.Random(RANDOM_SEED + 2)
    testers = [users['tester01'], users['tester02']]

    templates = {
        'sast': (
            [('SonarQube', 'git@demo.corp:{p}/backend.git'),
             ('Fortify SCA', 'git@demo.corp:{p}/firmware.git'),
             ('Semgrep', 'git@demo.corp:{p}/mobile-app.git')],
            [('严重', 'CWE-89', '用户中心接口 SQL 注入', 'src/user/dao.py:88'),
             ('高危', 'CWE-79', '订单备注未转义导致存储型 XSS', 'templates/order.html:42'),
             ('高危', 'CWE-798', '配置文件里硬编码数据库口令', 'config/db.py:17'),
             ('中危', 'CWE-200', '错误页返回堆栈信息', 'app/handlers.py:63'),
             ('低危', 'CWE-477', '使用了已废弃的加密算法', 'utils/crypto.py:25')],
        ),
        'sca': (
            [('Trivy', 'requirements.txt'), ('Snyk', 'package-lock.json'),
             ('OWASP Dependency-Check', 'pom.xml')],
            [('严重', 'CVE-2021-44228', 'log4j-core 2.14.1 存在远程代码执行', 'org.apache.logging.log4j:log4j-core:2.14.1'),
             ('高危', 'CVE-2022-22965', 'Spring Framework 参数绑定漏洞', 'org.springframework:spring-beans:5.3.17'),
             ('中危', 'CVE-2023-32681', 'requests 未校验代理环境变量', 'requests:2.28.0'),
             ('低危', 'CVE-2023-45803', 'urllib3 请求体泄漏风险', 'urllib3:1.26.15')],
        ),
        'container': (
            [('Trivy', 'registry.demo.corp/{p}/gateway:3.2.1'),
             ('Clair', 'registry.demo.corp/{p}/web:1.4.0'),
             ('Anchore', 'registry.demo.corp/{p}/worker:latest')],
            [('严重', 'CVE-2023-4911', 'glibc 本地提权漏洞（Looney Tunables）', 'layer: base/debian:11'),
             ('高危', 'CVE-2024-21626', 'runc 容器逃逸漏洞', 'layer: usr/bin/runc'),
             ('中危', 'CVE-2023-5678', 'openssl 拒绝服务', 'layer: usr/lib/libssl.so'),
             ('低危', 'CIS-4.1', '镜像以 root 用户运行', 'layer: Dockerfile')],
        ),
    }

    scans = []
    for index, project in enumerate(projects):
        for scan_type, (tools, findings_pool) in templates.items():
            # 每个项目只做其中两类扫描，让数据不那么整齐
            if (index + list(templates).index(scan_type)) % 3 == 2:
                continue
            tool, target_tpl = tools[index % len(tools)]
            created_at = datetime.utcnow() - timedelta(days=rng.randint(1, 40))
            scan = Scan(
                scan_code=f'SCAN-DEMO-{len(scans) + 1:04d}',
                scan_type=scan_type,
                project_id=project.id,
                creator_id=testers[index % len(testers)].id,
                tool=tool,
                target=target_tpl.format(p=project.name.split()[0].lower()),
                status='completed',
                started_at=created_at,
                finished_at=created_at + timedelta(hours=rng.randint(1, 6)),
                note='由 CI 流水线定时触发。',
                created_at=created_at,
            )
            db.session.add(scan)
            db.session.flush()

            picked = rng.sample(findings_pool, k=rng.randint(2, len(findings_pool)))
            for severity, rule_id, title, location in picked:
                db.session.add(ScanFinding(
                    scan_id=scan.id, severity=severity, rule_id=rule_id,
                    title=title, location=location, status='open',
                ))
            db.session.flush()

            # 重算计数
            rows = (db.session.query(ScanFinding.severity, func.count(ScanFinding.id))
                    .filter(ScanFinding.scan_id == scan.id)
                    .group_by(ScanFinding.severity).all())
            counts = dict(rows)
            scan.critical_count = counts.get('严重', 0)
            scan.high_count = counts.get('高危', 0)
            scan.medium_count = counts.get('中危', 0)
            scan.low_count = counts.get('低危', 0)
            scan.total_findings = sum(counts.values())
            scans.append(scan)
    return scans


def _build_audit_logs(db, AuditLog, users, vulns):
    rng = random.Random(RANDOM_SEED + 1)
    operators = [users['admin'], users['lead01'], users['tester01'],
                 users['tester02'], users['dev01'], users['dev02']]
    for vuln in vulns:
        rows = [('create', None, 'pending', vuln.created_at)]
        if vuln.status in ('fixed', 'closed'):
            rows.append(('fix', 'pending', 'fixed', vuln.fixed_at or vuln.created_at))
        if vuln.status == 'closed':
            rows.append(('verify_pass', 'fixed', 'closed', vuln.closed_at or vuln.created_at))
        elif vuln.status == 'false_positive':
            rows.append(('mark_false_positive', 'pending', 'false_positive', vuln.created_at))
        elif vuln.status == 'ignored':
            rows.append(('mark_ignored', 'pending', 'ignored', vuln.created_at))

        for action, from_status, to_status, moment in rows:
            operator = rng.choice(operators)
            db.session.add(AuditLog(
                operator_id=operator.id,
                resource_type='vulnerability',
                resource_id=vuln.id,
                action=action,
                from_status=from_status,
                to_status=to_status,
                detail=f'状态转换：{from_status or "—"} → {to_status}'
                       if action != 'create' else f'创建漏洞：{vuln.title}',
                ip_address=f'10.20.{rng.randint(1, 30)}.{rng.randint(2, 250)}',
                created_at=moment,
            ))


def main():
    parser = argparse.ArgumentParser(description='生成脱敏演示数据')
    parser.add_argument('--db', default=os.path.join('instance', 'sdl_demo.db'),
                        help='目标数据库路径（默认 instance/sdl_demo.db）')
    parser.add_argument('--force', action='store_true',
                        help='目标已存在时不再询问，直接覆盖（仍会自动备份）')
    parser.add_argument('--count', type=int, default=64, help='生成的漏洞条数')
    args = parser.parse_args()

    db_path = os.path.abspath(args.db)
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    _reset_target(db_path, args.force)

    # 必须在 create_app() 之前指定目标库 —— 它内部会跑迁移和 create_all。
    #
    # 这里要同时设环境变量**和**类属性:Config.SQLALCHEMY_DATABASE_URI 是模块导入时
    # 就求值的,而 `from app.config import Config` 在文件顶部已经执行过了,光设
    # 环境变量不会生效 —— 脚本会悄悄连到默认的 instance/sdl.db 上。
    os.environ['SDL_DB'] = db_path
    AppConfig.DB_PATH = db_path
    AppConfig.SQLALCHEMY_DATABASE_URI = f'sqlite:///{db_path.replace(os.sep, "/")}'

    from app import create_app, db
    from app.models import (AuditLog, Project, Scan, ScanFinding, Task, User,
                        Vulnerability)

    app = create_app()

    # 自检:确认真的连到了指定库。URI 是导入时求值的,一旦这里对不上,
    # 脚本会往默认库(instance/sdl.db)里写演示数据。
    actual_db = os.path.abspath(app.config['DB_PATH'])
    if actual_db != db_path:
        sys.exit(f'[中止] 目标库未生效：期望 {db_path}，实际 {actual_db}')

    with app.app_context():
        users = _build_users(db, User)
        projects, tasks = _build_projects(db, Project, Task, users)
        vulns = _build_vulnerabilities(db, Vulnerability, users, projects, tasks, args.count)
        scans = _build_scans(db, Scan, ScanFinding, users, projects, tasks)
        _build_audit_logs(db, AuditLog, users, vulns)
        db.session.commit()

        counts = {status: sum(1 for v in vulns if v.status == status)
                  for status in ('pending', 'fixed', 'closed', 'false_positive', 'ignored')}

    print(f'\n演示数据已生成 -> {db_path}')
    print(f'  用户 {len(users)} 个 / 项目 {len(projects)} 个 / 任务 {len(tasks)} 个 / 漏洞 {len(vulns)} 条')
    print(f'  状态分布: ' + '，'.join(f'{k} {v}' for k, v in counts.items()))
    print(f'\n  登录账号（密码统一 {DEMO_PASSWORD}）:')
    print('    admin / lead01     —— 管理员、测试主管（可看统计看板与审计日志）')
    print('    tester01 / tester02—— 测试人员（漏洞录入、状态流转、复测）')
    print('    dev01 / dev02/dev03—— 开发人员（提交修复）')
    print('    biz01 / biz02      —— 业务人员')
    print('    guest01            —— 访客（仅已闭环漏洞）')
    relative = os.path.relpath(db_path).replace(os.sep, '/')
    print(f'\n  用该库启动服务:')
    print(f'    set SDL_DB={relative} && python run.py        (Windows)')
    print(f'    SDL_DB={relative} python run.py               (macOS / Linux)')


if __name__ == '__main__':
    main()
