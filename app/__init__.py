import json

from flask import Flask, flash, redirect, render_template, request, url_for
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFError, CSRFProtect, generate_csrf

from app.config import Config

db = SQLAlchemy()
csrf = CSRFProtect()
login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.login_message = '请先登录后访问此页面'


@login_manager.user_loader
def load_user(user_id):
    from app.models import User
    return User.query.get(int(user_id))


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    login_manager.init_app(app)
    # 对所有 POST/PUT/PATCH/DELETE 校验 CSRF token。
    # 手写表单用 {{ csrf_token() }},FlaskForm 用 form.hidden_tag() —— 两者写的是
    # 同一个字段名,校验逻辑也同一套,不会冲突。
    csrf.init_app(app)

    # 模板过滤器：把 JSON 文本字段（如 screenshots）还原成列表
    @app.template_filter('from_json')
    def from_json_filter(value):
        if not value:
            return []
        return json.loads(value)

    # csrf_token() 原本只由 CSRFProtect.init_app 注册。这里提前注册同一个函数,
    # 好让模板可以先写 token（阶段性地无害,校验开关稍后统一打开）。
    app.jinja_env.globals['csrf_token'] = generate_csrf

    # 状态机相关的模板辅助。原先每个模板各写一份中文映射
    # （detail/edit/management/task_workflow 四处),改一处漏三处。
    from app.state_machine import (
        STATUS_BADGE_CLASSES, STATUS_LABELS, available_actions, status_label,
        verification_action_class, verification_action_label,
    )
    app.jinja_env.globals.update(
        STATUS_LABELS=STATUS_LABELS,
        status_label=status_label,
        STATUS_BADGE_CLASSES=STATUS_BADGE_CLASSES,
        available_actions=available_actions,
        verification_action_label=verification_action_label,
        verification_action_class=verification_action_class,
    )

    # 枚举 → 中文标签 / 徽章配色的统一取用点。
    # 此前这些映射以字面量散落在 11 处模板里,「任务状态」还被独立写了 3 遍
    # 且译法互不一致。模板只调函数,不再写 if/elif 链或内联字典。
    from app import labels
    app.jinja_env.globals.update(
        # 字典本身也暴露出去 —— 筛选下拉要遍历它们生成选项
        TASK_STATUS_LABELS=labels.TASK_STATUS_LABELS,
        TEST_TYPE_LABELS=labels.TASK_TEST_TYPE_LABELS,
        SEVERITY_LABELS=labels.SEVERITY_LABELS,
        PROJECT_TYPE_LABELS=labels.PROJECT_TYPE_LABELS,
        SCAN_TYPE_LABELS=labels.SCAN_TYPE_LABELS,
        SCAN_TYPE_DESCRIPTIONS=labels.SCAN_TYPE_DESCRIPTIONS,
        SCAN_STATUS_LABELS=labels.SCAN_STATUS_LABELS,
        scan_type_label=labels.scan_type_label,
        scan_type_class=labels.scan_type_class,
        scan_status_label=labels.scan_status_label,
        scan_status_class=labels.scan_status_class,
        finding_status_label=labels.finding_status_label,
        finding_status_class=labels.finding_status_class,
        severity_label=labels.severity_label,
        severity_class=labels.severity_class,
        task_status_label=labels.task_status_label,
        task_status_class=labels.task_status_class,
        test_type_label=labels.test_type_label,
        project_type_label=labels.project_type_label,
        criticality_label=labels.criticality_label,
        criticality_class=labels.criticality_class,
        environment_label=labels.environment_label,
        source_label=labels.source_label,
        vuln_type_label=labels.vuln_type_label,
        role_label=labels.role_label,
    )

    # 模板里也要判权限（如"改派修复人"下拉只给有权的角色看）。
    # 用 PERM.* 常量而不是在模板里写 'vuln.assign' 这种魔法字符串。
    from types import SimpleNamespace

    from app import permissions as perms
    app.jinja_env.globals['has_perm'] = perms.has_perm
    app.jinja_env.globals['is_admin'] = perms.is_admin
    # 列表页要用它判断"这一行给不给查看链接" —— 与详情页的服务端判断同源,
    # 避免出现"列表里有链接、点进去 403"的死链。
    app.jinja_env.globals['can_view_vulnerability'] = perms.can_view_vulnerability
    app.jinja_env.globals['can_view_scan'] = perms.can_view_scan
    # 导航栏按这两个判断决定"业务端/测试端"显不显示
    app.jinja_env.globals['can_access_business'] = perms.can_access_business
    app.jinja_env.globals['can_access_testing'] = perms.can_access_testing
    # 15 个权限点全部暴露给模板,键名去掉 PERM_ 前缀。
    # 模板里写 `has_perm(current_user, PERM.PROJECT_CREATE)` 而不是硬编码角色 ——
    # 硬编码会渲染出"点了就 403"的死按钮。
    app.jinja_env.globals['PERM'] = SimpleNamespace(**{
        name[len('PERM_'):]: getattr(perms, name)
        for name in dir(perms)
        if name.startswith('PERM_') and name.isupper()
    })

    @app.context_processor
    def inject_shared_context():
        """各页面都要用的少量只读数据。"""
        from datetime import datetime

        from app.forms import VULN_TYPE_CHOICES
        from app.state_machine import ALL_STATUSES, TERMINAL_STATUSES
        return {
            # 用于在列表里标记逾期
            'now': datetime.utcnow(),
            'open_statuses': [s for s in ALL_STATUSES if s not in TERMINAL_STATUSES],
            'vuln_type_labels': dict(VULN_TYPE_CHOICES),
        }

    from app.routes import audit, auth, main, projects, scans, vulnerabilities
    app.register_blueprint(auth.bp)
    app.register_blueprint(main.bp)
    app.register_blueprint(vulnerabilities.bp)
    app.register_blueprint(projects.bp)
    app.register_blueprint(audit.bp)
    app.register_blueprint(scans.bp)

    _register_error_handlers(app)
    _warn_missing_optional_dependencies(app)

    from app.migrations import run_migrations
    with app.app_context():
        run_migrations()
        db.create_all()

    return app


def _warn_missing_optional_dependencies(app):
    """启动时检查可选依赖。

    WTForms 的 ``Email()`` 校验器对 ``email_validator`` 是**延迟导入**:
    缺了不会在启动时报错,而是在用户点"注册"提交时抛异常,表现为一个
    信息量为零的 500。与其等它在运行时炸,不如启动时就把话说清楚 ——
    尤其是用系统 Python 而不是 venv 启动的时候（那种情况下很容易踩到）。
    """
    try:
        import email_validator  # noqa: F401
    except ImportError:
        app.logger.warning(
            '未安装 email_validator：注册页提交会直接 500。'
            '请用 venv 启动，或执行 pip install -r requirements.txt'
        )


def _register_error_handlers(app):
    """给 403/404/500 配上统一版式的页面。

    权限收口后 403 会明显变多,裸的 Werkzeug 错误页既不好看、
    也看不出"为什么被拒"。
    """

    def _render(code, heading, description):
        return render_template(
            'errors/error.html',
            code=code,
            heading=heading,
            description=description,
            back_url=request.referrer or url_for('auth.login'),
        ), code

    @app.errorhandler(403)
    def forbidden(_error):
        return _render(403, '没有访问权限',
                       '当前账号的角色不足以查看该内容。如需访问，请联系管理员调整权限。')

    @app.errorhandler(404)
    def not_found(_error):
        return _render(404, '页面或数据不存在',
                       '请求的资源不存在，或已被删除。')

    @app.errorhandler(500)
    def server_error(_error):
        return _render(500, '服务器内部错误',
                       '处理请求时出现异常，请稍后重试或联系管理员。')

    @app.errorhandler(CSRFError)
    def csrf_error(error):
        """CSRF 校验失败:记日志 + 友好提示。

        保留 400 状态码 —— 语义正确,也让"哪个表单漏了 token"能被测试直接断言出来。
        这条日志则是人工排查时的雷达:endpoint 直接指出位置。

        图片上传端点走的是 fetch 且期望 JSON,不能返回 HTML 页面,否则前端解析失败。
        """
        app.logger.warning('CSRF 校验失败 endpoint=%s referer=%s reason=%s',
                           request.endpoint, request.referrer, error.description)
        if request.endpoint == 'vulnerabilities.upload_image':
            from flask import jsonify
            return jsonify(ok=False, error='安全校验失败，请刷新页面后重试'), 400
        return _render(400, '安全校验未通过',
                       '页面可能已过期，请刷新后重试；若反复出现请联系管理员。')
