"""跨蓝图复用的业务逻辑。

risk 评分 / SLA 计算 / 漏洞编号 / 复测历史 / 审计日志 / 安全跳转统一放在这里,
避免 routes 之间互相 import 造成耦合。原文件为空,现作为公共服务层使用。
"""
import json
import secrets
from datetime import datetime, timedelta

from app import db


def calculate_risk_score(severity, project_criticality):
    """根据严重等级和项目重要性计算风险评分。"""
    severity_score = {
        '严重': 9.0,
        '高危': 7.0,
        '中危': 5.0,
        '低危': 3.0
    }.get(severity, 5.0)

    criticality_coefficient = {
        '普通': 1.0,
        '重要': 1.2,
        '核心': 1.5
    }.get(project_criticality, 1.0)

    return round(severity_score * criticality_coefficient, 2)


def calculate_due_date(severity):
    """根据严重等级计算修复截止日期(SLA)。"""
    sla_days = {
        '严重': 7,
        '高危': 14,
        '中危': 30,
        '低危': 60
    }.get(severity, 30)
    return datetime.utcnow() + timedelta(days=sla_days)


def generate_vuln_code():
    """生成漏洞编号。

    原实现只依赖时间戳,`create/create_for_project` 用秒级格式,同秒多条会撞
    `vuln_code` 唯一约束(见 #4)。这里保留可读的秒级时间,再补 6 位随机十六进制
    (24 bit)防同秒碰撞。长度 24 字符,与历史代码 `%Y%m%d%H%M%S%f` 产生的
    24 字符编号一致;`varchar(20)` 在 SQLite 中不强制长度,如需迁移到严格
    DB 应把该列加宽为 varchar(32)。
    """
    ts = datetime.utcnow().strftime('%Y%m%d%H%M%S')
    return f'VUL-{ts}{secrets.token_hex(3)}'


def append_verification_history(vuln, result, comment, operator):
    """向漏洞的 verification_history(JSON 文本)追加一条复测记录。"""
    history = json.loads(vuln.verification_history or '[]')
    history.append({
        'result': result,
        'comment': comment,
        'operator': operator,
        'time': datetime.utcnow().isoformat()
    })
    vuln.verification_history = json.dumps(history, ensure_ascii=False)


def client_ip():
    """取客户端 IP。优先 X-Forwarded-For 的第一段(反代场景),否则 remote_addr。

    原实现里 AuditLog.ip_address 永远为空 —— 各调用点都没传这个参数。
    在这里统一采集,一处改动覆盖全部埋点,不必去改几十个调用点。
    """
    from flask import has_request_context, request
    if not has_request_context():
        return None
    forwarded = request.headers.get('X-Forwarded-For', '')
    if forwarded:
        return forwarded.split(',')[0].strip()[:50]
    return (request.remote_addr or '')[:50] or None


def log_audit(operator_id, resource_type, resource_id, action,
              from_status=None, to_status=None, detail=None, ip_address=None):
    """构造一条审计日志并加入当前 session,由调用方统一 commit。"""
    from app.models import AuditLog
    db.session.add(AuditLog(
        operator_id=operator_id,
        resource_type=resource_type,
        resource_id=resource_id,
        action=action,
        from_status=from_status,
        to_status=to_status,
        detail=detail,
        ip_address=ip_address or client_ip()
    ))


def delete_project_cascade(project):
    """删除项目及其全部关联数据。

    级联顺序:测试用例 -> 漏洞(软删除) -> 测试任务 -> 项目本身。

    漏洞走软删除而不是物理删除 —— 漏洞是审计对象,即使所属项目没了也应留痕,
    回收站里还能看到并恢复。

    调用方负责 ``db.session.commit()``。
    """
    from app.models import TestCase, Task, Vulnerability

    for task in Task.query.filter_by(project_id=project.id).all():
        TestCase.query.filter_by(task_id=task.id).delete(synchronize_session=False)
        Vulnerability.query.filter_by(task_id=task.id).update(
            {'is_deleted': True, 'deleted_at': datetime.utcnow()},
            synchronize_session=False
        )
        db.session.delete(task)

    # 没挂任务、但直接挂项目的漏洞也要一并软删除
    Vulnerability.query.filter_by(project_id=project.id, task_id=None).update(
        {'is_deleted': True, 'deleted_at': datetime.utcnow()},
        synchronize_session=False
    )
    db.session.delete(project)


def safe_next_url(url):
    """仅放行站内相对路径,拦截开放重定向(如 ?next=https://evil.com)。"""
    if url and url.startswith('/') and not url.startswith('//'):
        return url
    return None
