"""审计日志查询。

改造前 ``audit_logs`` 表有数据,但全站**没有任何页面能查看** ——
"数据审计追溯"这条要求只落地了一半(写进去了,读不出来)。
"""
from datetime import datetime, timedelta

from flask import Blueprint, render_template, request
from flask_login import login_required
from sqlalchemy import or_
from sqlalchemy.orm import joinedload

from app.models import AuditLog, User
from app.permissions import PERM_AUDIT_VIEW, require_perm

bp = Blueprint('audit', __name__, url_prefix='/audit')

PER_PAGE = 30

#: 动作 -> 中文名。用于筛选下拉和列表展示。
ACTION_LABELS = {
    'create': '创建漏洞',
    'edit': '编辑漏洞',
    'delete': '删除漏洞',
    'restore': '恢复漏洞',
    'reassign': '改派修复人',
    'view_denied': '越权访问被拒',
    'fix': '提交修复',
    'verify_pass': '复测通过',
    'verify_fail': '复测不通过',
    'reopen': '重新打开',
    'mark_false_positive': '判定误报',
    'mark_ignored': '风险接受',
    'push_task': '推送测试任务',
    'push_iteration': '推送迭代',
    'delete_iteration': '删除迭代',
    'create_iteration': '创建迭代',
    'edit_project': '编辑项目',
    'archive_project': '归档项目',
    'restore_project': '恢复项目',
    'delete_project': '删除项目',
    'create_task': '创建测试任务',
    'task_assign': '分配测试任务',
    'task_start': '开始测试',
    'task_review': '审核测试结果',
    'retest_complete': '复测完成归档',
    'case_update': '变更用例状态',
    'case_create': '新增测试用例',
    'case_edit': '编辑测试用例',
    'case_delete': '删除测试用例',
    'export': '导出数据',
    'user_role_change': '调整用户角色',
    'user_delete': '删除用户',
    'user_password_change': '修改密码',
    'user_password_reset': '重置密码',
    'user_profile_update': '更新个人资料',
}

#: 资源类型 -> 中文名
RESOURCE_LABELS = {
    'vulnerability': '漏洞',
    'task': '测试任务',
    'project': '项目/迭代',
    'user': '用户',
}

#: 筛选下拉里可选的资源类型顺序
RESOURCE_ORDER = ('vulnerability', 'task', 'project', 'user')


def action_label(action):
    return ACTION_LABELS.get(action, action or '未知')


def resource_label(resource_type):
    return RESOURCE_LABELS.get(resource_type, resource_type or '未知')


def _parse_date(value):
    try:
        return datetime.strptime(value, '%Y-%m-%d')
    except (TypeError, ValueError):
        return None


@bp.route('/logs')
@login_required
@require_perm(PERM_AUDIT_VIEW)
def logs():
    """审计日志列表:按操作人 / 资源类型 / 动作 / 时间区间筛选。"""
    operator = request.args.get('operator', '').strip()
    resource_type = request.args.get('resource_type', '').strip()
    action = request.args.get('action', '').strip()
    date_from = request.args.get('date_from', '').strip()
    date_to = request.args.get('date_to', '').strip()

    query = AuditLog.query

    if operator:
        query = query.join(User, AuditLog.operator_id == User.id, isouter=True).filter(
            or_(User.username.ilike(f'%{operator}%'),
                AuditLog.detail.ilike(f'%{operator}%'))
        )
    if resource_type in RESOURCE_LABELS:
        query = query.filter(AuditLog.resource_type == resource_type)
    if action in ACTION_LABELS:
        query = query.filter(AuditLog.action == action)

    start = _parse_date(date_from)
    if start:
        query = query.filter(AuditLog.created_at >= start)
    end = _parse_date(date_to)
    if end:
        # 含当天,所以加一天再取下界
        query = query.filter(AuditLog.created_at < end + timedelta(days=1))

    page = request.args.get('page', 1, type=int)
    pagination = (query.options(joinedload(AuditLog.operator))
                  .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
                  .paginate(page=page, per_page=PER_PAGE, error_out=False))

    return render_template(
        'audit/logs.html',
        pagination=pagination,
        logs=pagination.items,
        filters={
            'operator': operator,
            'resource_type': resource_type,
            'action': action,
            'date_from': date_from,
            'date_to': date_to,
        },
        action_labels=ACTION_LABELS,
        resource_labels=RESOURCE_LABELS,
        resource_order=RESOURCE_ORDER,
        action_label=action_label,
        resource_label=resource_label,
        title='审计日志',
    )
