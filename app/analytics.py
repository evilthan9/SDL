"""统计看板的数据聚合。

原实现把聚合逻辑全堆在 ``main.index`` 里,而且:

- 只统计严重/高危/中危三档,**低危被丢掉了**;
- 柱状图拿"漏洞总数"当分母,导致所有柱子都很矮;
- 只有管理员能看(``abort(403)``),与"多角色"的要求不符。

这里把所有维度收进一个函数,视图只负责取数 + 渲染。
"""
from datetime import datetime, timedelta

from app.models import Vulnerability
from app.forms import VULN_TYPE_CHOICES
from app.permissions import SCOPE_LABELS, apply_vuln_scope
from app.state_machine import ALL_STATUSES, STATUS_LABELS, TERMINAL_STATUSES

#: 趋势图回看的周数
TREND_WEEKS = 12
#: 项目分布图最多显示几个项目
TOP_PROJECTS = 8

_SEVERITY_ORDER = ('严重', '高危', '中危', '低危')

#: 未填写漏洞类型时的展示名（不能直接用英文占位符,图上会露出来）
_UNCLASSIFIED = '未分类'


def _week_buckets(weeks):
    """最近 N 周的 (周一日期, 标签) 列表,按时间升序。"""
    today = datetime.utcnow().date()
    this_monday = today - timedelta(days=today.weekday())
    return [
        (this_monday - timedelta(weeks=offset),
         (this_monday - timedelta(weeks=offset)).strftime('%m-%d'))
        for offset in range(weeks - 1, -1, -1)
    ]


def _safe_rate(numerator, denominator):
    return round(numerator / denominator * 100, 2) if denominator else 0.0


def build_dashboard(user):
    """汇总当前用户可见范围内的全部看板数据。

    可见范围复用 ``apply_vuln_scope`` —— 与列表页、详情页同源,
    不同角色看到的数字不同是设计使然,不是 bug。
    """
    vulns = apply_vuln_scope(
        Vulnerability.query.filter_by(is_deleted=False), user
    ).all()

    now = datetime.utcnow()
    total = len(vulns)

    severity_counts = {level: 0 for level in _SEVERITY_ORDER}
    status_counts = {status: 0 for status in ALL_STATUSES}
    type_counts = {}
    project_counts = {}
    overdue = []

    resolved = 0          # 已闭环(含误报/忽略,它们是终止态)
    closed_only = 0       # 真正"复测通过"
    fix_durations = []    # 平均修复时长(天)

    for vuln in vulns:
        severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1
        status_counts[vuln.status] = status_counts.get(vuln.status, 0) + 1

        key = vuln.vuln_type or _UNCLASSIFIED
        type_counts[key] = type_counts.get(key, 0) + 1

        project_name = vuln.project.name if vuln.project else '未关联项目'
        project_counts[project_name] = project_counts.get(project_name, 0) + 1

        if vuln.status in TERMINAL_STATUSES:
            resolved += 1
        if vuln.status == 'closed':
            closed_only += 1

        # 逾期:过了 SLA 截止时间且仍未闭环
        if (vuln.due_date and vuln.status not in TERMINAL_STATUSES
                and vuln.due_date < now):
            overdue.append(vuln)

        # MTTR:从创建到标记修复的耗时
        if vuln.fixed_at and vuln.created_at:
            fix_durations.append((vuln.fixed_at - vuln.created_at).total_seconds() / 86400)

    # ---- 趋势:最近 TREND_WEEKS 周的新增与闭环 ----
    buckets = _week_buckets(TREND_WEEKS)
    created_series = [0] * len(buckets)
    closed_series = [0] * len(buckets)

    def _bucket_index(moment):
        if not moment:
            return None
        day = moment.date()
        for index, (start, _) in enumerate(buckets):
            if start <= day < start + timedelta(days=7):
                return index
        return None

    for vuln in vulns:
        index = _bucket_index(vuln.created_at)
        if index is not None:
            created_series[index] += 1
        index = _bucket_index(vuln.closed_at)
        if index is not None:
            closed_series[index] += 1

    type_labels = dict(VULN_TYPE_CHOICES)
    top_projects = sorted(project_counts.items(), key=lambda item: item[1], reverse=True)[:TOP_PROJECTS]

    return {
        'scope_label': SCOPE_LABELS.get(user.role, '可见范围'),
        'total': total,
        'pending_count': status_counts.get('pending', 0),
        'fixed_count': status_counts.get('fixed', 0),
        'resolved_count': resolved,
        'closed_count': closed_only,
        'closure_rate': _safe_rate(resolved, total),
        'high_total': severity_counts.get('严重', 0) + severity_counts.get('高危', 0),

        'severity_counts': severity_counts,
        'severity_series': [
            {'name': level, 'value': severity_counts.get(level, 0)}
            for level in _SEVERITY_ORDER
        ],
        'status_series': [
            {'name': STATUS_LABELS[status], 'value': status_counts.get(status, 0)}
            for status in ALL_STATUSES
        ],
        'type_series': [
            {'name': type_labels.get(key, key or '未分类'), 'value': value}
            for key, value in sorted(type_counts.items(), key=lambda item: item[1], reverse=True)
        ],
        'project_series': [{'name': name, 'value': value} for name, value in top_projects],

        'trend_labels': [label for _, label in buckets],
        'trend_created': created_series,
        'trend_closed': closed_series,

        'overdue_count': len(overdue),
        'overdue_list': sorted(overdue, key=lambda v: v.due_date)[:10],
        'mttr_days': round(sum(fix_durations) / len(fix_durations), 1) if fix_durations else None,
        'mttr_samples': len(fix_durations),
    }
