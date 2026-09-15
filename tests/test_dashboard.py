"""统计看板测试:角色可见范围、各维度聚合、降级。

改造前 main.index 一进来就 abort(403),只有管理员能看;而且只统计
严重/高危/中危三档,低危被丢掉了。
"""
from datetime import datetime, timedelta

import pytest

from app import db
from app.analytics import build_dashboard
from app.models import User, Vulnerability


def test_dashboard_open_to_non_admin_roles(app, client, seed, as_user):
    """除访客外都能看自己的看板。"""
    for name in ('admin', 'lead', 'tester', 'dev', 'biz'):
        as_user(seed.user_ids[name])
        assert client.get('/').status_code == 200, name


def test_guest_cannot_open_dashboard(app, client, seed, as_user):
    """访客没有 dashboard.view 权限。"""
    as_user(seed.user_ids['guest'])
    assert client.get('/').status_code == 403


def test_scope_label_reflects_role(app, seed):
    with app.app_context():
        for name, expected in [('admin', '全部漏洞'),
                               ('tester', '本人测试发现的漏洞'),
                               ('dev', '指派给本人的漏洞'),
                               ('biz', '本人名下项目的漏洞'),
                               ('guest', '仅已闭环漏洞')]:
            user = db.session.get(User, seed.user_ids[name])
            assert build_dashboard(user)['scope_label'] == expected, name


def test_severity_includes_low(app, seed):
    """回归:原看板丢掉了低危。"""
    with app.app_context():
        vuln = db.session.get(Vulnerability, seed.vuln_ids['pending'])
        vuln.severity = '低危'
        db.session.commit()

        admin = db.session.get(User, seed.user_ids['admin'])
        data = build_dashboard(admin)
        names = {item['name'] for item in data['severity_series']}
        assert names == {'严重', '高危', '中危', '低危'}
        assert data['severity_counts']['低危'] == 1


def test_status_series_covers_all_five_states(app, seed):
    with app.app_context():
        admin = db.session.get(User, seed.user_ids['admin'])
        data = build_dashboard(admin)
        assert len(data['status_series']) == 5
        # 种子里五种状态各一条
        assert all(item['value'] == 1 for item in data['status_series'])


def test_closure_rate_and_counts(app, seed):
    with app.app_context():
        admin = db.session.get(User, seed.user_ids['admin'])
        data = build_dashboard(admin)
        assert data['total'] == 5
        assert data['pending_count'] == 1
        assert data['fixed_count'] == 1
        # closed / false_positive / ignored 三个终止态都算已闭环
        assert data['resolved_count'] == 3
        assert data['closure_rate'] == 60.0


def test_overdue_only_counts_open_vulns(app, seed):
    """已闭环的漏洞即使过了截止时间也不算逾期。"""
    with app.app_context():
        past = datetime.utcnow() - timedelta(days=3)
        for status in ('pending', 'closed', 'false_positive'):
            vuln = db.session.get(Vulnerability, seed.vuln_ids[status])
            vuln.due_date = past
        db.session.commit()

        admin = db.session.get(User, seed.user_ids['admin'])
        data = build_dashboard(admin)
        # pending 算逾期;closed 和 false_positive 是终止态,不算
        assert data['overdue_count'] == 1
        assert data['overdue_list'][0].status == 'pending'


def test_mttr_computed_from_fixed_at(app, seed):
    with app.app_context():
        vuln = db.session.get(Vulnerability, seed.vuln_ids['pending'])
        vuln.created_at = datetime.utcnow() - timedelta(days=10)
        vuln.fixed_at = datetime.utcnow() - timedelta(days=4)
        db.session.commit()

        admin = db.session.get(User, seed.user_ids['admin'])
        data = build_dashboard(admin)
        assert data['mttr_samples'] == 1
        assert 5.9 < data['mttr_days'] < 6.1


def test_mttr_is_none_without_fixed_records(app, seed, as_user):
    """没有已修复记录时应显示 —,而不是 0 或报错。"""
    with app.app_context():
        Vulnerability.query.update({'fixed_at': None}, synchronize_session=False)
        db.session.commit()
        admin = db.session.get(User, seed.user_ids['admin'])
        assert build_dashboard(admin)['mttr_days'] is None

    body = as_user(seed.user_ids['admin']).get('/').get_data(as_text=True)
    assert '暂无已修复记录' in body


def test_unclassified_type_is_localised(app, seed):
    """未填类型的漏洞不能在图例里露出英文占位符。"""
    with app.app_context():
        vuln = db.session.get(Vulnerability, seed.vuln_ids['pending'])
        vuln.vuln_type = None
        db.session.commit()

        admin = db.session.get(User, seed.user_ids['admin'])
        names = {item['name'] for item in build_dashboard(admin)['type_series']}
        assert '未分类' in names
        assert 'unclassified' not in names


def test_trend_has_twelve_weeks(app, seed):
    with app.app_context():
        admin = db.session.get(User, seed.user_ids['admin'])
        data = build_dashboard(admin)
        assert len(data['trend_labels']) == 12
        assert len(data['trend_created']) == 12
        assert len(data['trend_closed']) == 12
        # 种子数据是刚创建的,应落在最后一桶
        assert data['trend_created'][-1] == 5


def test_dashboard_data_is_embedded_for_charts(app, client, seed, as_user):
    as_user(seed.user_ids['admin'])
    body = client.get('/').get_data(as_text=True)
    assert 'echarts.min.js' in body
    assert 'SEVERITY =' in body
    assert 'TREND_LABELS =' in body


def test_dashboard_has_static_fallback(app, client, seed, as_user):
    """CDN 断网时必须能降级成表格,不能白屏。"""
    as_user(seed.user_ids['admin'])
    body = client.get('/').get_data(as_text=True)
    assert 'fbSeverity' in body          # 降级表格存在
    assert 'showFallback' in body        # 降级逻辑存在
    assert '图表库未能加载' in body


def test_developer_dashboard_excludes_others(app, client, seed, as_user):
    """看板数字必须遵守数据范围,不能绕过 apply_vuln_scope 全局统计。"""
    with app.app_context():
        dev2 = db.session.get(User, seed.user_ids['dev2'])
        assert build_dashboard(dev2)['total'] == 0

        dev = db.session.get(User, seed.user_ids['dev'])
        assert build_dashboard(dev)['total'] == 5
