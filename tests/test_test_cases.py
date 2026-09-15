"""测试用例的增删改，以及漏洞计数的真实性。

改造前测试用例是"只读展示 + 单字段状态机"：
``TestCase`` 有 name/detail/version 三个字段，但全项目**没有任何路由**能新增、
改名、改版本或删除用例；``detail`` 列从未被任何代码写入过；
``vulnerability_count`` 是个**假计数**（写死 ``1 if status == 'fail' else 0``，
与该用例实际关联的漏洞条数无关）。
"""
import pytest

from app import db
from app.models import AuditLog, Task, TestCase, Vulnerability
from app.routes.projects import CASE_PER_PAGE


def _make_vuln(task, case, **overrides):
    fields = {
        'vuln_code': f'VUL-TC-{case.id}-{Vulnerability.query.count()}',
        'title': f'用例 {case.case_number} 发现的漏洞',
        'description': 'x',
        'project_id': task.project_id,
        'task_id': task.id,
        'test_case_id': case.id,
        'source': 'manual',
        'severity': '中危',
        'status': 'pending',
    }
    fields.update(overrides)
    vuln = Vulnerability(**fields)
    db.session.add(vuln)
    db.session.flush()
    return vuln


# ---------------------------------------------------------------- 新增


def test_create_case(app, client, seed, as_user):
    as_user(seed.user_ids['tester'])
    resp = client.post(f'/projects/task/{seed.task_id}/case/create',
                       data={'name': '自研用例：车载网关密钥硬编码',
                             'version': '2.1', 'detail': '补充说明'},
                       follow_redirects=False)
    assert resp.status_code == 302

    with app.app_context():
        case = TestCase.query.filter_by(name='自研用例：车载网关密钥硬编码').first()
        assert case is not None
        assert case.version == '2.1'
        assert case.detail == '补充说明'
        assert case.status == 'disabled'
        # 编号应当接在已有之后（种子里已有一条 No.1）
        assert case.case_number == 2

        row = AuditLog.query.filter_by(action='case_create').first()
        assert row is not None and row.resource_type == 'task'


def test_create_case_rejects_empty_name(app, client, seed, as_user):
    as_user(seed.user_ids['tester'])
    before = None
    with app.app_context():
        before = TestCase.query.filter_by(task_id=seed.task_id).count()

    client.post(f'/projects/task/{seed.task_id}/case/create', data={'name': '   '})

    with app.app_context():
        assert TestCase.query.filter_by(task_id=seed.task_id).count() == before


def test_non_owner_cannot_create_case(app, client, seed, as_user):
    """tester2 不是这个任务的处理人。"""
    as_user(seed.user_ids['tester2'])
    resp = client.post(f'/projects/task/{seed.task_id}/case/create',
                       data={'name': '蹭一个用例'}, follow_redirects=False)
    assert resp.status_code == 403


def test_developer_cannot_create_case(app, client, seed, as_user):
    """开发者没有 PERM_CASE_UPDATE。"""
    as_user(seed.user_ids['dev'])
    resp = client.post(f'/projects/task/{seed.task_id}/case/create',
                       data={'name': 'x'}, follow_redirects=False)
    assert resp.status_code == 403


# ---------------------------------------------------------------- 编辑


def test_edit_case(app, client, seed, as_user):
    as_user(seed.user_ids['tester'])
    payload = {'name': '改过名的用例', 'version': '3.0', 'detail': '新说明'}
    resp = client.post(f'/projects/task/{seed.task_id}/case/{seed.case_id}/edit',
                       data=payload, follow_redirects=False)
    assert resp.status_code == 302

    with app.app_context():
        case = db.session.get(TestCase, seed.case_id)
        assert case.name == '改过名的用例'
        assert case.version == '3.0'
        assert case.detail == '新说明'

        row = AuditLog.query.filter_by(action='case_edit').first()
        assert row is not None
        assert '版本' in row.detail and '说明' in row.detail


def test_edit_case_does_not_touch_status(app, client, seed, as_user):
    """状态改动走单独那条路由（它会联动生成漏洞记录），这里不该碰。"""
    as_user(seed.user_ids['tester'])
    client.post(f'/projects/task/{seed.task_id}/case/{seed.case_id}/edit',
                data={'name': '只改名字', 'version': '1.0', 'status': 'pass'})

    with app.app_context():
        case = db.session.get(TestCase, seed.case_id)
        assert case.status == 'fail', '编辑不该改状态'
        assert case.name == '只改名字'


# ---------------------------------------------------------------- 删除


def test_delete_case(app, client, seed, as_user):
    as_user(seed.user_ids['tester'])
    resp = client.post(f'/projects/task/{seed.task_id}/case/{seed.case_id}/delete',
                       follow_redirects=False)
    assert resp.status_code == 302

    with app.app_context():
        assert db.session.get(TestCase, seed.case_id) is None
        assert AuditLog.query.filter_by(action='case_delete').count() == 1


def test_cannot_delete_case_with_linked_vulnerabilities(app, client, seed, as_user):
    """已关联漏洞的用例不能删 —— 否则漏洞的"来源测试用例"会变成悬空引用。"""
    with app.app_context():
        task = db.session.get(Task, seed.task_id)
        case = db.session.get(TestCase, seed.case_id)
        _make_vuln(task, case)
        db.session.commit()

    as_user(seed.user_ids['tester'])
    resp = client.post(f'/projects/task/{seed.task_id}/case/{seed.case_id}/delete',
                       follow_redirects=False)
    assert resp.status_code == 302

    with app.app_context():
        assert db.session.get(TestCase, seed.case_id) is not None, '有关联漏洞时不该删掉'
        assert AuditLog.query.filter_by(action='case_delete').count() == 0


# ---------------------------------------------------------------- 真实计数


def test_vulnerability_count_is_real_not_faked(app, client, seed, as_user):
    """回归:原先是 ``1 if status == 'fail' else 0`` 的假计数。

    这里给同一个用例挂 3 条漏洞,页面必须显示 3。
    """
    with app.app_context():
        task = db.session.get(Task, seed.task_id)
        case = db.session.get(TestCase, seed.case_id)
        for i in range(3):
            _make_vuln(task, case, vuln_code=f'VUL-COUNT-{i}')
        db.session.commit()

    as_user(seed.user_ids['tester'])
    body = client.get(f'/projects/task/{seed.task_id}/workflow').get_data(as_text=True)
    assert '漏洞：3' in body, '用例的漏洞计数不是真实值'


def test_marking_fail_no_longer_writes_fake_count(app, client, seed, as_user):
    """标记不通过时不再往 vulnerability_count 写假值。"""
    with app.app_context():
        db.session.get(TestCase, seed.case_id).vulnerability_count = 0
        db.session.commit()

    as_user(seed.user_ids['tester'])
    client.post(f'/projects/task/{seed.task_id}/case/{seed.case_id}/status',
                data={'status': 'fail'})

    with app.app_context():
        case = db.session.get(TestCase, seed.case_id)
        assert case.status == 'fail'
        assert case.vulnerability_count == 0, '不该再写假计数'
        # 但确实生成了一条漏洞
        assert Vulnerability.query.filter_by(test_case_id=case.id, is_deleted=False).count() == 1


def test_case_list_is_paginated(app, client, seed, as_user):
    """回归:156 条用例会一次全渲染出来。"""
    with app.app_context():
        task = db.session.get(Task, seed.task_id)
        for i in range(CASE_PER_PAGE * 2):
            db.session.add(TestCase(task_id=task.id, case_number=100 + i,
                                    name=f'批量用例 {i:03d}', status='disabled',
                                    version='1.0'))
        db.session.commit()

    as_user(seed.user_ids['tester'])
    first = client.get(f'/projects/task/{seed.task_id}/workflow').get_data(as_text=True)
    assert f'第 1 /' in first
    assert '批量用例 000' in first

    second = client.get(f'/projects/task/{seed.task_id}/workflow?page=2').get_data(as_text=True)
    assert '第 2 /' in second
    assert '批量用例 000' not in second


def test_case_links_are_localised(app, client, seed, as_user):
    """用例区此前硬编码"云端(Cloud)--WEB",且状态用内联字典。"""
    as_user(seed.user_ids['tester'])
    body = client.get(f'/projects/task/{seed.task_id}/workflow').get_data(as_text=True)
    assert '云端(Cloud)' not in body
