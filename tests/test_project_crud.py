"""项目 / 迭代的编辑、归档与删除。

改造前项目**只能创建**：没有编辑、没有归档、也没有删除入口（只有一个
"删除迭代"）。``Project.status`` 全项目只有 ``'active'`` 一个取值，而大量
查询都在过滤 ``status == 'active'`` —— 那个条件其实是恒真的。

给 status 一个真实语义会带来一个必须一起处理的副作用：归档的项目会从各处
下拉里静默消失，用户会以为数据丢了。所以归档必须配一个"显示已归档"的开关。
"""
import pytest

from app import db
from app.models import AuditLog, Project, Task, TestCase, User, Vulnerability


def _select_options(html, field_name):
    """取某个 <select> 里的全文本内容。

    不能直接拿整页做 `assert '项目名' not in body` —— flash 提示里也会带项目名
    （比如"项目「X」已归档"），会误判。
    """
    import re
    match = re.search(
        r'<select[^>]*name="%s"[^>]*>(.*?)</select>' % re.escape(field_name),
        html, re.S,
    )
    return match.group(1) if match else ''


def _form_payload(project, **overrides):
    data = {
        'name': project.name,
        'project_type': project.project_type or 'web',
        'department': project.department or '',
        'environment': project.environment or 'testing',
        'criticality': project.criticality or '普通',
        'description': project.description or '',
    }
    data.update(overrides)
    return data


# ---------------------------------------------------------------- 编辑


def test_owner_can_edit_project(app, client, seed, as_user):
    as_user(seed.user_ids['biz'])
    with app.app_context():
        project = db.session.get(Project, seed.project_id)
        payload = _form_payload(project, name='改过名的项目', criticality='重要')

    resp = client.post(f'/projects/{seed.project_id}/edit', data=payload, follow_redirects=False)
    assert resp.status_code == 302, resp.get_data(as_text=True)[:300]

    with app.app_context():
        project = db.session.get(Project, seed.project_id)
        assert project.name == '改过名的项目'
        assert project.criticality == '重要'

        row = AuditLog.query.filter_by(action='edit_project').first()
        assert row is not None, '编辑项目没有写审计'
        assert row.resource_type == 'project'
        assert '改过名的项目' in (row.detail or '')


def test_edit_records_field_changes(app, client, seed, as_user):
    as_user(seed.user_ids['biz'])
    with app.app_context():
        project = db.session.get(Project, seed.project_id)
        # 种子里 project.criticality 已是「核心」,这里换成「重要」才测得出变化
        payload = _form_payload(project, criticality='重要', department='新部门')

    client.post(f'/projects/{seed.project_id}/edit', data=payload)

    with app.app_context():
        detail = AuditLog.query.filter_by(action='edit_project').first().detail
        assert '重要等级' in detail and '部门' in detail
        assert '核心 → 重要' in detail
        assert '→' in detail


def test_non_owner_cannot_edit_project(app, client, seed, as_user):
    """另一个业务人员不是这个项目的负责人。"""
    with app.app_context():
        other = User(username='biz2', email='biz2@test.local',
                     password_hash=User.query.first().password_hash, role='business')
        db.session.add(other)
        db.session.commit()
        other_id = other.id

    as_user(other_id)
    with app.app_context():
        payload = _form_payload(db.session.get(Project, seed.project_id), name='越权改名')

    assert client.post(f'/projects/{seed.project_id}/edit',
                       data=payload).status_code == 403

    with app.app_context():
        assert db.session.get(Project, seed.project_id).name != '越权改名'


def test_developer_cannot_edit_project(app, client, seed, as_user):
    """开发者没有 PERM_PROJECT_CREATE,不能建也不能改项目。"""
    as_user(seed.user_ids['dev'])
    with app.app_context():
        payload = _form_payload(db.session.get(Project, seed.project_id))

    assert client.post(f'/projects/{seed.project_id}/edit', data=payload).status_code == 403


# ---------------------------------------------------------------- 归档


def test_archive_hides_project_from_vuln_create_dropdown(app, client, seed, as_user):
    """归档的核心语义:从"新建漏洞"的项目下拉里收起来。"""
    as_user(seed.user_ids['biz'])
    client.post(f'/projects/{seed.project_id}/archive', follow_redirects=False)

    with app.app_context():
        assert db.session.get(Project, seed.project_id).status == 'archived'
        assert AuditLog.query.filter_by(action='archive_project').count() == 1

    # 测试人员新建漏洞时,项目下拉里不该再出现这个项目
    as_user(seed.user_ids['tester'])
    options = _select_options(
        client.get('/vulnerabilities/create').get_data(as_text=True), 'project_id')
    assert options, '没找到项目下拉'
    assert '演示项目' not in options


def test_show_archived_toggle_brings_it_back(app, client, seed, as_user):
    """归档必须可找回 —— 否则用户会以为数据丢了。"""
    as_user(seed.user_ids['biz'])
    client.post(f'/projects/{seed.project_id}/archive', follow_redirects=False)

    import re

    def _iteration_rows(url):
        body = client.get(url).get_data(as_text=True)
        # 只取迭代表格的行,避开 flash 与其它区域的文本
        table = re.search(r'<table[^>]*class="[^"]*iteration-table[^"]*"[^>]*>(.*?)</table>',
                           body, re.S)
        return table.group(1) if table else ''

    assert '演示项目' not in _iteration_rows('/business?stage=requirement')
    assert '演示项目' in _iteration_rows('/business?stage=requirement&show_archived=1')


def test_restore_brings_project_back(app, client, seed, as_user):
    as_user(seed.user_ids['biz'])
    client.post(f'/projects/{seed.project_id}/archive')
    client.post(f'/projects/{seed.project_id}/restore', follow_redirects=False)

    with app.app_context():
        assert db.session.get(Project, seed.project_id).status == 'active'
        assert AuditLog.query.filter_by(action='restore_project').count() == 1

    as_user(seed.user_ids['tester'])
    options = _select_options(
        client.get('/vulnerabilities/create').get_data(as_text=True), 'project_id')
    assert '演示项目' in options


def test_archived_project_detail_still_opens(app, client, seed, as_user):
    """归档不是删除:详情页要能正常打开并标明已归档。"""
    as_user(seed.user_ids['biz'])
    client.post(f'/projects/{seed.project_id}/archive')

    resp = client.get(f'/projects/{seed.project_id}')
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert '已归档' in body


# ---------------------------------------------------------------- 删除


def test_admin_can_delete_project_with_cascade(app, client, seed, as_user):
    """删除项目要连带任务与用例,漏洞走软删除进回收站。"""
    with app.app_context():
        project = db.session.get(Project, seed.project_id)
        task_ids = [t.id for t in Task.query.filter_by(project_id=project.id).all()]
        vuln_ids = [v.id for v in Vulnerability.query.filter_by(project_id=project.id).all()]

    as_user(seed.user_ids['admin'])
    resp = client.post(f'/projects/{seed.project_id}/delete', follow_redirects=False)
    assert resp.status_code == 302

    with app.app_context():
        assert db.session.get(Project, seed.project_id) is None
        assert Task.query.filter(Task.id.in_(task_ids)).count() == 0
        assert TestCase.query.filter(TestCase.task_id.in_(task_ids)).count() == 0
        # 漏洞不物理删除:它们进回收站,可恢复
        for vid in vuln_ids:
            vuln = db.session.get(Vulnerability, vid)
            assert vuln is not None, '漏洞不该被物理删除'
            assert vuln.is_deleted is True

        row = AuditLog.query.filter_by(action='delete_project').first()
        assert row is not None and row.resource_type == 'project'


def test_non_admin_cannot_delete_project(app, client, seed, as_user):
    """删除不可逆,收紧到管理员。项目负责人可以归档,但不能删。"""
    for name in ('biz', 'lead', 'tester', 'dev'):
        as_user(seed.user_ids[name])
        assert client.post(f'/projects/{seed.project_id}/delete').status_code == 403, name

    with app.app_context():
        assert db.session.get(Project, seed.project_id) is not None
