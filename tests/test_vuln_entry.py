"""漏洞录入链路测试。

覆盖改造前的三个缺陷:

1. ``create()`` / ``create_for_project()`` 不写 ``vuln_type`` —— 经这两个入口建的
   漏洞类型恒为 NULL,看板的"漏洞类型分布"全落到"未分类";
2. 两个入口都不支持截图,表单里既没有 ``enctype`` 也没有 file 控件;
3. ``create_for_project`` 把项目下拉 ``disabled`` 掉 —— 禁用控件不随表单提交,
   ``DataRequired`` 必然失败,**这个入口从来提交不成功**。

外加一条换行:``description`` 曾是 ``StringField``,渲染成单行 ``<input>``,
用户输入的换行会被浏览器直接压掉。
"""
import io
import json

import pytest

from app import db
from app.models import Vulnerability
from app.routes.vulnerabilities import collect_referenced_screenshots


def _payload(**overrides):
    data = {
        'title': '链路验证用漏洞标题',
        'description': '第一行\n第二行',
        'source': 'manual',
        'severity': '高危',
        'vuln_type': 'sqli',
    }
    data.update(overrides)
    return data


# ---------------------------------------------------------------- 纯函数


def test_collect_referenced_screenshots_accepts_local_uploads():
    html = ('<p>看图</p>'
            '<img src="/vulnerabilities/screenshot/' + 'a' * 32 + '.png" alt="截图">'
            '<img src="/vulnerabilities/screenshot/' + 'b' * 32 + '.jpg">')
    assert collect_referenced_screenshots(html) == ['a' * 32 + '.png', 'b' * 32 + '.jpg']


def test_collect_referenced_screenshots_rejects_external_and_traversal():
    """NAME_RE 是这条链路上唯一的路径穿越防线,不能被放宽。"""
    html = ('<img src="https://evil.example.com/x.png">'
            '<img src="../../etc/passwd">'
            '<img src="/vulnerabilities/screenshot/../../secret.png">'
            '<img src="/vulnerabilities/screenshot/notahexname.png">')
    assert collect_referenced_screenshots(html) == []


def test_collect_referenced_screenshots_dedupes_and_merges_extras():
    html = '<img src="/vulnerabilities/screenshot/' + 'c' * 32 + '.png">'
    html += html  # 同一张图引用两次
    extra = ['c' * 32 + '.png', 'd' * 32 + '.gif']
    assert collect_referenced_screenshots(html, extra) == ['c' * 32 + '.png', 'd' * 32 + '.gif']


# ---------------------------------------------------------------- 表单渲染


def test_create_form_is_multipart_and_has_vuln_type(app, client, seed, as_user):
    as_user(seed.user_ids['tester'])
    body = client.get('/vulnerabilities/create').get_data(as_text=True)
    assert 'enctype="multipart/form-data"' in body, '表单缺 enctype,request.files 永远为空'
    assert 'name="screenshots"' in body, '缺文件上传控件'
    assert 'name="vuln_type"' in body, '缺漏洞类型字段'


def test_description_renders_as_textarea(app, client, seed, as_user):
    """回归:StringField 会渲染成单行 <input>,rows 被浏览器忽略。"""
    as_user(seed.user_ids['tester'])
    body = client.get('/vulnerabilities/create').get_data(as_text=True)
    assert '<textarea' in body, 'description 没有渲染成 textarea'
    assert 'rows="8"' in body


def test_create_for_project_form_is_not_disabled(app, client, seed, as_user):
    """回归:项目下拉被 disabled → 不随表单提交 → 校验必然失败。"""
    as_user(seed.user_ids['tester'])
    body = client.get(f'/vulnerabilities/create-for-project/{seed.project_id}').get_data(as_text=True)
    assert 'name="screenshots"' in body
    # 项目应当是只读文本而不是 disabled 的表单控件
    assert 'name="project_id"' not in body or 'disabled' not in body.split('name="project_id"')[0][-120:]


# ---------------------------------------------------------------- 创建行为


def test_create_writes_vuln_type_and_screenshot(app, client, seed, as_user):
    as_user(seed.user_ids['tester'])
    data = _payload(project_id=str(seed.project_id), task_id=str(seed.task_id),
                    assignee_id=str(seed.user_ids['dev']))
    data['screenshots'] = (io.BytesIO(b'\x89PNG\r\n\x1a\n fake'), 'eviden.png')

    resp = client.post('/vulnerabilities/create', data=data,
                       content_type='multipart/form-data', follow_redirects=False)
    assert resp.status_code == 302, resp.get_data(as_text=True)[:400]

    with app.app_context():
        vuln = Vulnerability.query.filter_by(title='链路验证用漏洞标题').first()
        assert vuln is not None, '漏洞没有创建出来'
        assert vuln.vuln_type == 'sqli', 'vuln_type 没写入'
        names = json.loads(vuln.screenshots or '[]')
        assert len(names) == 1 and names[0].endswith('.png'), vuln.screenshots


def test_create_preserves_line_breaks(app, client, seed, as_user):
    """回归:StringField 时代换行会被压成一行。"""
    as_user(seed.user_ids['tester'])
    data = _payload(project_id=str(seed.project_id), task_id=str(seed.task_id),
                    assignee_id=str(seed.user_ids['dev']))

    client.post('/vulnerabilities/create', data=data, follow_redirects=False)

    with app.app_context():
        vuln = Vulnerability.query.filter_by(title='链路验证用漏洞标题').first()
        assert '<br>' in (vuln.description or ''), f'换行没保留: {vuln.description!r}'

    as_user(seed.user_ids['tester'])
    detail = client.get(f'/vulnerabilities/{vuln.id}').get_data(as_text=True)
    assert '第一行' in detail and '第二行' in detail


def test_create_for_project_actually_creates(app, client, seed, as_user):
    """回归:这个入口此前从未提交成功过。"""
    as_user(seed.user_ids['tester'])
    before = None
    with app.app_context():
        before = Vulnerability.query.count()

    data = _payload(title='为项目建的漏洞', task_id='0',
                    assignee_id=str(seed.user_ids['dev']))
    resp = client.post(f'/vulnerabilities/create-for-project/{seed.project_id}',
                       data=data, follow_redirects=False)
    assert resp.status_code == 302, resp.get_data(as_text=True)[:400]

    with app.app_context():
        assert Vulnerability.query.count() == before + 1
        vuln = Vulnerability.query.filter_by(title='为项目建的漏洞').first()
        assert vuln is not None and vuln.project_id == seed.project_id
        assert vuln.vuln_type == 'sqli'


def test_screenshots_derived_from_inline_images_on_edit(app, client, seed, as_user):
    """编辑时按描述里的 <img> 重建 screenshots 缓存。"""
    vuln_id = seed.vuln_ids['pending']
    filename = 'e' * 32 + '.png'

    as_user(seed.user_ids['tester'])
    with app.app_context():
        vuln = db.session.get(Vulnerability, vuln_id)
        payload = {
            'title': vuln.title,
            'description': f'<p>复现截图</p><img src="/vulnerabilities/screenshot/{filename}">',
            'project_id': str(vuln.project_id),
            'task_id': str(vuln.task_id or 0),
            'source': vuln.source or 'manual',
            'severity': vuln.severity or '中危',
            'vuln_type': vuln.vuln_type or '',
            'assignee_id': str(vuln.assignee_id or 0),
        }

    resp = client.post(f'/vulnerabilities/{vuln_id}/edit', data=payload, follow_redirects=False)
    assert resp.status_code == 302, resp.get_data(as_text=True)[:400]

    with app.app_context():
        vuln = db.session.get(Vulnerability, vuln_id)
        assert json.loads(vuln.screenshots or '[]') == [filename]


def test_oversized_description_is_rejected(app, client, seed, as_user):
    """description 有长度上限 —— sanitize 会给每个未闭合标签补闭合标签,
    不设限的话大量标签会放大成数倍体积。"""
    as_user(seed.user_ids['tester'])
    data = _payload(project_id=str(seed.project_id), task_id=str(seed.task_id),
                    assignee_id=str(seed.user_ids['dev']),
                    description='<div>' * 5000)
    resp = client.post('/vulnerabilities/create', data=data, follow_redirects=False)
    # 校验失败会重新渲染表单(200),而不是创建成功(302)
    assert resp.status_code == 200
    with app.app_context():
        assert Vulnerability.query.filter_by(title='链路验证用漏洞标题').first() is None
