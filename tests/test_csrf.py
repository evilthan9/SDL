"""CSRF 防护测试。

改造前全站未启用 CSRFProtect:28 个手写 POST 表单里有 17 个没有 token,
另有 2 处 fetch() 上传图片无保护。

这里用两道防线:
1. 静态扫描全部模板 —— 机器证明"没有表单漏 token";
2. 逐个 POST 端点发无 token 请求 —— 证明"漏了就会被拒"。
"""
import pathlib
import re

import pytest

from app import db
from app.models import User

TEMPLATES_DIR = pathlib.Path(__file__).resolve().parent.parent / 'app' / 'templates'

_JINJA_COMMENT = re.compile(r'\{#.*?#\}', re.S)
_HTML_COMMENT = re.compile(r'<!--.*?-->', re.S)


def _strip_comments(text):
    """去掉模板注释再扫描。

    注释里可能出现 "<form>" 或 "csrf_token" 这类字面量:
    不剥掉的话前者会误报嵌套表单,后者会让漏 token 的表单误判为通过。
    """
    return _HTML_COMMENT.sub('', _JINJA_COMMENT.sub('', text))


@pytest.fixture
def csrf_client(app, client):
    """在已建好的 app 上打开 CSRF 校验。

    CSRFProtect 是每次请求读配置的,所以这里直接改即可,不必重建应用。
    """
    app.config['WTF_CSRF_ENABLED'] = True
    return client


# ---------------------------------------------------------------- 静态扫描

def test_every_post_form_carries_a_token():
    """遍历所有模板,每个 method=post 的表单都必须带 token。

    这条测试就是"17 处漏网"的机器证明。
    """
    offenders = []
    for path in sorted(TEMPLATES_DIR.rglob('*.html')):
        text = _strip_comments(path.read_text(encoding='utf-8'))
        for match in re.finditer(r'<form\b([^>]*)>(.*?)</form>', text, re.S | re.I):
            attrs, inner = match.group(1), match.group(2)
            if not re.search(r'method\s*=\s*["\']?post', attrs, re.I):
                continue
            if 'csrf_token' in inner or 'hidden_tag' in inner:
                continue
            offenders.append(f'{path.name}:{text[:match.start()].count(chr(10)) + 1}')

    assert not offenders, '以下 POST 表单缺少 CSRF token：' + ', '.join(offenders)


def test_no_nested_forms():
    """表单不能嵌套。HTML 会丢弃内层 <form> 起始标签,导致按钮提交到错误的表单。

    users.html 曾经把"删除用户"的表单套在"保存权限"的表单里,
    结果点删除实际执行的是保存权限。
    """
    offenders = []
    for path in sorted(TEMPLATES_DIR.rglob('*.html')):
        text = _strip_comments(path.read_text(encoding='utf-8'))
        depth = 0
        for match in re.finditer(r'<form\b|</form>', text, re.I):
            if match.group(0).lower().startswith('</'):
                depth = max(0, depth - 1)
            else:
                depth += 1
                if depth > 1:
                    line = text[:match.start()].count('\n') + 1
                    offenders.append(f'{path.name}:{line}')
    assert not offenders, '以下位置存在嵌套表单：' + ', '.join(offenders)


def test_upload_fetch_sends_csrf_header():
    """两处富文本上传的 fetch 必须带 X-CSRFToken 头。"""
    for name in ('edit.html', 'publish.html'):
        text = _strip_comments((TEMPLATES_DIR / 'vulnerabilities' / name).read_text(encoding='utf-8'))
        assert 'X-CSRFToken' in text, name


def test_base_template_exposes_csrf_meta():
    text = (TEMPLATES_DIR / 'base.html').read_text(encoding='utf-8')
    assert 'name="csrf-token"' in text


# ---------------------------------------------------------------- 端点逐个验证


def _post_targets(seed):
    """所有需要写操作的真实 URL(带真实主键),覆盖四大蓝图。"""
    vuln = seed.vuln_ids
    return [
        ('/auth/login', 'admin'),
        ('/auth/register', 'admin'),
        ('/auth/users', 'admin'),
        (f'/auth/users/{seed.user_ids["dev2"]}/delete', 'admin'),
        ('/vulnerabilities/create', 'tester'),
        (f'/vulnerabilities/{vuln["pending"]}/edit', 'tester'),
        (f'/vulnerabilities/{vuln["pending"]}/transition/fix', 'dev'),
        (f'/vulnerabilities/{vuln["pending"]}/delete', 'tester'),
        (f'/vulnerabilities/{vuln["pending"]}/restore', 'tester'),
        ('/vulnerabilities/batch-delete', 'tester'),
        ('/vulnerabilities/upload-image', 'tester'),
        (f'/vulnerabilities/create-for-project/{seed.project_id}', 'tester'),
        (f'/vulnerabilities/publish/{seed.task_id}/{seed.case_id}', 'tester'),
        ('/projects/create', 'admin'),
        (f'/projects/task/{seed.task_id}/assign', 'admin'),
        (f'/projects/task/{seed.task_id}/start', 'tester'),
        (f'/projects/task/{seed.task_id}/review', 'tester'),
        (f'/projects/task/{seed.task_id}/retest-complete', 'tester'),
        (f'/projects/task/{seed.task_id}/delete', 'admin'),
        (f'/projects/task/{seed.task_id}/case/{seed.case_id}/status', 'tester'),
        ('/business/requirements/iterations/create', 'biz'),
        ('/business/testing/tasks/create', 'tester'),
        ('/business/testing/tasks/create-quick', 'tester'),
        (f'/business/testing/tasks/{seed.task_id}/push', 'admin'),
        (f'/business/iterations/{seed.project_id}/push', 'biz'),
        (f'/business/iterations/{seed.project_id}/delete', 'biz'),
        ('/business/assessment', 'biz'),
    ]


def test_post_endpoints_reject_requests_without_token(app, csrf_client, seed, as_user):
    """没有 token 的 POST 一律 400。任何漏网的表单都会在这里暴露出来。"""
    failures = []
    for url, role in _post_targets(seed):
        as_user(seed.user_ids[role])
        resp = csrf_client.post(url, data={})
        if resp.status_code != 400:
            failures.append(f'{url} ({role}) -> {resp.status_code}')

    assert not failures, '以下端点未拦截无 token 的 POST：\n' + '\n'.join(failures)


def test_upload_image_rejects_without_token_as_json(app, csrf_client, seed, as_user):
    """上传端点是 fetch 调的,被拒时也必须是 JSON,不能返回 HTML。"""
    as_user(seed.user_ids['tester'])
    resp = csrf_client.post('/vulnerabilities/upload-image', data={})
    assert resp.status_code == 400
    assert resp.is_json
    assert resp.get_json()['ok'] is False


def test_upload_image_accepts_valid_token(app, csrf_client, seed, as_user):
    """带上正确的 X-CSRFToken 头就应该放行。"""
    import io
    as_user(seed.user_ids['tester'])
    token = _fetch_token(csrf_client, '/vulnerabilities/management', 'tester', seed)

    data = {'image': (io.BytesIO(b'\x89PNG\r\n\x1a\n fake'), 'shot.png')}
    resp = csrf_client.post('/vulnerabilities/upload-image', data=data,
                            headers={'X-CSRFToken': token},
                            content_type='multipart/form-data')
    assert resp.status_code == 200, resp.get_data(as_text=True)[:200]
    assert resp.get_json()['ok'] is True


def test_form_post_succeeds_with_token_from_page(app, csrf_client, seed, as_user):
    """带 token 的正常提交必须成功 —— 证明开关没把功能打坏。"""
    as_user(seed.user_ids['dev'])
    token = _fetch_token(csrf_client, f'/vulnerabilities/{seed.vuln_ids["pending"]}', 'dev', seed)

    resp = csrf_client.post(
        f'/vulnerabilities/{seed.vuln_ids["pending"]}/transition/fix',
        data={'csrf_token': token},
    )
    assert resp.status_code == 302

    from app.models import Vulnerability
    with app.app_context():
        assert db.session.get(Vulnerability, seed.vuln_ids['pending']).status == 'fixed'


def _fetch_token(client, url, role, seed):
    """从页面里抠出真实的 csrf token（页面里嵌在 meta 标签上）。"""
    resp = client.get(url)
    assert resp.status_code == 200, f'{url} 返回 {resp.status_code}'
    match = re.search(r'name="csrf-token" content="([^"]+)"', resp.get_data(as_text=True))
    assert match, f'{url} 页面里找不到 csrf meta'
    return match.group(1)
