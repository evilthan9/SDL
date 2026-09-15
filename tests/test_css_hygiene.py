"""CSS 卫生检查:防类名冲撞、防样式重复、防设计 token 漂移。

背景:`base.html` 曾用**裸类选择器**定义 `.btn-secondary` 和 `.btn-light`,
与 Bootstrap 5.3 同名类直接冲撞。base 的 `<style>` 排在 CDN `<link>` 之后,
同特异性后者胜 —— 全站 Bootstrap 的 `.btn-light` 被静默劫持。

这类问题不会报错、不会 500,只会让页面长得不对,所以必须靠机器守。
"""
import pathlib
import re

import pytest

TEMPLATES_DIR = pathlib.Path(__file__).resolve().parent.parent / 'app' / 'templates'
STATIC_DIR = pathlib.Path(__file__).resolve().parent.parent / 'app' / 'static'

#: 会被本项目用到、且容易与自定义样式撞名的 Bootstrap 5.3 类名。
#: 自定义 CSS 里出现这些名字的**裸选择器**即为冲撞。
BOOTSTRAP_COMPONENT_CLASSES = {
    'btn', 'btn-primary', 'btn-secondary', 'btn-light', 'btn-dark', 'btn-success',
    'btn-danger', 'btn-warning', 'btn-info', 'btn-link', 'btn-close', 'btn-sm', 'btn-lg',
    'btn-outline-primary', 'btn-outline-secondary', 'btn-outline-danger',
    'card', 'card-header', 'card-body', 'card-footer', 'card-title', 'card-text',
    'table', 'table-hover', 'table-striped', 'table-responsive', 'table-light', 'table-dark',
    'badge', 'bg-primary', 'bg-secondary', 'bg-success', 'bg-danger', 'bg-warning',
    'bg-info', 'bg-light', 'bg-dark', 'text-white', 'text-muted', 'text-danger',
    'alert', 'alert-info', 'alert-warning', 'alert-danger', 'alert-success',
    'form-control', 'form-select', 'form-label', 'form-check', 'form-check-input',
    'input-group', 'modal', 'modal-dialog', 'modal-content', 'modal-header',
    'modal-body', 'modal-footer', 'modal-title',
    'nav', 'navbar', 'nav-item', 'nav-link', 'progress', 'progress-bar',
    'dropdown', 'dropdown-menu', 'dropdown-item', 'list-group', 'list-group-item',
    'container', 'container-fluid', 'row', 'active', 'disabled', 'show', 'fade',
    'close', 'small', 'lead', 'shadow', 'shadow-sm', 'border', 'rounded',
}


def _style_blocks():
    """所有模板内联 `<style>` 块，产出 (来源, 起始行号, CSS 文本)。"""
    for path in sorted(TEMPLATES_DIR.rglob('*.html')):
        text = path.read_text(encoding='utf-8')
        for match in re.finditer(r'<style\b[^>]*>(.*?)</style>', text, re.S):
            line = text[:match.start()].count('\n') + 1
            yield f'{path.name}:{line}', match.group(1)


def _css_files():
    if not STATIC_DIR.exists():
        return
    for path in sorted(STATIC_DIR.rglob('*.css')):
        yield path.name, path.read_text(encoding='utf-8')


def _all_css():
    return list(_style_blocks()) + list(_css_files())


def _bare_selectors(css):
    """提取裸单类选择器（`.foo` 单独成选择器，不带任何限定上下文）。

    只把裸选择器算作冲撞：`.quick-modal-body .form-label` 这种后代选择器
    是有意的作用域覆盖，安全。
    """
    names = set()
    for block in re.finditer(r'([^{}]+)\{', css):
        selector_group = block.group(1)
        # 跳过 at-rule（@media 等）与注释残留
        if selector_group.strip().startswith('@'):
            continue
        for selector in selector_group.split(','):
            sel = selector.strip()
            # 去掉伪类/伪元素后必须恰好是一个 `.name`
            sel = re.sub(r'::?[a-zA-Z-]+(\([^)]*\))?', '', sel).strip()
            match = re.fullmatch(r'\.([a-zA-Z][\w-]*)', sel)
            if match:
                names.add(match.group(1))
    return names


def test_no_bare_bootstrap_class_selectors():
    """自定义 CSS 不得用裸选择器覆盖 Bootstrap 的组件类。

    回归:base.html 曾裸定义 `.btn-secondary` / `.btn-light`,劫持全站同名按钮。
    """
    offenders = []
    for source, css in _all_css():
        for name in _bare_selectors(css) & BOOTSTRAP_COMPONENT_CLASSES:
            offenders.append(f'{source}: 裸选择器 .{name} 覆盖了 Bootstrap 同名类')
    assert not offenders, '\n'.join(offenders)


def test_custom_button_family_is_namespaced():
    """自定义按钮家族必须带命名空间前缀,避免再次与 Bootstrap 撞名。"""
    #: base.html 里定义的三个自定义按钮类
    expected = {'ui-btn-primary', 'ui-btn-secondary', 'ui-btn-soft'}
    defined = set()
    for _source, css in _all_css():
        defined |= _bare_selectors(css)
    missing = expected - defined
    assert not missing, f'自定义按钮类缺失：{missing}'


def test_no_conflicting_class_names_in_styles():
    """同一个类名不应在多个页面里各定义一份。

    这类重复是"两套视觉体系"的来源:同一个类在两个页面里长得不一样,
    改一处漏一处。公共样式应当集中到 app.css。
    """
    owners = {}
    for source, css in _style_blocks():
        for name in _bare_selectors(css):
            if name.startswith(('ui-', 'db-', 'au-', 'pv-', 'dv-', 'vn-', 'mg-', 'cv-',
                                'workflow-', 'assign-', 'case-', 'iteration-', 'rich-',
                                'shot-', 'publish-', 'err-', 'step', 'flow-', 'process-',
                                'question-', 'survey-', 'panel-', 'section-', 'tab-',
                                'inline-', 'content-', 'meta-', 'chapter-', 'scroll-',
                                'operation-', 'main-', 'topbar', 'filter-', 'form-field',
                                'toolbar', 'page-', 'data-table', 'task-', 'priority-',
                                'status-', 'tag-badge', 'table-card', 'bar', 'progress',
                                'stat-', 'chart', 'icon-', 'user-pill', 'nav-',
                                'vuln-', 'quick-', 'biz-', 'mini-', 'option', 'project-',
                                'dot', 'radio', 'selected', 'current-label', 'empty-',
                                'version-', 'search-', 'sub-', 'crumb', 'schema')):
                continue
            owners.setdefault(name, []).append(source)
    duplicates = {k: v for k, v in owners.items() if len(set(v)) > 1}
    assert not duplicates, f'以下类名在多个页面里各定义了一份：{duplicates}'


def test_no_colour_duplicated_across_templates():
    """同一个色值不应在多个模板里各写一遍。

    改造前全站有 4 套视觉可辨的主蓝（#2c7ef5 / #126ed0 / #2878d8 /
    #2a61cf+#3158e8）、7 种深灰在做"标题"、5 种中灰在做"正文"。
    这类重复是"同一个语义在不同页面长得不一样"的根源 —— 改一处漏一处。

    现在跨文件重复已清零；这条断言防止它重新长回来。
    """
    owners = {}
    for source, css in _all_css():
        page = source.split(':')[0]
        if page.endswith('.css'):
            continue  # app.css 是 token 的定义处，不参与"跨模板重复"的比较
        for colour in set(re.findall(r'#[0-9a-fA-F]{6}\b', css)):
            owners.setdefault(colour.lower(), set()).add(page)

    duplicated = {c: sorted(p) for c, p in owners.items() if len(p) > 1}
    assert not duplicated, (
        '以下色值在多个模板里各写了一遍，应当提取成 app.css 的 token：\n'
        + '\n'.join(f'  {c}  出现在 {", ".join(p)}' for c, p in sorted(duplicated.items()))
    )


def test_tokens_are_actually_used():
    """app.css 里定义的 token 应当真的被引用，而不是定义了没人用。"""
    app_css = '\n'.join(css for source, css in _all_css() if source.endswith('.css'))
    root = re.search(r':root\s*\{(.*?)\}', app_css, re.S)
    assert root, 'app.css 里找不到 :root'

    declared = set(re.findall(r'(--[\w-]+)\s*:', root.group(1)))
    assert declared, '没解析到任何 token'

    used_anywhere = '\n'.join(css for _s, css in _all_css())
    unused = sorted(t for t in declared if used_anywhere.count(f'var({t})') == 0)
    assert not unused, f'以下 token 定义了但从未被引用：{unused}'


#: Bootstrap 原生组件类。改造的目标是把它们换成 app.css 里的 .ui-* 组件,
#: 这个集合是那条迁移线的棘轮 —— 只允许减少。
_BOOTSTRAP_COMPONENTS = {
    'btn', 'btn-primary', 'btn-secondary', 'btn-light', 'btn-outline-primary',
    'btn-outline-secondary', 'btn-outline-danger', 'btn-outline-success',
    'btn-danger', 'btn-warning', 'btn-success',
    'card', 'card-header', 'card-body', 'card-footer',
    'badge',
    'table', 'table-hover', 'table-light', 'table-responsive',
    'alert', 'alert-info', 'alert-warning', 'alert-danger', 'alert-success',
}

#: 允许保留 Bootstrap 的地方（都是有意的）：
#: base.html 的 flash 消息区用 alert 是 Bootstrap 的语义化提示，
#: business.html 的 modal 依赖 Bootstrap 的 data-bs-* 行为。
_ALLOWED_FILES = {'base.html'}


def test_bootstrap_component_usage_is_ratcheted():
    """Bootstrap 原生组件的用法数不得回升。

    这条是改造进度的棘轮：迁移到 .ui-* 组件后计数下降，之后不允许再涨回去
    （比如新页面又写成 `class="btn btn-primary"`）。
    数字只减不增；改完记得同步下调下面的上限。
    """
    #: 已经清零了。新页面请一律用 app.css 里的 .ui-* 组件。
    LIMIT = 0

    offenders = []
    total = 0
    for path in sorted(TEMPLATES_DIR.rglob('*.html')):
        if path.name in _ALLOWED_FILES:
            continue
        text = path.read_text(encoding='utf-8')
        # 注释里提到 class 名不该计数
        text = re.sub(r'\{#.*?#\}', '', text, flags=re.S)
        text = re.sub(r'<!--.*?-->', '', text, flags=re.S)
        used = set()
        for match in re.finditer(r'class="([^"]*)"', text):
            used.update(match.group(1).split())
        hits = sorted(used & _BOOTSTRAP_COMPONENTS)
        if hits:
            total += len(hits)
            offenders.append(f'{path.name}: {", ".join(hits)}')

    assert total <= LIMIT, (
        f'Bootstrap 原生组件用法为 {total} 处，超过上限 {LIMIT}。\n'
        '新页面请用 app.css 里的 .ui-* 组件，不要再用 Bootstrap 原生组件。\n'
        + '\n'.join(offenders)
    )


def test_app_stylesheet_is_served(app, client):
    """app.css 必须真的能取到。

    `<link>` 路径写错时页面会全裸,而所有渲染测试依然是绿的 ——
    因为它们只断言 HTML 结构,不关心 CSS 是否加载成功。
    """
    resp = client.get('/static/css/app.css')
    assert resp.status_code == 200, '静态样式表取不到,<link> 路径可能写错了'
    body = resp.get_data(as_text=True)
    assert len(body) > 3000, f'app.css 只有 {len(body)} 字节,可能没搬全'
    assert '.page-container' in body
    assert '.ui-btn-primary' in body


def test_base_template_links_app_css_before_head_block():
    """app.css 必须排在 `{% block head %}` 之前。

    否则页面级样式会输给全站样式（同特异性下后者胜），
    页面想覆盖全站规则时会出现"改了不生效"。
    """
    text = (TEMPLATES_DIR / 'base.html').read_text(encoding='utf-8')
    css_pos = text.find('css/app.css')
    head_pos = text.find('{% block head %}')
    assert css_pos != -1, 'base.html 没有引用 app.css'
    assert head_pos != -1
    assert css_pos < head_pos, 'app.css 的 <link> 必须在 {% block head %} 之前'


def test_page_container_contract_is_locked():
    """锁定 `.page-container` 的关键声明。

    有 4 个页面用 `margin: -20px -18px -32px` 硬抵这个容器的 padding
    （audit/logs、management、task_workflow、publish）。改一次 padding,
    这 4 个页面同时破版,而没有任何测试能发现。这条断言就是那道防线。
    """
    # 不按来源文件名认（CSS 会从 base.html 内联搬进 app.css），全网找这条规则
    css_all = '\n'.join(css for _source, css in _all_css())

    container = re.search(r'\.page-container\s*\{([^}]*)\}', css_all)
    assert container, '找不到 .page-container 规则'
    fullbleed = re.search(r'\.ui-page--fullbleed\s*\{([^}]*)\}', css_all)
    assert fullbleed, '找不到 .ui-page--fullbleed 规则'

    # 现在的不变量是「两者共用同一组布局 token」：
    # 只要 token 一致，改 token 会同时带动两边，不可能再出现单方面错位。
    for token in ('--page-gutter-y', '--page-gutter-x', '--page-gutter-bottom'):
        assert token in container.group(1), f'.page-container 没有用布局 token {token}'
        assert token in fullbleed.group(1), f'.ui-page--fullbleed 没有用布局 token {token}'

    assert '--topbar-height' in fullbleed.group(1), \
        '.ui-page--fullbleed 的 min-height 必须基于 --topbar-height 计算'

    # 且两个 token 都要在 :root 里真的有定义
    for token in ('--page-gutter-y', '--page-gutter-x', '--page-gutter-bottom',
                  '--topbar-height'):
        assert re.search(re.escape(token) + r'\s*:', css_all), f'{token} 没有定义'
