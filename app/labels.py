"""展示层的枚举 → 中文标签映射 —— 全站唯一来源。

改造前这些映射以字面量形式散落在模板里（粗数 11 处），其中「任务状态」被独立写了
**3 遍且译法互相不一致**：

    business.html:875      archived → 已归档
    projects/list.html:111 archived → 已完成
    task_workflow.html:122 archived → 完成

同一个值在三个页面显示成三种说法。漏洞的 `pending` 也有同样问题
（canonical 是「待修复」，但两个页面写成「待复测」）。

这里把标签和徽章配色一并收口,模板只调函数、不再写 if/elif 链或内联字典。
"""
from app.forms import VULN_SOURCE_CHOICES, VULN_TYPE_CHOICES
from app.permissions import ROLE_LABELS

# ---------------------------------------------------------------- 漏洞严重等级

SEVERITY_LABELS = {
    '严重': '严重',
    '高危': '高危',
    '中危': '中危',
    '低危': '低危',
}

#: 徽章配色变体（定义在 app/static/css/app.css）
SEVERITY_BADGE_CLASSES = {
    '严重': 'ui-badge--critical',
    '高危': 'ui-badge--high',
    '中危': 'ui-badge--medium',
    '低危': 'ui-badge--low',
}

# ---------------------------------------------------------------- 测试任务状态

#: 注意 ``archived`` 统一译作「已归档」而非「已完成」——
#: main.py 与 projects.py 里 archived 都是终态归档语义。
TASK_STATUS_LABELS = {
    'scheduled': '待分配',
    'assigned': '待测试',
    'in_progress': '测试中',
    'retest': '整改与复测',
    'archived': '已归档',
}

TASK_STATUS_BADGE_CLASSES = {
    'scheduled': 'ui-badge--waiting',
    'assigned': 'ui-badge--waiting',
    'in_progress': 'ui-badge--ongoing',
    'retest': 'ui-badge--warning',
    'archived': 'ui-badge--done',
}

# ---------------------------------------------------------------- 其他枚举

TASK_TEST_TYPE_LABELS = {
    'penetration_test': '渗透测试',
    'compliance_test': '合规测试',
    'security_scan': '安全扫描',
    'security_test': '安全测试',
}

PROJECT_TYPE_LABELS = {
    'embedded': '嵌入式',
    'web': 'Web应用',
    'mobile': '移动应用',
    'backend': '后台服务',
    'other': '其他',
}

CRITICALITY_LABELS = {'普通': '普通', '重要': '重要', '核心': '核心'}

CRITICALITY_BADGE_CLASSES = {
    '普通': 'ui-badge--low',
    '重要': 'ui-badge--medium',
    '核心': 'ui-badge--critical',
}

ENVIRONMENT_LABELS = {
    'development': '开发环境',
    'testing': '测试环境',
    'production': '生产环境',
}

#: 漏洞来源 / 类型直接复用表单里的选项常量,避免第三份拷贝
SOURCE_LABELS = dict(VULN_SOURCE_CHOICES)
VULN_TYPE_LABELS = dict(VULN_TYPE_CHOICES)

# ---------------------------------------------------------------- 安全扫描

SCAN_TYPE_LABELS = {
    'sast': '源代码扫描',
    'sca': '组件扫描',
    'container': '容器（镜像）扫描',
}

SCAN_TYPE_DESCRIPTIONS = {
    'sast': '对源代码做静态分析，识别注入、越权、硬编码凭据等代码层缺陷。',
    'sca': '扫描第三方依赖与开源组件，比对已知 CVE，发现存在漏洞的版本。',
    'container': '扫描容器镜像的各层，识别系统包与基础镜像中的已知漏洞。',
}

SCAN_TYPE_BADGE_CLASSES = {
    'sast': 'ui-badge--medium',
    'sca': 'ui-badge--high',
    'container': 'ui-badge--ongoing',
}

#: 每类扫描常见的工具，用于新建时的下拉建议
SCAN_TOOL_SUGGESTIONS = {
    'sast': ['SonarQube', 'Fortify SCA', 'Semgrep', 'CodeQL', 'Coverity'],
    'sca': ['Snyk', 'OWASP Dependency-Check', 'Trivy', 'Sonatype Nexus IQ', 'WhiteSource'],
    'container': ['Trivy', 'Clair', 'Anchore Engine', 'Aqua Security', 'Harbor 内置扫描'],
}

SCAN_STATUS_LABELS = {
    'pending': '待执行',
    'running': '执行中',
    'completed': '已完成',
    'failed': '执行失败',
}

SCAN_STATUS_BADGE_CLASSES = {
    'pending': 'ui-badge--waiting',
    'running': 'ui-badge--ongoing',
    'completed': 'ui-badge--closed',
    'failed': 'ui-badge--critical',
}

FINDING_STATUS_LABELS = {
    'open': '待处理',
    'converted': '已转漏洞',
    'ignored': '已忽略',
}

FINDING_STATUS_BADGE_CLASSES = {
    'open': 'ui-badge--pending',
    'converted': 'ui-badge--closed',
    'ignored': 'ui-badge--ignored',
}

#: 扫描类型 -> 用于生成漏洞记录时的"漏洞来源"取值
SCAN_TYPE_TO_VULN_SOURCE = {
    'sast': 'sast',
    'sca': 'sca',
    'container': 'container',
}

#: 按规则编号/标题猜漏洞类型。猜不出就落到 other。
_RULE_TYPE_HINTS = (
    ('CWE-89', 'sqli'), ('CWE-79', 'xss'), ('CWE-352', 'csrf'),
    ('CWE-918', 'ssrf'), ('CWE-22', 'file_vuln'), ('CWE-434', 'file_vuln'),
    ('CWE-502', 'deserialize'), ('CWE-798', 'weak_password'),
    ('CWE-521', 'weak_password'), ('CWE-200', 'info_leak'), ('CWE-538', 'info_leak'),
    ('CWE-284', 'auth_bypass'), ('CWE-287', 'auth_bypass'), ('CWE-862', 'auth_bypass'),
)


def guess_vuln_type(rule_id, title=''):
    """从规则编号或标题猜漏洞类型，猜不出返回 other。

    这只是个便利默认值 —— 转成漏洞后仍可在编辑页改。
    """
    haystack = f'{rule_id or ""} {title or ""}'.upper()
    for keyword, vuln_type in _RULE_TYPE_HINTS:
        if keyword.upper() in haystack:
            return vuln_type
    lowered = (title or '').lower()
    for keyword, vuln_type in (
        ('sql', 'sqli'), ('xss', 'xss'), ('csrf', 'csrf'), ('ssrf', 'ssrf'),
        ('deserial', 'deserialize'), ('password', 'weak_password'),
        ('credential', 'weak_password'), ('secret', 'weak_password'),
        ('traversal', 'file_vuln'), ('upload', 'file_vuln'),
        ('cve-', 'other'),
    ):
        if keyword in lowered:
            return vuln_type
    return 'other'



# ---------------------------------------------------------------- 取标签函数


def _label_getter(mapping, default):
    """生成一个"取不到就原样返回"的标签函数。

    原实现里 ``edit.html`` 用的是 ``{'pending': ...}[vuln.status]`` 直接下标,
    一旦出现字典外的值就是 Jinja KeyError → 500。这里统一兜底。
    """

    def getter(value):
        if value is None or value == '':
            return default
        return mapping.get(value, value)

    return getter


def _class_getter(mapping, default):
    def getter(value):
        return mapping.get(value, default)

    return getter


severity_label = _label_getter(SEVERITY_LABELS, '未定级')
severity_class = _class_getter(SEVERITY_BADGE_CLASSES, 'ui-badge--low')
task_status_label = _label_getter(TASK_STATUS_LABELS, '未知')
task_status_class = _class_getter(TASK_STATUS_BADGE_CLASSES, 'ui-badge--waiting')
test_type_label = _label_getter(TASK_TEST_TYPE_LABELS, '未分类')
project_type_label = _label_getter(PROJECT_TYPE_LABELS, '未设置')
criticality_label = _label_getter(CRITICALITY_LABELS, '普通')
criticality_class = _class_getter(CRITICALITY_BADGE_CLASSES, 'ui-badge--low')
environment_label = _label_getter(ENVIRONMENT_LABELS, '未设置')
source_label = _label_getter(SOURCE_LABELS, '未设置')
vuln_type_label = _label_getter(VULN_TYPE_LABELS, '未分类')
role_label = _label_getter(ROLE_LABELS, '未知')
scan_type_label = _label_getter(SCAN_TYPE_LABELS, '未知类型')
scan_status_label = _label_getter(SCAN_STATUS_LABELS, '未知')
scan_status_class = _class_getter(SCAN_STATUS_BADGE_CLASSES, 'ui-badge--waiting')
scan_type_class = _class_getter(SCAN_TYPE_BADGE_CLASSES, 'ui-badge--low')
finding_status_label = _label_getter(FINDING_STATUS_LABELS, '未知')
finding_status_class = _class_getter(FINDING_STATUS_BADGE_CLASSES, 'ui-badge--pending')
