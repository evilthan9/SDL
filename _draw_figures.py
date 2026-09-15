"""生成论文插图（SVG）。用完即删。

用 SVG 而不是 PNG：矢量图插进 Word 放大不虚，也能再编辑。
全部用 presentation 属性而不是 CSS 类，兼容性最好。
"""
import pathlib

OUT = pathlib.Path(r'C:\Users\V\Desktop\毕业答辩材料\插图')
OUT.mkdir(parents=True, exist_ok=True)

FONT = "Microsoft YaHei, SimHei, sans-serif"
# 配色：与论文正文的黑白灰为主，关键状态用低饱和强调色
C_LINE = '#44546a'
C_TEXT = '#1f2a37'
C_SUB = '#667085'
C_BOX_FILL = '#ffffff'
C_STATE_FILL = '#eaf2ff'
C_STATE_EDGE = '#2c7ef5'
C_TERM_FILL = '#f3f4f6'
C_TERM_EDGE = '#98a2b3'
C_LAYER_FILL = '#f8f9fb'

HEAD = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}">'
        '<defs>'
        '<marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" '
        'orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="{c}"/></marker>'
        '<marker id="arrowOpen" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" '
        'orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10" fill="none" stroke="{c}" stroke-width="1.6"/></marker>'
        '</defs>'
        '<rect width="{w}" height="{h}" fill="#ffffff"/>').format


def txt(x, y, s, size=14, color=C_TEXT, weight='normal', anchor='middle'):
    return (f'<text x="{x}" y="{y}" font-family="{FONT}" font-size="{size}" fill="{color}" '
            f'font-weight="{weight}" text-anchor="{anchor}">{s}</text>')


def box(x, y, w, h, fill=C_BOX_FILL, edge=C_LINE, r=8, sw=1.5, dash=None):
    d = f' stroke-dasharray="{dash}"' if dash else ''
    return (f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{r}" ry="{r}" '
            f'fill="{fill}" stroke="{edge}" stroke-width="{sw}"{d}/>')


def line(x1, y1, x2, y2, color=C_LINE, sw=1.5, marker=True, dash=None):
    m = ' marker-end="url(#arrow)"' if marker else ''
    d = f' stroke-dasharray="{dash}"' if dash else ''
    return (f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{color}" '
            f'stroke-width="{sw}"{d}{m}/>')


def path(d, color=C_LINE, sw=1.5, marker=True, dash=None):
    m = ' marker-end="url(#arrow)"' if marker else ''
    da = f' stroke-dasharray="{dash}"' if dash else ''
    return f'<path d="{d}" fill="none" stroke="{color}" stroke-width="{sw}"{da}{m}/>'


# ============================================================================
# 图 3-1  车企安全测试业务流程图
# ============================================================================
W, H = 1100, 520
s = [HEAD(w=W, h=H, c=C_LINE)]

stages = [
    ('定级备案', ['填写安全合规评估问卷', '判定是否需要安全测试']),
    ('需求控制', ['创建项目迭代', '推送至安全测试排期']),
    ('研发控制', ['SAST / SCA / 容器扫描', '开发人员整改漏洞']),
    ('测试控制', ['执行测试用例', '录入并发布漏洞']),
    ('发布控制', ['确认高危是否闭环', '确认是否存在超期']),
]
bx, by, bw, bh, gap = 40, 60, 180, 120, 25
for i, (name, items) in enumerate(stages):
    x = bx + i * (bw + gap)
    s.append(box(x, by, bw, 46, fill=C_STATE_FILL, edge=C_STATE_EDGE, r=6))
    s.append(txt(x + bw / 2, by + 30, name, size=16, weight='bold'))
    s.append(box(x, by + 46, bw, bh - 46 + 40, fill=C_BOX_FILL, edge='#c9d3e0', r=6))
    for j, it in enumerate(items):
        s.append(txt(x + bw / 2, by + 76 + j * 24, it, size=12, color=C_SUB))
    if i < len(stages) - 1:
        s.append(line(x + bw + 2, by + 23, x + bw + gap - 2, by + 23, color=C_STATE_EDGE, sw=2))

# 漏洞生命周期贯穿条
ly = 320
s.append(box(40, ly, 1020, 150, fill='#fbfcfe', edge='#c9d3e0', r=8, dash='6 4'))
s.append(txt(70, ly + 26, '漏洞记录（贯穿研发、测试、发布三阶段的唯一载体）',
             size=14, weight='bold', anchor='start'))
lifecycle = [('测试发现', '测试人员录入漏洞'), ('指派修复', '分派给开发人员'),
             ('提交修复', '开发人员提交整改'), ('复测验证', '测试人员复测'),
             ('闭环 / 终止', '闭环或判定误报、忽略')]
lw, lgap = 172, 25
for i, (t1, t2) in enumerate(lifecycle):
    x = 62 + i * (lw + lgap)
    s.append(box(x, ly + 48, lw, 72, fill='#ffffff', edge=C_LINE, r=6))
    s.append(txt(x + lw / 2, ly + 74, t1, size=14, weight='bold'))
    s.append(txt(x + lw / 2, ly + 98, t2, size=12, color=C_SUB))
    if i < len(lifecycle) - 1:
        s.append(line(x + lw + 2, ly + 84, x + lw + lgap - 2, ly + 84, color=C_LINE))

s.append(txt(W / 2, H - 14, '图3-1  车企安全测试业务流程图', size=13, color=C_SUB))
s.append('</svg>')
(OUT / '图3-1_业务流程图.svg').write_text('\n'.join(s), encoding='utf-8')


# ============================================================================
# 图 4-1  系统总体架构图
# ============================================================================
W, H = 1080, 700
s = [HEAD(w=W, h=H, c=C_LINE)]

LX, LW = 60, 760
layers = [
    ('表示层', '#eaf2ff', '#2c7ef5', [
        '页面模板（Jinja2 服务端渲染，统一继承基础模板）',
        '设计系统（设计令牌 + 通用组件：按钮 / 徽章 / 卡片 / 表格 / 表单）',
        '交互组件（Bootstrap：表单控件、弹窗、下拉菜单）',
    ]),
    ('业务逻辑层', '#f0f7f2', '#2dbd74', [
        '蓝图路由：auth 认证 | main 业务流程 | vulnerabilities 漏洞 | projects 项目任务 | scans 安全扫描 | audit 审计',
        '横切模块：状态机（状态转换与校验）｜权限模块（权限矩阵与数据范围）｜标签模块（枚举映射）｜分析模块（看板聚合）',
        '服务层：风险评分｜SLA 计算｜漏洞编号｜审计写入｜级联删除',
    ]),
    ('数据访问层', '#fdf3e7', '#f5b14d', [
        'SQLAlchemy ORM（8 个实体模型，含索引定义）',
        'SQLite 数据库（sdl.db）｜文件存储（漏洞截图）',
    ]),
]
y = 70
for name, fill, edge, items in layers:
    hgt = 34 + len(items) * 40 + 14
    s.append(box(LX, y, LW, hgt, fill=fill, edge=edge, r=10, sw=2))
    s.append(txt(LX + 14, y + 24, name, size=15, weight='bold', anchor='start'))
    for i, it in enumerate(items):
        s.append(txt(LX + 30, y + 56 + i * 40, it, size=12.5, color=C_TEXT, anchor='start'))
    y += hgt + 26

# 右侧横切关注点
cx, cw = 860, 180
s.append(box(cx, 70, cw, y - 70 - 26, fill='#f8f9fb', edge='#c9d3e0', r=10, dash='6 4'))
s.append(txt(cx + cw / 2, 100, '横切关注点', size=14, weight='bold'))
for i, it in enumerate(['身份认证与会话', '（Flask-Login）', '', 'CSRF 防护', '（Flask-WTF）', '',
                        '审计日志', '（全操作留痕）', '', '权限校验', '（装饰器 + 数据范围）']):
    s.append(txt(cx + cw / 2, 128 + i * 22, it, size=12, color=C_SUB))

s.append(txt(W / 2, H - 16, '图4-1  系统总体架构图', size=13, color=C_SUB))
s.append('</svg>')
(OUT / '图4-1_系统架构图.svg').write_text('\n'.join(s), encoding='utf-8')


# ============================================================================
# 图 4-2  系统 ER 图
# ============================================================================
W, H = 1080, 820
s = [HEAD(w=W, h=H, c=C_LINE)]


def entity(x, y, w, title, fields, pk='id'):
    h = 34 + len(fields) * 20 + 10
    s.append(box(x, y, w, h, fill='#ffffff', edge=C_LINE, r=6, sw=1.6))
    s.append(f'<rect x="{x}" y="{y}" width="{w}" height="30" rx="6" ry="6" fill="#eaf2ff" stroke="{C_STATE_EDGE}" stroke-width="1.6"/>')
    s.append(f'<rect x="{x}" y="{y+20}" width="{w}" height="10" fill="#eaf2ff"/>')
    s.append(txt(x + w / 2, y + 21, title, size=13.5, weight='bold'))
    for i, f in enumerate(fields):
        tx = x + 12
        weight = 'bold' if f == pk else 'normal'
        s.append(txt(tx, y + 50 + i * 20, f, size=11.5, color=C_SUB, weight=weight, anchor='start'))
    return h


# 实体位置
h_user = entity(60, 60, 170, 'User 用户',
                ['id (PK)', 'username', 'password_hash', 'role', 'email'])
h_audit = entity(430, 60, 190, 'AuditLog 审计日志',
                 ['id (PK)', 'operator_id (FK)', 'resource_type', 'action', 'from_status / to_status', 'ip_address'])
h_proj = entity(60, 300, 170, 'Project 项目',
                ['id (PK)', 'name', 'owner_id (FK)', 'criticality', 'status'])
h_scan = entity(820, 60, 200, 'Scan 安全扫描',
                ['id (PK)', 'scan_code', 'scan_type', 'project_id (FK)', 'tool / target', 'total_findings'])
h_task = entity(60, 540, 170, 'Task 测试任务',
                ['id (PK)', 'name', 'project_id (FK)', 'tester_id (FK)', 'status'])
h_case = entity(60, 740, 170, 'TestCase 测试用例',
                ['id (PK)', 'task_id (FK)', 'case_number', 'status'])
h_vuln = entity(400, 480, 230, 'Vulnerability 漏洞',
                ['id (PK)', 'vuln_code', 'project_id / task_id', 'test_case_id (FK)', 'severity / risk_score', 'status', 'creator_id / assignee_id', 'due_date / fixed_at'])
h_find = entity(820, 400, 200, 'ScanFinding 扫描发现',
                ['id (PK)', 'scan_id (FK)', 'rule_id / severity', 'location', 'status', 'vulnerability_id (FK)'])

# 关系连线
s.append(line(145, 145, 145, 300, color=C_LINE))          # User -> Project
s.append(txt(152, 230, '1:N 负责', size=11.5, color=C_SUB, anchor='start'))
s.append(line(230, 100, 430, 100, color=C_LINE))          # User -> AuditLog
s.append(txt(330, 92, '1:N 操作', size=11.5, color=C_SUB))
s.append(line(145, 400, 145, 540, color=C_LINE))          # Project -> Task
s.append(txt(152, 478, '1:N 包含', size=11.5, color=C_SUB, anchor='start'))
s.append(line(145, 640, 145, 740, color=C_LINE))          # Task -> TestCase
s.append(txt(152, 698, '1:N 包含', size=11.5, color=C_SUB, anchor='start'))
s.append(line(230, 360, 400, 510, color=C_LINE))          # Project -> Vuln
s.append(txt(250, 430, '1:N', size=11.5, color=C_SUB, anchor='start'))
s.append(line(230, 580, 400, 570, color=C_LINE))          # Task -> Vuln
s.append(txt(290, 566, '1:N', size=11.5, color=C_SUB))
s.append(line(230, 780, 400, 620, color=C_LINE))          # TestCase -> Vuln
s.append(txt(268, 720, '1:N 产生', size=11.5, color=C_SUB, anchor='start'))
s.append(line(920, 170, 920, 400, color=C_LINE))          # Scan -> Finding
s.append(txt(928, 292, '1:N', size=11.5, color=C_SUB, anchor='start'))
s.append(line(820, 460, 630, 460, color=C_LINE))          # Finding -> Vuln
s.append(txt(725, 452, '0..1 转化', size=11.5, color=C_SUB))
s.append(line(215, 150, 400, 520, color='#98a2b3', dash='5 4'))  # User -> Vuln
s.append(txt(258, 300, '1:N 创建 / 指派', size=11.5, color=C_SUB, anchor='start'))

s.append(txt(W / 2, H - 16, '图4-2  系统实体关系（ER）图', size=13, color=C_SUB))
s.append('</svg>')
(OUT / '图4-2_ER图.svg').write_text('\n'.join(s), encoding='utf-8')


# ============================================================================
# 图 4-3  漏洞状态机转换图（论文最重要的一张）
# ============================================================================
W, H = 1000, 640
s = [HEAD(w=W, h=H, c=C_LINE)]

SW_, SH = 158, 54
A = (70, 80)      # 待修复
B = (378, 80)     # 已修复待复测
C = (758, 80)     # 已闭环
D = (300, 420)    # 误报
E = (600, 420)    # 已忽略
BW = {'A': 158, 'B': 200, 'C': 158, 'D': 140, 'E': 140}
B[0], BW['B'] = 378, 200


def state(x, y, w, label, sub, fill, edge):
    s.append(box(x, y, w, SH, fill=fill, edge=edge, r=27, sw=2))
    s.append(txt(x + w / 2, y + 24, label, size=15, weight='bold'))
    s.append(txt(x + w / 2, y + 43, sub, size=10.5, color=C_SUB))


state(*A, BW['A'], '待修复', 'pending', C_STATE_FILL, C_STATE_EDGE)
state(*B, BW['B'], '已修复待复测', 'fixed', C_STATE_FILL, C_STATE_EDGE)
state(*C, BW['C'], '已闭环', 'closed', '#e8f7ed', '#2dbd74')
state(*D, BW['D'], '误报', 'false_positive', C_TERM_FILL, C_TERM_EDGE)
state(*E, BW['E'], '已忽略', 'ignored', C_TERM_FILL, C_TERM_EDGE)

# 主链正向
s.append(line(A[0] + BW['A'] + 3, A[1] + 27, B[0] - 3, B[1] + 27, color=C_STATE_EDGE, sw=2))
s.append(txt(303, 96, '提交修复', size=12.5, weight='bold', color='#1f65d9'))
s.append(line(B[0] + BW['B'] + 3, B[1] + 27, C[0] - 3, C[1] + 27, color=C_STATE_EDGE, sw=2))
s.append(txt(668, 96, '复测通过', size=12.5, weight='bold', color='#1d8a57'))

# 复测不通过：从 B 上方绕回 A
s.append(path(f'M {B[0]+20} {B[1]-2} L {B[0]+20} 34 L {A[0]+BW["A"]/2} 34 L {A[0]+BW["A"]/2} {A[1]-3}',
              color='#f15d5d', sw=2))
s.append(txt(300, 24, '复测不通过', size=12.5, weight='bold', color='#c0392b'))

# 终止分支总线：从 A、B 底部引出
BUS_Y = 268
s.append(line(A[0] + 40, A[1] + SH + 2, A[0] + 40, BUS_Y, color=C_TERM_EDGE, sw=1.5, marker=False))
s.append(line(B[0] + BW['B'] / 2, B[1] + SH + 2, B[0] + BW['B'] / 2, BUS_Y, color=C_TERM_EDGE, sw=1.5, marker=False))
s.append(line(A[0] + 40, BUS_Y, E[0] + BW['E'] / 2, BUS_Y, color=C_TERM_EDGE, sw=1.5, marker=False))
s.append(txt(120, BUS_Y - 8, '待修复 / 已修复待复测', size=11, color=C_SUB, anchor='start'))

s.append(path(f'M {D[0]+BW["D"]/2} {BUS_Y} L {D[0]+BW["D"]/2} {D[1]-3}', color=C_TERM_EDGE, sw=1.6))
s.append(txt(D[0] + BW['D'] / 2 + 12, 350, '判定误报', size=12, weight='bold', color=C_TEXT))
s.append(txt(D[0] + BW['D'] / 2 + 12, 366, '（测试 / 主管 / 管理员）', size=10, color=C_SUB))

s.append(path(f'M {E[0]+BW["E"]/2} {BUS_Y} L {E[0]+BW["E"]/2} {E[1]-3}', color=C_TERM_EDGE, sw=1.6))
s.append(txt(E[0] + BW['E'] / 2 + 12, 350, '风险接受', size=12, weight='bold', color=C_TEXT))
s.append(txt(E[0] + BW['E'] / 2 + 12, 366, '（业务 / 主管 / 管理员）', size=10, color=C_SUB))

# 重新打开：三个终止态汇聚回 A
RET_Y = 540
RET_X = 36
s.append(line(D[0] + BW['D'] / 2, D[1] + SH + 2, D[0] + BW['D'] / 2, RET_Y, color='#f5b14d', sw=1.6, marker=False))
s.append(line(E[0] + BW['E'] / 2, E[1] + SH + 2, E[0] + BW['E'] / 2, RET_Y, color='#f5b14d', sw=1.6, marker=False))
s.append(line(C[0] + BW['C'] / 2, C[1] + SH + 2, C[0] + BW['C'] / 2, RET_Y, color='#f5b14d', sw=1.6, marker=False))
s.append(line(RET_X, RET_Y, E[0] + BW['E'] / 2, RET_Y, color='#f5b14d', sw=1.6, marker=False))
s.append(path(f'M {RET_X} {RET_Y} L {RET_X} {A[1]+27} L {A[0]-3} {A[1]+27}', color='#f5b14d', sw=1.8))
s.append(txt(430, RET_Y - 10, '重新打开（主管 / 管理员）', size=12, weight='bold', color='#b06a00'))

# 图例
s.append(box(700, 540, 270, 66, fill='#fbfcfe', edge='#c9d3e0', r=6, dash='5 4'))
s.append(txt(714, 562, '主链：待修复 → 已修复待复测 → 已闭环', size=11, color=C_TEXT, anchor='start'))
s.append(txt(714, 580, '终止分支：误报 / 已忽略', size=11, color=C_TEXT, anchor='start'))
s.append(txt(714, 598, '回退：三个终止态均可重新打开', size=11, color=C_TEXT, anchor='start'))

s.append(txt(W / 2, H - 12, '图4-3  漏洞状态机转换图', size=13, color=C_SUB))
s.append('</svg>')
(OUT / '图4-3_状态机转换图.svg').write_text('\n'.join(s), encoding='utf-8')

print('已生成 4 张 SVG：')
for f in sorted(OUT.glob('*.svg')):
    print('  ', f.name, f.stat().st_size, 'bytes')
