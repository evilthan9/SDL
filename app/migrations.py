"""轻量级 schema 迁移。

项目用 SQLite + ``db.create_all()``,没有引入 Alembic。``create_all()`` 只建新表,
不会给**已存在**的表补列,所以历史上新增的列需要在这里显式声明、启动时补齐。

对已存在的列无操作,因此可重复执行(幂等)。新增列时在 ``_ADDED_COLUMNS`` 里加一行即可。
"""
from sqlalchemy import inspect, text

from app import db


# 表名 -> [(列名, 列类型)]。都是 create_all() 补不到旧表上的"后加列"。
_ADDED_COLUMNS = {
    'tasks': [
        ('creator_id', 'INTEGER'),
        ('submission_status', 'VARCHAR(20)'),
        ('assets', 'TEXT'),
        ('expected_release_date', 'DATETIME'),
        ('manual_test_start', 'DATETIME'),
        ('manual_test_end', 'DATETIME'),
    ],
    'projects': [
        ('security_test_required', 'BOOLEAN'),
        ('requirements_pushed', 'BOOLEAN'),
        ('questionnaire_completed', 'BOOLEAN'),
    ],
    'vulnerabilities': [
        ('test_case_id', 'INTEGER'),
        ('vuln_type', 'VARCHAR(30)'),
        ('screenshots', 'TEXT'),
    ],
}

# 表名 -> [(索引名, 列名)]。与 models.py 里 index=True 生成的默认索引名保持一致
# (SQLAlchemy 的命名规则是 ix_<表>_<列>),避免新库重复建索引。
_ADDED_INDEXES = {
    'vulnerabilities': [
        ('ix_vulnerabilities_project_id', 'project_id'),
        ('ix_vulnerabilities_task_id', 'task_id'),
        ('ix_vulnerabilities_status', 'status'),
        ('ix_vulnerabilities_severity', 'severity'),
        ('ix_vulnerabilities_creator_id', 'creator_id'),
        ('ix_vulnerabilities_assignee_id', 'assignee_id'),
        ('ix_vulnerabilities_is_deleted', 'is_deleted'),
        ('ix_vulnerabilities_created_at', 'created_at'),
    ],
    'audit_logs': [
        ('ix_audit_logs_created_at', 'created_at'),
        ('ix_audit_logs_operator_id', 'operator_id'),
        ('ix_audit_logs_resource_type', 'resource_type'),
    ],
    'tasks': [
        ('ix_tasks_project_id', 'project_id'),
        ('ix_tasks_tester_id', 'tester_id'),
    ],
    'test_cases': [
        ('ix_test_cases_task_id', 'task_id'),
    ],
}


def run_migrations():
    """为已存在的表补齐缺失列与缺失索引。应在 db.create_all() 之前调用。"""
    inspector = inspect(db.engine)
    changed = False

    for table, columns in _ADDED_COLUMNS.items():
        if not inspector.has_table(table):
            continue  # 新库交给 create_all() 建全
        existing = {column['name'] for column in inspector.get_columns(table)}
        for name, column_type in columns:
            if name not in existing:
                db.session.execute(text(f'ALTER TABLE {table} ADD COLUMN {name} {column_type}'))
                changed = True

    for table, indexes in _ADDED_INDEXES.items():
        if not inspector.has_table(table):
            continue
        existing = {index['name'] for index in inspector.get_indexes(table)}
        for index_name, column_name in indexes:
            if index_name not in existing:
                db.session.execute(text(
                    f'CREATE INDEX IF NOT EXISTS {index_name} ON {table} ({column_name})'
                ))
                changed = True

    if changed:
        db.session.commit()
