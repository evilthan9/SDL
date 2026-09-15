from app import create_app, db
from app.models import Task, TestCase, User, Vulnerability
from werkzeug.security import generate_password_hash

app = create_app()
app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
with app.app_context():
    User.query.filter(User.username.like('__delete_%')).delete(synchronize_session=False)
    db.session.commit()
    admin = User(username='__delete_admin__', email='delete-admin@example.com', password_hash=generate_password_hash('x'), role='admin')
    tester = User(username='__delete_tester__', email='delete-tester@example.com', password_hash=generate_password_hash('x'), role='tester')
    db.session.add_all([admin, tester])
    db.session.commit()
    task = Task(name='__delete_task__', creator_id=admin.id, tester_id=tester.id, status='scheduled')
    db.session.add(task)
    db.session.commit()
    case = TestCase(task_id=task.id, case_number=1, name='__delete_case__')
    vulnerability = Vulnerability(task_id=task.id, title='__delete_vulnerability__', creator_id=tester.id, status='pending', is_deleted=False)
    db.session.add_all([case, vulnerability])
    db.session.commit()
    task_id = task.id

admin_client = app.test_client()
admin_client.post('/auth/login', data={'username': '__delete_admin__', 'password': 'x'})
list_body = admin_client.get('/projects/').get_data(as_text=True)
delete_response = admin_client.post('/projects/task/%s/delete' % task_id, follow_redirects=False)
with app.app_context():
    deleted_task = Task.query.get(task_id)
    deleted_case = TestCase.query.filter_by(task_id=task_id).first()
    deleted_vulnerability = Vulnerability.query.filter_by(title='__delete_vulnerability__').first()
print('admin_delete_button=', '删除' in list_body)
print('delete_redirect=', delete_response.status_code == 302)
print('task_deleted=', deleted_task is None)
print('case_deleted=', deleted_case is None)
print('vulnerability_soft_deleted=', deleted_vulnerability is not None and deleted_vulnerability.is_deleted)

with app.app_context():
    task = Task(name='__delete_forbidden_task__', creator_id=admin.id, status='scheduled')
    db.session.add(task)
    db.session.commit()
    forbidden_task_id = task.id

tester_client = app.test_client()
tester_client.post('/auth/login', data={'username': '__delete_tester__', 'password': 'x'})
forbidden = tester_client.post('/projects/task/%s/delete' % forbidden_task_id)
print('tester_forbidden=', forbidden.status_code == 403)

with app.app_context():
    Task.query.filter_by(id=forbidden_task_id).delete(synchronize_session=False)
    User.query.filter(User.username.like('__delete_%')).delete(synchronize_session=False)
    db.session.commit()
