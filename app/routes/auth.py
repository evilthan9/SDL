from flask import Blueprint, render_template, redirect, url_for, flash, request, abort
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import or_
from app import db
from app.models import AuditLog, Project, Task, User, Vulnerability
from app.forms import (
    ChangePasswordForm, LoginForm, ProfileForm, RegistrationForm,
    ResetPasswordForm,
)
from app.permissions import (
    ALL_ROLES, PERM_USER_MANAGE, ROLE_ADMIN, ROLE_LABELS, can_access_testing,
    has_perm, is_admin,
)
from app.services import log_audit, safe_next_url

bp = Blueprint('auth', __name__, url_prefix='/auth')


def _home_for_user(user):
    if is_admin(user):
        return url_for('main.index')
    if can_access_testing(user):
        return url_for('projects.list')
    return url_for('main.business', stage='requirement')

@bp.route('/register', methods=['GET', 'POST'])
def register():
    # 已登录的非管理员直接回首页;管理员保留注册页以便创建测试/业务账号
    if current_user.is_authenticated and not is_admin(current_user):
        return redirect(_home_for_user(current_user))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        # 注册一律创建访客(guest),权限由管理员在“用户权限”里分配
        user = User(
            username=form.username.data,
            email=form.email.data,
            password_hash=hashed_password,
            role='guest'
        )
        db.session.add(user)
        db.session.commit()
        flash(f'用户 {form.username.data} 注册成功（默认访客，可在用户权限中分配角色）！', 'success')
        if is_admin(current_user):
            return redirect(url_for('auth.users'))
        return redirect(url_for('auth.login'))

    return render_template('register.html', form=form)

ASSIGNABLE_ROLES = ALL_ROLES


@bp.route('/users', methods=['GET', 'POST'])
@login_required
def users():
    """用户权限管理:给已注册用户分配/调整角色。"""
    if not has_perm(current_user, PERM_USER_MANAGE):
        abort(403)

    if request.method == 'POST':
        changed = 0
        admin_count = User.query.filter_by(role=ROLE_ADMIN).count()
        for key, value in request.form.items():
            if not key.startswith('role_'):
                continue
            try:
                uid = int(key[len('role_'):])
            except ValueError:
                continue
            if value not in ASSIGNABLE_ROLES or uid == current_user.id:
                continue
            target = User.query.get(uid)
            if not target or target.role == value:
                continue
            # 防止取消最后一个管理员导致系统无管理员
            if target.role == ROLE_ADMIN and admin_count <= 1:
                flash('系统至少需要保留一名管理员', 'warning')
                continue

            old_role = target.role
            target.role = value
            changed += 1
            # 权限变更必须留痕:这是「数据审计追溯」里最该被审计的一类操作。
            # 原实现完全没写审计,而审计页却有"用户"这个筛选项,永远查不到结果。
            log_audit(
                operator_id=current_user.id,
                resource_type='user',
                resource_id=target.id,
                action='user_role_change',
                from_status=old_role,
                to_status=value,
                detail=f'调整用户「{target.username}」角色：'
                       f'{ROLE_LABELS.get(old_role, old_role)} → {ROLE_LABELS.get(value, value)}'
            )
        db.session.commit()
        flash(f'已更新 {changed} 个用户的权限', 'success')
        return redirect(url_for('auth.users'))

    # 搜索:用户名/邮箱关键字 + 角色过滤
    keyword = request.args.get('keyword', '').strip()
    role = request.args.get('role', '').strip()
    query = User.query
    if keyword:
        like = f'%{keyword}%'
        query = query.filter(or_(User.username.ilike(like), User.email.ilike(like)))
    if role in ASSIGNABLE_ROLES:
        query = query.filter(User.role == role)
    user_list = query.order_by(User.id.asc()).all()
    admin_count = User.query.filter_by(role=ROLE_ADMIN).count()
    return render_template(
        'auth/users.html',
        users=user_list,
        roles=ASSIGNABLE_ROLES,
        role_labels=ROLE_LABELS,
        admin_count=admin_count,
        filters={'keyword': keyword, 'role': role},
        title='用户权限管理'
    )


@bp.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    """删除已注册用户(先解除其在漏洞/任务/项目/日志中的引用)。"""
    if not has_perm(current_user, PERM_USER_MANAGE):
        abort(403)

    target = User.query.get_or_404(user_id)
    if target.id == current_user.id:
        flash('不能删除当前登录账号', 'warning')
        return redirect(url_for('auth.users'))
    if target.role == ROLE_ADMIN and User.query.filter_by(role=ROLE_ADMIN).count() <= 1:
        flash('系统至少需要保留一名管理员，不能删除', 'warning')
        return redirect(url_for('auth.users'))

    uid = target.id
    username = target.username
    role_label = ROLE_LABELS.get(target.role, target.role)
    Vulnerability.query.filter_by(creator_id=uid).update({'creator_id': None}, synchronize_session=False)
    Vulnerability.query.filter_by(assignee_id=uid).update({'assignee_id': None}, synchronize_session=False)
    Task.query.filter_by(creator_id=uid).update({'creator_id': None}, synchronize_session=False)
    Task.query.filter_by(tester_id=uid).update({'tester_id': None}, synchronize_session=False)
    Project.query.filter_by(owner_id=uid).update({'owner_id': None}, synchronize_session=False)
    AuditLog.query.filter_by(operator_id=uid).update({'operator_id': None}, synchronize_session=False)
    db.session.delete(target)

    # 删用户是最该留痕的操作之一。注意要在 delete 之后、commit 之前写:
    # 上面刚把该用户自己的审计记录 operator_id 置空,这里记的是**操作者**的 id,
    # 不受影响。
    log_audit(
        operator_id=current_user.id,
        resource_type='user',
        resource_id=uid,
        action='user_delete',
        detail=f'删除用户「{username}」（原角色：{role_label}）'
    )
    db.session.commit()
    flash(f'用户“{username}”已删除', 'success')
    return redirect(url_for('auth.users'))


@bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """个人资料。

    用户名不可改:它是登录凭据,而且被审计日志和诸多外键引用。
    """
    form = ProfileForm(obj=current_user)
    if form.validate_on_submit():
        old_email = current_user.email
        current_user.email = form.email.data
        log_audit(
            operator_id=current_user.id,
            resource_type='user',
            resource_id=current_user.id,
            action='user_profile_update',
            detail=f'更新个人资料：邮箱 {old_email or "—"} → {current_user.email}'
        )
        db.session.commit()
        flash('个人资料已保存', 'success')
        return redirect(url_for('auth.profile'))

    return render_template('auth/profile.html', form=form,
                           password_form=ChangePasswordForm(), title='个人资料')


@bp.route('/password', methods=['GET', 'POST'])
@login_required
def change_password():
    """修改自己的密码。

    改造前全站没有任何改密入口 —— 忘了密码只能直接改数据库。
    """
    form = ChangePasswordForm()
    if form.validate_on_submit():
        current_user.password_hash = generate_password_hash(form.new_password.data)
        log_audit(
            operator_id=current_user.id,
            resource_type='user',
            resource_id=current_user.id,
            action='user_password_change',
            detail=f'用户「{current_user.username}」修改了登录密码'
        )
        db.session.commit()
        # 刻意不注销会话：用户名和 id 都没变，Flask-Login 的会话仍然有效，
        # 强制重新登录只会让人觉得"改完密码就被踢了"。
        flash('密码已修改，请牢记新密码', 'success')
        return redirect(url_for('auth.profile'))

    return render_template('auth/profile.html', form=ProfileForm(obj=current_user),
                           password_form=form, title='修改密码')


@bp.route('/users/<int:user_id>/reset-password', methods=['POST'])
@login_required
def reset_password(user_id):
    """管理员重置他人密码。

    这是"忘了密码"唯一的补救途径 —— 在此之前只能直接改数据库。
    """
    if not has_perm(current_user, PERM_USER_MANAGE):
        abort(403)

    target = User.query.get_or_404(user_id)
    form = ResetPasswordForm()
    if not form.validate_on_submit():
        flash('新密码不符合要求（至少 6 位）', 'danger')
        return redirect(url_for('auth.users'))

    target.password_hash = generate_password_hash(form.new_password.data)
    log_audit(
        operator_id=current_user.id,
        resource_type='user',
        resource_id=target.id,
        action='user_password_reset',
        detail=f'管理员重置了用户「{target.username}」的密码'
    )
    db.session.commit()
    flash(f'用户「{target.username}」的密码已重置', 'success')
    return redirect(url_for('auth.users'))


@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(_home_for_user(current_user))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = safe_next_url(request.args.get('next'))
            flash(f'欢迎回来，{user.username}！', 'success')
            if next_page:
                return redirect(next_page)
            return redirect(_home_for_user(user))
        else:
            flash('用户名或密码错误', 'danger')
    
    return render_template('login.html', form=form)

@bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('您已退出登录', 'info')
    return redirect(url_for('auth.login'))