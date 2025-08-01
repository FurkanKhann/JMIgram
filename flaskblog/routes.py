import os
import secrets
from PIL import Image
from flask import render_template, url_for, flash, redirect, request, abort, jsonify
from flaskblog import app, db, bcrypt, mail
from flaskblog.forms import (RegistrationForm, LoginForm, UpdateAccountForm,
                             PostForm, RequestResetForm, ResetPasswordForm, UserRoleForm, EmptyForm)
from flaskblog.models import User, Post, Like, Comment, Notification
from flask_login import login_user, current_user, logout_user, login_required
from flask_mail import Message
import google.generativeai as genai
from dotenv import load_dotenv
from sqlalchemy import or_, and_

# Load environment variables
load_dotenv()

# Configure Gemini with your API key
genai.configure(api_key=os.getenv('API_KEY'))
model = genai.GenerativeModel("gemini-2.5-flash")

# =====================================
# UTILITY FUNCTIONS
# =====================================

def save_picture(form_picture):
    """Save profile picture and return filename"""
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/profile_pic', picture_fn)

    output_size = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)
    return picture_fn

def save_post_image(form_image):
    """Save uploaded post image and return filename"""
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_image.filename)
    image_filename = random_hex + f_ext
    image_path = os.path.join(app.root_path, 'static/post_images', image_filename)
    
    os.makedirs(os.path.dirname(image_path), exist_ok=True)
    
    output_size = (800, 600)
    img = Image.open(form_image)
    img.thumbnail(output_size)
    img.save(image_path)
    return image_filename

def create_notification(user_id, notification_type, message, related_post_id=None, related_user_id=None):
    """Create a new notification"""
    notification = Notification(
        user_id=user_id,
        type=notification_type,
        message=message,
        related_post_id=related_post_id,
        related_user_id=related_user_id
    )
    db.session.add(notification)
    db.session.commit()

def send_verification_email(user):
    """Send email verification email"""
    token = user.generate_verification_token()
    msg = Message(
        'Verify Your Email - JMIgram',
        sender='noreply@jmigram.com',
        recipients=[user.email]
    )
    msg.body = f'''Welcome to JMIgram!

Please click the following link to verify your email address and activate your account:
{url_for('verify_email', token=token, _external=True)}

This link will expire in 1 hour.

If you did not create this account, please ignore this email.

Best regards,
JMIgram Team
'''
    msg.html = f'''
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #bbe741;">Welcome to JMIgram!</h2>
        <p>Thank you for signing up. Please verify your email address to activate your account.</p>
        <div style="text-align: center; margin: 30px 0;">
            <a href="{url_for('verify_email', token=token, _external=True)}" 
               style="background-color: #bbe741; color: black; padding: 12px 30px; text-decoration: none; border-radius: 5px; font-weight: bold;">
               Verify Email Address
            </a>
        </div>
        <p><strong>Note:</strong> This link will expire in 1 hour.</p>
        <p>If you did not create this account, please ignore this email.</p>
        <hr>
        <p style="color: #666; font-size: 12px;">JMIgram Team</p>
    </div>
    '''
    mail.send(msg)

def send_reset_email(user):
    """Send password reset email"""
    token = user.get_reset_token()
    msg = Message(
        'Password Reset Request',
        sender='noreply@demo.com',
        recipients=[user.email]
    )
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}

If you did not make this request, simply ignore this email.
'''
    mail.send(msg)

# =====================================
# MIDDLEWARE & BEFORE REQUEST HANDLERS
# =====================================

@app.before_request
def check_email_verification():
    """Check if user has verified their email before accessing protected routes"""
    if (current_user.is_authenticated and 
        not current_user.email_verified and 
        request.endpoint not in ['verify_email', 'resend_verification', 'logout', 'static', 'verify_email_prompt']):
        flash('Please verify your email address to access this feature.', 'warning')
        return redirect(url_for('verify_email_prompt'))

# =====================================
# MAIN PAGE ROUTES
# =====================================

@app.route("/")
@app.route("/home")
@login_required
def home():
    form = EmptyForm()
    page = request.args.get('page', 1, type=int)
    
    if current_user.is_authenticated and (current_user.is_admin or current_user.role == 'Police'):
        posts = Post.query.order_by(Post.date_posted.desc()).paginate(page=page, per_page=5)
    else:
        posts = Post.query.filter_by(is_under_review=False).order_by(Post.date_posted.desc()).paginate(page=page, per_page=5)
    
    return render_template('home.html', posts=posts, form=form)

# =====================================
# AUTHENTICATION ROUTES
# =====================================

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(
            username=form.username.data, 
            email=form.email.data, 
            password=hashed_password,
            email_verified=False
        )
        db.session.add(user)
        db.session.commit()
        
        try:
            send_verification_email(user)
            flash(f'Account created! Please check your email ({user.email}) to verify your account before logging in.', 'info')
        except Exception as e:
            flash('Account created but verification email could not be sent. Please contact support.', 'warning')
            
        return redirect(url_for('login'))
    
    return render_template('register.html', title='Register', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            if not user.email_verified:
                flash('Please verify your email address before logging in. Check your inbox or request a new verification email.', 'warning')
                return redirect(url_for('resend_verification'))
            
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    
    return render_template('login.html', title='Login', form=form)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))

# =====================================
# EMAIL VERIFICATION ROUTES
# =====================================

@app.route("/verify_email/<token>")
def verify_email(token):
    """Verify email address using token"""
    if current_user.is_authenticated and current_user.email_verified:
        flash('Your email is already verified!', 'info')
        return redirect(url_for('home'))
    
    user = User.verify_email_token(token)
    if user is None:
        flash('Invalid or expired verification token. Please request a new one.', 'danger')
        return redirect(url_for('resend_verification'))
    
    user.email_verified = True
    user.verification_token = None
    user.token_created_at = None
    db.session.commit()
    
    flash('Email verified successfully! You can now log in and use all features.', 'success')
    return redirect(url_for('login'))

@app.route("/verify_email_prompt")
def verify_email_prompt():
    """Show page prompting user to verify email"""
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    
    if current_user.email_verified:
        return redirect(url_for('home'))
    
    return render_template('verify_email_prompt.html', title='Verify Email')

@app.route("/resend_verification", methods=['GET', 'POST'])
def resend_verification():
    """Resend verification email"""
    if current_user.is_authenticated and current_user.email_verified:
        flash('Your email is already verified!', 'info')
        return redirect(url_for('home'))
    
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if user.email_verified:
                flash('This email is already verified!', 'info')
            else:
                try:
                    send_verification_email(user)
                    flash('Verification email sent! Please check your inbox.', 'info')
                except Exception as e:
                    flash('Could not send verification email. Please try again later.', 'danger')
        else:
            flash('No account found with that email address.', 'danger')
        
        return redirect(url_for('login'))
    
    return render_template('resend_verification.html', title='Resend Verification', form=form)

# =====================================
# PASSWORD RESET ROUTES
# =====================================

@app.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('An email has been sent with instructions to reset your password.', 'info')
        return redirect(url_for('login'))
    
    return render_template('reset_request.html', title='Reset Password', form=form)

@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash('Your password has been updated! You are now able to log in', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_token.html', title='Reset Password', form=form)

# =====================================
# USER PROFILE & ACCOUNT ROUTES
# =====================================

@app.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            current_user.image_file = picture_file
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    
    image_file = url_for('static', filename='profile_pic/' + current_user.image_file)
    return render_template('account.html', title='Account', image_file=image_file, form=form)

@app.route("/user/<string:username>")
def user_posts(username):
    page = request.args.get('page', 1, type=int)
    user = User.query.filter_by(username=username).first_or_404()
    posts = Post.query.filter_by(author=user).order_by(Post.date_posted.desc()).paginate(page=page, per_page=5)
    return render_template('user_posts.html', posts=posts, user=user)

# =====================================
# POST MANAGEMENT ROUTES
# =====================================

@app.route("/post/new", methods=['GET', 'POST'])
@login_required
def new_post():
    form = PostForm()
    if form.validate_on_submit():
        image_file = None
        if form.image.data:
            image_file = save_post_image(form.image.data)
        
        post = Post(
            title=form.title.data, 
            content=form.content.data,
            image_file=image_file,
            author=current_user
        )
        db.session.add(post)
        db.session.commit()
        flash('Post created!', 'success')
        return redirect(url_for('home'))
    
    return render_template('create_post.html', title='New Post', form=form, legend='New Post')

@app.route("/post/<int:post_id>")
def post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.is_under_review and not (current_user.is_authenticated and (current_user.is_admin or current_user.role == 'Police')):
        abort(404)
    
    form = EmptyForm()
    return render_template('post.html', title=post.title, post=post, form=form)

@app.route("/post/<int:post_id>/update", methods=['GET', 'POST'])
@login_required
def update_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    
    form = PostForm()
    if form.validate_on_submit():
        post.title = form.title.data
        post.content = form.content.data
        db.session.commit()
        flash('Post updated successfully!', 'success')
        return redirect(url_for('post', post_id=post.id))
    elif request.method == 'GET':
        form.title.data = post.title
        form.content.data = post.content
    
    return render_template('create_post.html', title='Update Post', form=form, legend='Update Post')

@app.route("/post/<int:post_id>/delete", methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    
    if (post.author != current_user and 
        not current_user.is_admin and 
        current_user.role not in ['Police']):
        abort(403)
    
    post_title = post.title
    post_author_id = post.author.id
    post_author = post.author.username
    
    # Create notification for post author (if deleted by someone else)
    if post.author != current_user:
        role_name = "Admin" if current_user.is_admin else current_user.role
        create_notification(
            user_id=post_author_id,
            notification_type='post_deleted',
            message=f"Your post '{post_title}' has been deleted by {role_name}",
            related_user_id=current_user.id
        )
    
    db.session.delete(post)
    db.session.commit()
    
    if post_author_id == current_user.id:
        flash('Your post has been deleted!', 'success')
    else:
        flash(f'Post "{post_title}" by {post_author} has been deleted by {current_user.role}.', 'warning')
    
    return redirect(url_for('home'))

# =====================================
# LIKE & COMMENT INTERACTION ROUTES
# =====================================

@app.route("/like_post/<int:post_id>", methods=['POST'])
@login_required
def like_post(post_id):
    post = Post.query.get_or_404(post_id)
    existing_like = Like.query.filter_by(user_id=current_user.id, post_id=post_id).first()
    
    if existing_like:
        db.session.delete(existing_like)
        liked = False
    else:
        like = Like(user_id=current_user.id, post_id=post_id)
        db.session.add(like)
        liked = True
        
        # Create notification for post author (only if someone else liked their post)
        if post.author != current_user:
            create_notification(
                user_id=post.author.id,
                notification_type='like',
                message=f"{current_user.username} liked your post '{post.title}'",
                related_post_id=post_id,
                related_user_id=current_user.id
            )
    
    db.session.commit()
    return jsonify({'liked': liked, 'like_count': post.get_like_count()})

@app.route("/add_comment/<int:post_id>", methods=['POST'])
@login_required
def add_comment(post_id):
    post = Post.query.get_or_404(post_id)
    content = request.form.get('comment_content')
    
    if content:
        comment = Comment(content=content, user_id=current_user.id, post_id=post_id)
        db.session.add(comment)
        
        # Create notification for post author (only if someone else commented)
        if post.author != current_user:
            create_notification(
                user_id=post.author.id,
                notification_type='comment',
                message=f"{current_user.username} commented on your post '{post.title}': {content[:50]}{'...' if len(content) > 50 else ''}",
                related_post_id=post_id,
                related_user_id=current_user.id
            )
        
        db.session.commit()
        flash('Comment added successfully!', 'success')
    
    return redirect(url_for('post', post_id=post_id))

@app.route("/delete_comment/<int:comment_id>", methods=['POST'])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    
    # Strict permission check - only allow:
    # 1. Comment author can delete their own comment
    # 2. Post author can delete comments on their post
    # 3. Admin can delete any comment
    # 4. Police can delete any comment (but NOT Reviewers for comments)
    
    if not (comment.author == current_user or 
            comment.post.author == current_user or 
            current_user.is_admin or 
            current_user.role == 'Police'):
        abort(403)
    
    post_id = comment.post_id
    db.session.delete(comment)
    db.session.commit()
    
    flash('Comment deleted successfully!', 'success')
    return redirect(url_for('post', post_id=post_id))

# =====================================
# NOTIFICATION SYSTEM ROUTES
# =====================================

@app.route("/notifications")
@login_required
def notifications():
    """View all notifications for current user"""
    page = request.args.get('page', 1, type=int)
    notifications = Notification.query.filter_by(user_id=current_user.id)\
        .order_by(Notification.created_at.desc())\
        .paginate(page=page, per_page=20)
    
    # Mark all notifications as read when user views them
    Notification.query.filter_by(user_id=current_user.id, is_read=False).update({'is_read': True})
    db.session.commit()
    
    form = EmptyForm()
    return render_template('notifications.html', notifications=notifications, form=form, title='Notifications')

@app.route("/notifications/unread_count")
@login_required
def unread_notifications_count():
    """Get count of unread notifications (for AJAX)"""
    count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    return jsonify({'unread_count': count})

@app.route("/notifications/mark_read/<int:notification_id>", methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    """Mark specific notification as read"""
    notification = Notification.query.get_or_404(notification_id)
    if notification.user_id != current_user.id:
        abort(403)
    
    notification.is_read = True
    db.session.commit()
    return jsonify({'success': True})

@app.route("/notifications/delete/<int:notification_id>", methods=['POST'])
@login_required
def delete_notification(notification_id):
    """Delete specific notification"""
    notification = Notification.query.get_or_404(notification_id)
    if notification.user_id != current_user.id:
        abort(403)
    
    db.session.delete(notification)
    db.session.commit()
    flash('Notification deleted!', 'success')
    return redirect(url_for('notifications'))

# =====================================
# SEARCH & DISCOVERY ROUTES
# =====================================

@app.route("/search")
def search():
    query = request.args.get('q', '')
    page = request.args.get('page', 1, type=int)
    
    if not query:
        return render_template('search.html', query='', users=[], posts=[], total_results=0)
    
    # Search users
    users = User.query.filter(
        or_(
            User.username.ilike(f'%{query}%'),
            User.email.ilike(f'%{query}%')
        )
    ).limit(10).all()
    
    # Search posts (exclude posts under review for non-privileged users)
    if current_user.is_authenticated and (current_user.is_admin or current_user.role == 'Police'):
        posts = Post.query.filter(
            or_(
                Post.title.ilike(f'%{query}%'),
                Post.content.ilike(f'%{query}%')
            )
        ).order_by(Post.date_posted.desc()).paginate(page=page, per_page=10)
    else:
        posts = Post.query.filter(
            and_(
                Post.is_under_review == False,
                or_(
                    Post.title.ilike(f'%{query}%'),
                    Post.content.ilike(f'%{query}%')
                )
            )
        ).order_by(Post.date_posted.desc()).paginate(page=page, per_page=10)
    
    total_results = len(users) + posts.total
    form = EmptyForm()
    
    return render_template('search.html', query=query, users=users, posts=posts, 
                         total_results=total_results, form=form)

@app.route("/search/ajax")
def search_ajax():
    """AJAX endpoint for real-time search suggestions"""
    query = request.args.get('q', '')
    
    if len(query) < 2:
        return jsonify({'users': [], 'posts': []})
    
    # Search users (limit to 5 for suggestions)
    users = User.query.filter(
        or_(
            User.username.ilike(f'%{query}%'),
            User.email.ilike(f'%{query}%')
        )
    ).limit(5).all()
    
    # Search posts (limit to 5 for suggestions)
    if current_user.is_authenticated and (current_user.is_admin or current_user.role == 'Police'):
        posts = Post.query.filter(
            or_(
                Post.title.ilike(f'%{query}%'),
                Post.content.ilike(f'%{query}%')
            )
        ).order_by(Post.date_posted.desc()).limit(5).all()
    else:
        posts = Post.query.filter(
            and_(
                Post.is_under_review == False,
                or_(
                    Post.title.ilike(f'%{query}%'),
                    Post.content.ilike(f'%{query}%')
                )
            )
        ).order_by(Post.date_posted.desc()).limit(5).all()
    
    return jsonify({
        'users': [{'id': u.id, 'username': u.username, 'image_file': u.image_file} for u in users],
        'posts': [{'id': p.id, 'title': p.title, 'author': p.author.username} for p in posts]
    })

# =====================================
# CONTENT MODERATION ROUTES
# =====================================

@app.route("/mark_for_review/<int:post_id>", methods=['POST'])
@login_required
def mark_for_review(post_id):
    post = Post.query.get_or_404(post_id)
    if current_user.role != 'Reviewer':
        abort(403)
    
    post.is_under_review = True
    
    # Create notification for post author
    create_notification(
        user_id=post.author.id,
        notification_type='post_marked',
        message=f"Your post '{post.title}' has been marked for review by a moderator",
        related_post_id=post_id,
        related_user_id=current_user.id
    )
    
    db.session.commit()
    flash("Post marked for review!", "info")
    return redirect(request.referrer or url_for('home'))

@app.route("/unmark_for_review/<int:post_id>", methods=['POST'])
@login_required
def unmark_for_review(post_id):
    post = Post.query.get_or_404(post_id)
    if not (current_user.is_admin or current_user.role == 'Police'):
        abort(403)
    
    post.is_under_review = False
    
    # Create notification for post author
    role_name = "Admin" if current_user.is_admin else current_user.role
    create_notification(
        user_id=post.author.id,
        notification_type='post_approved',
        message=f"Your post '{post.title}' has been reviewed and approved by {role_name}. It is now visible to all users.",
        related_post_id=post_id,
        related_user_id=current_user.id
    )
    
    db.session.commit()
    flash("Post has been reviewed and is now visible!", "success")
    return redirect(request.referrer or url_for('home'))

# =====================================
# ADMIN & USER MANAGEMENT ROUTES
# =====================================

@app.route("/admin/users", methods=['GET'])
@login_required
def admin_users():
    if not current_user.is_admin:
        abort(403)
    
    page = request.args.get('page', 1, type=int)
    users = User.query.paginate(page=page, per_page=10)
    return render_template('admin_users.html', title='Manage Users', users=users)

@app.route("/admin/user/<int:user_id>/role", methods=['GET', 'POST'])
@login_required
def update_user_role(user_id):
    if not current_user.is_admin:
        abort(403)
    
    user = User.query.get_or_404(user_id)
    
    if user == current_user:
        flash('You cannot change your own role!', 'warning')
        return redirect(url_for('admin_users'))
    
    form = UserRoleForm()
    
    if form.validate_on_submit():
        old_role = user.role
        user.role = form.role.data
        db.session.commit()
        flash(f'User {user.username} role updated from {old_role} to {user.role}!', 'success')
        return redirect(url_for('admin_users'))
    elif request.method == 'GET':
        form.role.data = user.role
    
    return render_template('update_user_role.html', title='Update User Role', 
                         form=form, user=user)

@app.route("/admin/user/<int:user_id>/toggle_admin", methods=['POST'])
@login_required
def toggle_admin_status(user_id):
    if not current_user.is_admin:
        abort(403)
    
    user = User.query.get_or_404(user_id)
    
    if user == current_user:
        flash('You cannot change your own admin status!', 'warning')
        return redirect(url_for('admin_users'))
    
    user.is_admin = not user.is_admin
    db.session.commit()
    
    status = "granted" if user.is_admin else "revoked"
    flash(f'Admin privileges {status} for user {user.username}!', 'success')
    
    return redirect(url_for('admin_users'))

@app.route("/admin/user/<int:user_id>/delete", methods=['POST'])
@login_required
def delete_user(user_id):
    """Delete a user account (Admin only)"""
    if not current_user.is_admin:
        abort(403)
    
    user = User.query.get_or_404(user_id)
    
    if user == current_user:
        flash('You cannot delete your own account!', 'danger')
        return redirect(url_for('admin_users'))
    
    username = user.username
    email = user.email
    posts_count = len(user.posts)
    
    try:
        db.session.delete(user)
        db.session.commit()
        
        flash(f'User "{username}" ({email}) has been permanently deleted along with {posts_count} posts and all related data.', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting user: {str(e)}', 'danger')
    
    return redirect(url_for('admin_users'))

@app.route("/admin/user/<int:user_id>/suspend", methods=['POST'])
@login_required  
def suspend_user(user_id):
    """Suspend/Unsuspend a user account (Alternative to deletion)"""
    if not current_user.is_admin:
        abort(403)
    
    user = User.query.get_or_404(user_id)
    
    if user == current_user:
        flash('You cannot suspend your own account!', 'warning')
        return redirect(url_for('admin_users'))
    
    flash('Suspension feature coming soon!', 'info')
    return redirect(url_for('admin_users'))
