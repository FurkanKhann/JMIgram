import os
import secrets
from PIL import Image
from flask import render_template, url_for, flash, redirect, request, abort, jsonify
from flaskblog import app, db, bcrypt, mail
from flaskblog.forms import (RegistrationForm, LoginForm, UpdateAccountForm,
                             PostForm, RequestResetForm, ResetPasswordForm, UserRoleForm, EmptyForm)
from flaskblog.models import User, Post, Like, Comment
from flask_login import login_user, current_user, logout_user, login_required
from flask_mail import Message
import google.generativeai as genai
from dotenv import load_dotenv
from sqlalchemy import or_, and_

# Load environment variables
load_dotenv()

# Configure Gemini with your API key
genai.configure(api_key=os.getenv('API_KEY'))

# Load the model
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
    
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(image_path), exist_ok=True)
    
    # Resize image to reasonable size
    output_size = (800, 600)
    img = Image.open(form_image)
    img.thumbnail(output_size)
    img.save(image_path)
    return image_filename

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
# HOME & BASIC PAGES
# =====================================

@app.route("/")
@app.route("/home")
@login_required
def home():
    form = EmptyForm()
    page = request.args.get('page', 1, type=int)
    
    if current_user.is_authenticated and (current_user.is_admin or current_user.role == 'Police'):
        # Police and Admin see all posts including under review
        posts = Post.query.order_by(Post.date_posted.desc()).paginate(page=page, per_page=5)
    else:
        # Regular users: exclude posts under review
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
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
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
# USER ACCOUNT ROUTES
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
    # Hide under-review post unless Police/Admin
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
    
    # Allow deletion if user is: author, admin, or Police role
    if (post.author != current_user and 
        not current_user.is_admin and 
        current_user.role not in ['Police']):
        abort(403)
    
    # Store post details for flash message
    post_title = post.title
    post_author = post.author.username
    
    db.session.delete(post)
    db.session.commit()
    
    # Different flash messages based on who deleted the post
    if post.author == current_user:
        flash('Your post has been deleted!', 'success')
    else:
        flash(f'Post "{post_title}" by {post_author} has been deleted by {current_user.role}.', 'warning')
    
    return redirect(url_for('home'))

# =====================================
# LIKE & COMMENT ROUTES
# =====================================

@app.route("/like_post/<int:post_id>", methods=['POST'])
@login_required
def like_post(post_id):
    post = Post.query.get_or_404(post_id)
    
    # Check if user already liked this post
    existing_like = Like.query.filter_by(user_id=current_user.id, post_id=post_id).first()
    
    if existing_like:
        # Unlike the post
        db.session.delete(existing_like)
        liked = False
    else:
        # Like the post
        like = Like(user_id=current_user.id, post_id=post_id)
        db.session.add(like)
        liked = True
    
    db.session.commit()
    
    return jsonify({
        'liked': liked,
        'like_count': post.get_like_count()
    })

@app.route("/add_comment/<int:post_id>", methods=['POST'])
@login_required
def add_comment(post_id):
    post = Post.query.get_or_404(post_id)
    content = request.form.get('comment_content')
    
    if content:
        comment = Comment(content=content, user_id=current_user.id, post_id=post_id)
        db.session.add(comment)
        db.session.commit()
        flash('Comment added successfully!', 'success')
    
    return redirect(url_for('post', post_id=post_id))

@app.route("/delete_comment/<int:comment_id>", methods=['POST'])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    
    # Allow deletion if user is: comment author, post author, admin, or Police/Reviewer
    if (comment.author != current_user and 
        comment.post.author != current_user and
        not current_user.is_admin and 
        current_user.role not in ['Police', 'Reviewer']):
        abort(403)
    
    post_id = comment.post_id
    db.session.delete(comment)
    db.session.commit()
    
    flash('Comment deleted successfully!', 'success')
    return redirect(url_for('post', post_id=post_id))

# =====================================
# SEARCH ROUTES
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
        # Police and Admin see all posts including under review
        posts = Post.query.filter(
            or_(
                Post.title.ilike(f'%{query}%'),
                Post.content.ilike(f'%{query}%')
            )
        ).order_by(Post.date_posted.desc()).paginate(page=page, per_page=10)
    else:
        # Regular users don't see posts under review
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
# ADMIN ROUTES
# =====================================

@app.route("/admin/users", methods=['GET'])
@login_required
def admin_users():
    # Check if current user is admin
    if not current_user.is_admin:
        abort(403)
    
    page = request.args.get('page', 1, type=int)
    users = User.query.paginate(page=page, per_page=10)
    return render_template('admin_users.html', title='Manage Users', users=users)

@app.route("/admin/user/<int:user_id>/role", methods=['GET', 'POST'])
@login_required
def update_user_role(user_id):
    # Check if current user is admin
    if not current_user.is_admin:
        abort(403)
    
    user = User.query.get_or_404(user_id)
    
    # Prevent admin from changing their own role
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
    # Check if current user is admin
    if not current_user.is_admin:
        abort(403)
    
    user = User.query.get_or_404(user_id)
    
    # Prevent admin from removing their own admin status
    if user == current_user:
        flash('You cannot change your own admin status!', 'warning')
        return redirect(url_for('admin_users'))
    
    user.is_admin = not user.is_admin
    db.session.commit()
    
    status = "granted" if user.is_admin else "revoked"
    flash(f'Admin privileges {status} for user {user.username}!', 'success')
    
    return redirect(url_for('admin_users'))

# =====================================
# POST REVIEW SYSTEM ROUTES
# =====================================

@app.route("/mark_for_review/<int:post_id>", methods=['POST'])
@login_required
def mark_for_review(post_id):
    post = Post.query.get_or_404(post_id)
    if current_user.role != 'Reviewer':
        abort(403)
    
    post.is_under_review = True
    db.session.commit()
    flash("Post marked for review!", "info")
    return redirect(request.referrer or url_for('home'))

@app.route("/unmark_for_review/<int:post_id>", methods=['POST'])
@login_required
def unmark_for_review(post_id):
    post = Post.query.get_or_404(post_id)
    # Only Police or Admin can unmark
    if not (current_user.is_admin or current_user.role == 'Police'):
        abort(403)
    
    post.is_under_review = False
    db.session.commit()
    flash("Post has been reviewed and is now visible!", "success")
    return redirect(request.referrer or url_for('home'))
