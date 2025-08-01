from datetime import datetime,timedelta
from flaskblog import db, login_manager
from flask_login import UserMixin
from itsdangerous import URLSafeTimedSerializer as Serializer
from werkzeug.security import generate_password_hash, check_password_hash
from flask import current_app


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    password = db.Column(db.String(60), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    role = db.Column(db.String(30), default="Student")
    
    # NEW - Email verification fields
    email_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(100), nullable=True)
    token_created_at = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', Admin={self.is_admin})"

    # Existing relationships
    posts = db.relationship('Post', backref='author', lazy=True)
    likes = db.relationship('Like', backref='user', lazy=True, cascade='all, delete-orphan')
    comments = db.relationship('Comment', backref='author', lazy=True, cascade='all, delete-orphan')

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def has_liked_post(self, post):
        return Like.query.filter_by(user_id=self.id, post_id=post.id).first() is not None

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(current_app.config['SECRET_KEY'])
        return s.dumps({'user_id': self.id})

    @staticmethod
    def verify_reset_token(token, expires_sec=1800):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token, max_age=expires_sec)
            user_id = data.get('user_id')
        except:
            return None
        return User.query.get(user_id)

    # NEW - Email verification methods
    def generate_verification_token(self):
        """Generate email verification token"""
        s = Serializer(current_app.config['SECRET_KEY'])
        token = s.dumps({'user_id': self.id, 'email': self.email})
        self.verification_token = token
        self.token_created_at = datetime.utcnow()
        return token

    @staticmethod
    def verify_email_token(token, expires_sec=3600):  # 1 hour expiry
        """Verify email verification token"""
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token, max_age=expires_sec)
            user_id = data.get('user_id')
            email = data.get('email')
        except:
            return None
        
        user = User.query.get(user_id)
        if user and user.email == email:
            return user
        return None

    def is_token_expired(self, expires_sec=3600):
        """Check if verification token is expired"""
        if not self.token_created_at:
            return True
        return datetime.utcnow() > self.token_created_at + timedelta(seconds=expires_sec)


    @staticmethod
    def verify_reset_token(token, expires_sec=1800):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token, max_age=expires_sec)
            user_id = data.get('user_id')
        except:
            return None
        return User.query.get(user_id)

    # Helper method to check if user liked a post
    def has_liked_post(self, post):
        return Like.query.filter_by(user_id=self.id, post_id=post.id).first() is not None


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    is_under_review = db.Column(db.Boolean, default=False)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=True)
    image_file = db.Column(db.String(120), nullable=True)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # New relationships for likes and comments
    likes = db.relationship('Like', backref='post', lazy='dynamic', cascade='all, delete-orphan')
    comments = db.relationship('Comment', backref='post', lazy='dynamic', cascade='all, delete-orphan')

    def __repr__(self):
        return f"Post('{self.id}', '{self.date_posted}', Author='{self.user_id}')"

    # Helper methods for likes and comments
    def get_like_count(self):
        return self.likes.count()

    def get_comment_count(self):
        return self.comments.count()

    def get_recent_comments(self, limit=3):
        return self.comments.order_by(Comment.date_posted.desc()).limit(limit).all()


class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    date_liked = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    # Unique constraint to prevent duplicate likes
    __table_args__ = (db.UniqueConstraint('user_id', 'post_id', name='unique_user_post_like'),)

    def __repr__(self):
        return f"Like(User={self.user_id}, Post={self.post_id})"


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)

    def __repr__(self):
        return f"Comment('{self.content[:20]}...', User={self.user_id}, Post={self.post_id})"


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    type = db.Column(db.String(50), nullable=False)  # 'post_marked', 'post_deleted', 'post_approved', 'like', 'comment'
    message = db.Column(db.String(255), nullable=False)
    related_post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=True)
    related_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Who triggered the notification
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    # Relationships
    user = db.relationship('User', foreign_keys=[user_id], backref='notifications')
    related_user = db.relationship('User', foreign_keys=[related_user_id])
    related_post = db.relationship('Post', backref='notifications')

    def __repr__(self):
        return f"Notification('{self.type}', '{self.message}', Read={self.is_read})"

    def time_since_created(self):
        """Return human-readable time since notification was created"""
        now = datetime.utcnow()
        diff = now - self.created_at
        
        if diff.days > 0:
            return f"{diff.days}d ago"
        elif diff.seconds > 3600:
            return f"{diff.seconds // 3600}h ago"
        elif diff.seconds > 60:
            return f"{diff.seconds // 60}m ago"
        else:
            return "Just now"


def delete_user_data(self):
    """Comprehensive user data deletion"""
    try:
        # Delete all notifications related to this user
        Notification.query.filter(
            (Notification.user_id == self.id) | 
            (Notification.related_user_id == self.id)
        ).delete()
        
        # Delete all likes by this user
        Like.query.filter_by(user_id=self.id).delete()
        
        # Delete all comments by this user
        Comment.query.filter_by(user_id=self.id).delete()
        
        # Delete all posts by this user (this will also delete related likes/comments)
        Post.query.filter_by(user_id=self.id).delete()
        
        # Finally delete the user
        db.session.delete(self)
        db.session.commit()
        
        return True
    except Exception as e:
        db.session.rollback()
        return False
