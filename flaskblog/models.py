from datetime import datetime
from flaskblog import db, login_manager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    password = db.Column(db.String(60), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)  # <-- Add this
    role=db.Column(db.String(30),default="Student")

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', Admin={self.is_admin})"

    posts = db.relationship('Post', backref='author', lazy=True)

    def set_password(self, password):
        self.password= generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    is_under_review = db.Column(db.Boolean, default=False)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=True)  # Text post
    image_file = db.Column(db.String(120), nullable=True)  # Optional image
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Post('{self.id}', '{self.date_posted}', Author='{self.user_id}')"
