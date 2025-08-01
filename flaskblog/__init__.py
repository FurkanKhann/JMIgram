from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_mail import Mail
import os
from dotenv import load_dotenv
from flask_wtf import CSRFProtect
csrf = CSRFProtect()



load_dotenv()  # Load environment variables from .env

app = Flask(__name__)
app.config['SECRET_KEY'] = 'FURKANKHANKHAN'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

csrf = CSRFProtect(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
csrf.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = "Hacker Hae bhai hacker jaada tezi nahi login kr mittar"
login_manager.login_message_category = 'info'

# Mail config
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USER')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASS')

mail = Mail(app)

from flaskblog import routes
