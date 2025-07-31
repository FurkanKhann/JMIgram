from flaskblog import db, app
from flaskblog.models import User
from werkzeug.security import generate_password_hash



with app.app_context():
    db.create_all()
    print("succesful")


