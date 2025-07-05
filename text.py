# create_db.py

from flaskblog import db, app

# Recreate database from models by dropping and creating tables
with app.app_context():
    db.drop_all()
    db.create_all()
    print("✅ Database dropped and recreated successfully!")
