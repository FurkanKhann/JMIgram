from flaskblog import db, app, bcrypt
from flaskblog.models import User, Post
from datetime import datetime

with app.app_context():
    db.create_all()

    # Check if the admin user already exists
    existing_user = User.query.filter_by(email='first()
    if existing_user:
        print("Admin user already exists.")
        admin_user = existing_user
    else:
        hashed_pw = bcrypt.generate_password_hash("").decode('utf-8')
        admin_user = User(username="admin", email="", password=hashed_pw, is_admin=True)
        db.session.add(admin_user)
        db.session.commit()
        print("Admin user created successfully.")
    
    # Create 1 dummy post using the admin user
    existing_posts = Post.query.count()
    if existing_posts == 0:
        post = Post(
            title="Welcome to Our Blog Platform",
            content="This is the first post on our new blog platform. We're excited to share knowledge and connect with our community!",
            author=admin_user,
            is_under_review=False,
            date_posted=datetime.utcnow()
        )
        db.session.add(post)
        db.session.commit()
        print("Created 1 dummy post successfully.")
    else:
        print(f"Posts already exist ({existing_posts} posts found). Skipping post creation.")
    
    print("Database setup completed!")
