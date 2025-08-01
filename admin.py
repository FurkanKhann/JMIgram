from flaskblog import db, app, bcrypt
from flaskblog.models import User, Post
from datetime import datetime

with app.app_context():
    db.create_all()

    # Check if the admin user already exists
    admin_email = 'admin@jmigram.com'  # Set admin email
    existing_user = User.query.filter_by(email=admin_email).first()  # Fixed syntax error
    
    if existing_user:
        print("Admin user already exists.")
        admin_user = existing_user
    else:
        # Create admin user with proper credentials
        hashed_pw = bcrypt.generate_password_hash("admin123").decode('utf-8')  # Added password
        admin_user = User(
            username="admin", 
            email=admin_email,  # Added actual email
            password=hashed_pw, 
            is_admin=True,
            role="Admin",  # Set role to Admin
            email_verified=True  # Set admin as verified to bypass email verification
        )
        db.session.add(admin_user)
        db.session.commit()
        print("Admin user created successfully.")
        print(f"Email: {admin_email}")
        print(f"Password: admin123")
    
    print("Database setup completed!")
