from flaskblog import app, db
from flaskblog.models import User

def add_email_verification_columns():
    """Add email verification columns to existing users table"""
    with app.app_context():
        try:
            print("Adding email verification columns...")
            
            # Create new columns
            db.engine.execute('ALTER TABLE user ADD COLUMN email_verified BOOLEAN DEFAULT 0')
            db.engine.execute('ALTER TABLE user ADD COLUMN verification_token VARCHAR(100)')
            db.engine.execute('ALTER TABLE user ADD COLUMN token_created_at DATETIME')
            
            # Optional: Set existing users as verified
            # Uncomment the next line to auto-verify existing users
            # db.engine.execute('UPDATE user SET email_verified = 1 WHERE email_verified IS NULL')
            
            print("Email verification columns added successfully!")
            print("Note: Existing users will need to verify their email addresses.")
            
        except Exception as e:
            print(f"Error: {e}")
            print("Columns may already exist or there was a database error.")

if __name__ == "__main__":
    add_email_verification_columns()
