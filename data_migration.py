from flaskblog import db, app, bcrypt
from flaskblog.models import User, Post,Like, Comment

def migrate_database():
    """
    Safely add new tables without losing existing data
    """
    with app.app_context():
        try:
            print("Starting database migration...")
            
            # Create new tables (Like and Comment) without affecting existing ones
            db.create_all()
            
            print("Migration completed successfully!")
            print("New tables created: Like, Comment")
            print("Existing data in User and Post tables preserved.")
            
            # Verify existing data
            user_count = User.query.count()
            post_count = Post.query.count()
            
            print(f"Verified: {user_count} users and {post_count} posts still exist.")
            
        except Exception as e:
            print(f"Error during migration: {str(e)}")
            db.session.rollback()

if __name__ == "__main__":
    migrate_database()
