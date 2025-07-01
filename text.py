from app1 import app, db
from app1.models import Post



with app.app_context():
    # Delete all posts
    Post.query.delete()
    db.session.commit()
    print("All posts deleted.")
