from models import db, User
from flask_login import LoginManager

login_manager = LoginManager()

def create_default_user():
    user = User.query.filter_by(username='default').first()
    if not user:
        user = User(username='default', email='default@example.com',password="defaultpassword" ,role="administrator" ,is_active=True)
        db.session.add(user)
        db.session.commit()
    
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))