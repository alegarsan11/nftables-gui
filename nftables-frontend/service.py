from models import db, User
from flask_login import LoginManager

login_manager = LoginManager()

def create_default_user():
    default_user = User(username='Default', email="default@gmail.com", password="password")
    db.session.add(default_user)
    db.session.commit()
    
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))