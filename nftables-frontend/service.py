from models import Table, db, User
from flask_login import LoginManager

login_manager = LoginManager()

def create_default_user():
    user = User.query.filter_by(username='default').first()
    if not user:
        user = User(username='default', email='default@example.com',password="defaultpassword" ,role="administrator" ,is_active=True)
        db.session.add(user)
        db.session.commit()
        
def create_user(username, email, password, role, is_active):
    user = User(username=username, email=email, password=password, role=role, is_active=is_active)
    db.session.add(user)
    db.session.commit()
    
def check_existing_table(name, family):
    table = Table.query.filter_by(name=name, family=family).first()
    if table:
        return True
    return False
    
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



def insert_in_table(name, family, description=None):
    try:
        if(description != None):
            Table(name=name, family=family, description=description).save()
        else:
            Table(name=name, family=family, description=description).save()
    except Exception as e:
        db.session.rollback()
        return str(e)
    return "Success"

def delete_table(table_id):
    table = Table.query.get(table_id)
    db.session.delete(table)
    db.session.commit()
    

def get_tables():
    return Table.query.all()