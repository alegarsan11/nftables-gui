from models import Chain, Rule, Table, BaseChain, db, User
from flask_login import LoginManager

login_manager = LoginManager()

def create_default_user():
    user = User.query.filter_by(username='default').first()
    if not user:
        user = User(username='default',password="defaultpassword" ,role="administrator" ,is_active=True)
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

def edit_user(user_id, username, email, role, is_active):
    user = User.query.get(user_id)
    user.username = username
    user.email = email
    user.role = role
    user.is_active = is_active
    db.session.commit()
    
def get_table(table_id):
    table = Table.query.filter_by(name=table_id).first()
    return table


def get_users():
    return User.query.all()

def get_user(user_id):
    user = User.query.get(user_id)
    return user

def delete_user(user_id):
    user = User.query.get(user_id)
    db.session.delete(user)
    db.session.commit()


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

def insert_chains(table_id, chains):
    table = Table.query.get(table_id)
    table.chains = chains
    db.session.commit()
    
def insert_chain(chain_name, family, policy, table_id, type,  hook_type=None, priority=None):
    if(hook_type != None and priority != None):
        chain = BaseChain(name=chain_name, family=family, type=type, policy=policy, table_id=table_id, hook_type=hook_type, priority=priority)
    else:
        chain = Chain(name=chain_name, family=family, table_id=table_id, policy=policy)
    db.session.add(chain)
    db.session.commit()
    
def check_existing_chain(chain_name, table_id, family):
    chain = Chain.query.filter_by(name=chain_name, table_id=table_id, family=family).first()
    if chain:
        return False
    return True

def get_chains_from_table(table_id):
    table = Table.query.get(table_id)
    return table.chains

def get_chains():
    return Chain.query.all()

def get_chain(chain_id):
    chain = Chain.query.filter_by(name=chain_id).first()
    base_chain = BaseChain.query.filter_by(name=chain_id).first()
    print(base_chain)
    if base_chain:
        return base_chain
    return chain

def check_existing_rule(chain_id, rule):
    rule = Rule.query.filter_by(chain_id=chain_id, expr=rule).first()
    if rule:
        return True
    return False

def insert_rule(chain_id, family, expr, handle, description=None):
    rule = Rule(chain_id=chain_id, family=family, expr=expr, handle=handle, description=description)
    db.session.add(rule)
    db.session.commit()
    
def get_rules_from_chain(chain_id):
    chain = Chain.query.get(chain_id)
    return chain.rules

def edit_chain(chain_description, chain_name, family, policy, type, hook_type=None, priority=None):
    chain = Chain.query.get(chain_name)
    chain.name = chain_name
    chain.family = family
    chain.policy = policy
    chain.type = type
    chain.description = chain_description
    if(hook_type != None and priority != None):
        base_chain = BaseChain.query.get(chain_name)
        base_chain.name = chain_name
        base_chain.family = family
        base_chain.policy = policy
        base_chain.type = type
        base_chain.hook_type = hook_type
        base_chain.priority = priority
        base_chain.description = chain_description
        
    db.session.commit()
    
def delete_chain(chain_id):
    chain = Chain.query.get(chain_id)
    db.session.delete(chain)
    db.session.commit()
    
def delete_rules_form_chain(chain_id):
    chain = Chain.query.get(chain_id)
    rules = chain.rules
    for rule in rules:
        db.session.delete(rule)
    db.session.commit()