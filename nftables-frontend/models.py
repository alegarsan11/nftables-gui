
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin


db = SQLAlchemy(session_options={"autoflush": False})

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(120), nullable=False)
    is_active = db.Column(db.Boolean, nullable=False)

    def __repr__(self):
        return '<User %r>' % self.username
    
    def print(self):
        print(self.id)
        print(self.username)
        print(self.email)
        print(self.role)
        print(self.is_active)
        print(self.password)
    
    def check_password(self, password):
        return self.password == password

class Table(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    family = db.Column(db.String(80), nullable=False)
    description = db.Column(db.String(120), nullable=True)
    chains = db.relationship('Chain', backref='table', lazy=True, cascade="all, delete-orphan")
    
    def save(self):
        db.session.add(self)
        db.session.commit()

    def __repr__(self):
        return '<Table %r>' % self.name
    
class Chain(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    table_id = db.Column(db.Integer, db.ForeignKey('table.id'), nullable=False)
    type = db.Column(db.String(120), nullable=True)
    family = db.Column(db.String(120), nullable=False)
    policy = db.Column(db.String(120), nullable=True)
    rules = db.relationship('Rule', backref='chain', lazy=True)

    def __repr__(self):
        return '<Chain %r>' % self.name
    
class user_chain(Chain, db.Model):
    
    __tablename__ = 'user_chain'
    
    id = db.Column(db.Integer, db.ForeignKey('chain.id'), primary_key=True)
    
    def __repr__(self):
        return '<User_chain %r>' % self.id

class base_chain(Chain, db.Model):
    
    __tablename__ = 'base_chain'
    
    id = db.Column(db.Integer, db.ForeignKey('chain.id'), primary_key=True)
    hook_type = db.Column(db.String(120), nullable=False)
    priority = db.Column(db.Integer, nullable=False)
    def __repr__(self):
        return '<Base_chain %r>' % self.id

class Rule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    chain_id = db.Column(db.Integer, db.ForeignKey('chain.id'), nullable=False)
    rule = db.Column(db.String(120), nullable=False)

    def __repr__(self):
        return '<Rule %r>' % self.rule