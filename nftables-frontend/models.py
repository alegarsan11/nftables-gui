
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
    name = db.Column(db.String(80), unique=True, nullable=False, primary_key=True)
    family = db.Column(db.String(80), nullable=False)
    description = db.Column(db.String(120), nullable=True)
    chains = db.relationship('Chain', backref='table', lazy=True, cascade="all, delete-orphan")
    
    def save(self):
        db.session.add(self)
        db.session.commit()

    def __repr__(self):
        return '<Table %r>' % self.name
    
class Chain(db.Model):
    __tablename__ = 'chain'
    name = db.Column(db.String(80), unique=True, nullable=False, primary_key=True)
    table_id = db.Column(db.Integer, db.ForeignKey('table.name'), nullable=False)
    family = db.Column(db.String(120), nullable=True)
    policy = db.Column(db.String(120), nullable=True)
    rules = db.relationship('Rule', backref='chain', lazy=True, cascade="all, delete-orphan")
    description = db.Column(db.String(120), nullable=True)


    def __repr__(self):
        return '<Chain %r>' % self.name

class UserChain(Chain):


    def __repr__(self):
        return '<UserChain %r>' % self.name

class BaseChain(Chain):
    type = db.Column(db.String(120), nullable=True)
    hook_type = db.Column(db.String(120), nullable=True)
    priority = db.Column(db.Integer, nullable=True)


    def __repr__(self):
        return '<BaseChain %r>' % self.name
class Rule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    chain_id = db.Column(db.Integer, db.ForeignKey('chain.name'), nullable=False)
    family = db.Column(db.String(120), nullable=False)
    expr = db.Column(db.String(120), nullable=False)
    handle = db.Column(db.String(120), nullable=False)
    description = db.Column(db.String(120), nullable=True)
    

    def __repr__(self):
        return '<Rule %r>' % self.handle