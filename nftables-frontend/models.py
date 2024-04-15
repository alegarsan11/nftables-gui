
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin


db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(120), nullable=False)
    is_active = db.Column(db.Boolean, nullable=False)

    def __repr__(self):
        return '<User %r>' % self.username
    
    def check_password(self, password):
        return self.password == password

class Table(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    family = db.Column(db.String(80), nullable=False)
    description = db.Column(db.String(120), nullable=True)
    chains = db.relationship('Chain', backref='table', lazy=True)
    
    def save(self):
        db.session.add(self)
        db.session.commit()

    def __repr__(self):
        return '<Table %r>' % self.name
    
class Chain(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    table_id = db.Column(db.Integer, db.ForeignKey('table.id'), nullable=False)
    rules = db.relationship('Rule', backref='chain', lazy=True)

    def __repr__(self):
        return '<Chain %r>' % self.name

class Rule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    chain_id = db.Column(db.Integer, db.ForeignKey('chain.id'), nullable=False)
    rule = db.Column(db.String(120), nullable=False)

    def __repr__(self):
        return '<Rule %r>' % self.rule