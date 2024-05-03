
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
    
    
    def check_password(self, password):
        return self.password == password

class Table(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
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
    id= db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    table_id = db.Column(db.Integer, db.ForeignKey('table.name'), nullable=False)
    family = db.Column(db.String(120), nullable=True)
    policy = db.Column(db.String(120), nullable=True)
    rules = db.relationship('Rule', backref='chain', lazy=True, cascade="all, delete-orphan")
    description = db.Column(db.String(120), nullable=True)

    def get_table(self):
        return Table.query.filter_by(name=self.table_id, family=self.family).first()


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
    chain_id = db.Column(db.Integer, db.ForeignKey('chain.id'), nullable=False)
    family = db.Column(db.String(120), nullable=False)
    expr = db.Column(db.String(120), nullable=False)
    handle = db.Column(db.String(120), nullable=True)
    description = db.Column(db.String(120), nullable=True)
    statement = db.relationship('Statement', backref='rule', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return '<Rule %r>' % self.handle
    
    def statements(self):
        return Statement.query.filter_by(rule_id=self.id).all()
    
    def table(self):
        chain = Chain.query.filter_by(id=self.chain_id, family=self.family).first()
        base_chain = BaseChain.query.filter_by(id=self.chain_id, family=self.family).first()
        if base_chain:
            return base_chain.table
        else:
            return chain.table
    
class Statement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rule_id = db.Column(db.Integer, db.ForeignKey('rule.id'), nullable=False)
    src_ip = db.Column(db.String(120), nullable=True)
    dst_ip = db.Column(db.String(120), nullable=True)
    src_port = db.Column(db.String(120), nullable=True)
    dst_port = db.Column(db.String(120), nullable=True)
    input_interface = db.Column(db.String(120), nullable=True)
    output_interface = db.Column(db.String(120), nullable=True)
    protocol = db.Column(db.String(120), nullable=True)
    
    def __repr__(self):
        return '<Statement %r>' % self.id
    
    def is_empty(self):
        return not any([self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.input_interface, self.output_interface, self.protocol])

class TerminalStatement(Statement):
    reject = db.Column(db.String(120), nullable=True)
    drop = db.Column(db.String(120), nullable=True)
    accept = db.Column(db.String(120), nullable=True)
    queue = db.Column(db.String(120), nullable=True)
    return_ = db.Column(db.Boolean(), nullable=True)
    jump = db.Column(db.String(120), nullable=True)
    go_to = db.Column(db.String(120), nullable=True)

    def __repr__(self):
        return '<TerminalStatement %r>' % self.id
    
    def is_empty(self):
        return not any([self.reject, self.drop, self.accept, self.queue, self.return_, self.jump, self.go_to])

class NotTerminalStatement(Statement):
    limit = db.Column(db.String(120), nullable=True)
    log = db.Column(db.String(120), nullable=True)
    counter = db.Column(db.String(120), nullable=True)
    masquerade = db.Column(db.Boolean(), nullable=True)
    snat = db.Column(db.String(120), nullable=True)
    dnat = db.Column(db.String(120), nullable=True)
    redirect = db.Column(db.String(120), nullable=True)


    def __repr__(self):
        return '<NotTerminalStatement %r>' % self.id

    def is_empty(self):
        return not any([self.limit, self.log, self.counter, self.masquerade, self.snat, self.dnat, self.redirect])
    
class Set(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    family = db.Column(db.String(120), nullable=False)
    type = db.Column(db.String(120), nullable=False)
    elements = db.Column(db.String(120), nullable=True)
    description = db.Column(db.String(120), nullable=True)
    table_id = db.Column(db.Integer, db.ForeignKey('table.name'), nullable=False)
    
    def __repr__(self):
        return '<Set %r>' % self.name
    
class Map(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    table_id = db.Column(db.Integer, db.ForeignKey('table.name'), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    family = db.Column(db.String(120), nullable=False)
    description = db.Column(db.String(120), nullable=True)
    type = db.Column(db.String(120), nullable=True)
    map = db.Column(db.String(120), nullable=True)
    elements = db.Column(db.String(120), nullable=True)
    
    def __repr__(self):
        return '<Map %r>' % self.name
