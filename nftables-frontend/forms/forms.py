from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, IntegerField
from wtforms.validators import DataRequired, Email, EqualTo
from wtforms import ValidationError
from models import Chain, Table, User

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')
    
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if not user:
            raise ValidationError('User does not exist.')
    
    def validate_password(self, password):
        user = User.query.filter_by(username=self.username.data).first()
        if user and not user.check_password(password.data):
            raise ValidationError('Invalid password.')
        
class CreateUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), EqualTo('confirm_password', message='Passwords must match.')])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired()])
    role = StringField('Role', validators=[DataRequired()])
    submit = SubmitField('Create User')
    
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('User already exists.')
        
    def validate_role(self, role):
        if role.data not in ['administrator', 'user', 'guest']:
            raise ValidationError('Role must be one of: administrator, user, guest.')
        
    def validate_password(self, password):
        if len(password.data) < 8:
            raise ValidationError('Password must be at least 8 characters long.')
        
class UpdateUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    role = StringField('Role', validators=[DataRequired()])
    is_active = SelectField('Active', choices=[('True', 'True'), ('False', 'False')], validators=[DataRequired()])
    submit = SubmitField('Update User')
    
    def validate_role(self, role):
        if role.data not in ['administrator', 'user', 'guest']:
            raise ValidationError('Role must be one of: administrator, user, guest.')
        
    def validate_is_active(self, is_active):
        if is_active.data not in ['True', 'False']:
            raise ValidationError('Active must be one of: True, False.')
        
class TableForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    family = SelectField('Family', choices=[('ip', 'ipv4'), ('inet', 'ipv4 and ipv6'), ('arp', 'arp'), ('bridge', 'bridge'), ('netdev', 'netdev')], validators=[DataRequired()])
    description = StringField('Description')
    submit = SubmitField('Create Table')
    
    def validate_family(self, family):
        if family.data not in ['ip', 'inet', 'arp', 'bridge', 'netdev']:
            raise ValidationError('Family must be one of: ip, inet, arp, bridge, netdev.')

    def validate_name(self, name):
        table = Table.query.filter_by(name=name.data).first()
        if table or " " in name.data or "-" in name.data or "/" in name.data or "." in name.data or "," in name.data or ";" in name.data or ":" in name.data or "@" in name.data or "#" in name.data or "$" in name.data or "%" in name.data or "^" in name.data or "&" in name.data or "*" in name.data or "(" in name.data or ")" in name.data or "+" in name.data or "=" in name.data or "[" in name.data or "]" in name.data or "{" in name.data or "}" in name.data or "|" in name.data or "<" in name.data or ">" in name.data or "?" in name.data or "!" in name.data or "'" in name.data or '"' in name.data or "\\" in name.data or "`" in name.data or "~" in name.data:
            raise ValidationError('Table name invalid. (Must not contain special characters or spaces.)')

class ChainForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    table = StringField('Table', validators=[DataRequired()])
    family = StringField('Family', validators=[DataRequired()])
    policy = SelectField('Policy', choices=[('accept', 'accept'), ('drop', 'drop'), ('reject', 'reject'), ('dnat', 'dnat'), ('snat', 'snat'), ('masquerade', 'masquerade'), ('redirect', 'redirect'), ('log', 'log'), ('continue', 'continue'), ('return', 'return'), ('jump', 'jump'), ('queue', 'queue'), ('unreachable', 'unreachable'), ('error', 'error'), ('broadcast', 'broadcast'), ('dnat', 'dnat'), ('snat', 'snat'), ('redirect', 'redirect'), ('mirror', 'mirror'), ('tproxy', 'tproxy'), ('netmap', 'netmap'), ('nflog', 'nflog'), ('nfqueue', 'nfqueue'), ('nfacct', 'nfacct'), ('nfct', 'nfct'), ('nftrace', 'nftrace'), ('nftlb', 'nftlb')], validators=[DataRequired()])
    description = StringField('Description')
    submit = SubmitField('Create Chain')
    
    def validate_name(self, name):
        chain = Chain.query.filter_by(name=name.data).first()
        if chain:
            raise ValidationError('Chain already exists.')
        if " " in name.data or "-" in name.data or "/" in name.data or "." in name.data or "," in name.data or ";" in name.data or ":" in name.data or "@" in name.data or "#" in name.data or "$" in name.data or "%" in name.data or "^" in name.data or "&" in name.data or "*" in name.data or "(" in name.data or ")" in name.data or "+" in name.data or "=" in name.data or "[" in name.data or "]" in name.data or "{" in name.data or "}" in name.data or "|" in name.data or "<" in name.data or ">" in name.data or "?" in name.data or "!" in name.data or "'" in name.data or '"' in name.data or "\\" in name.data or "`" in name.data or "~" in name.data:
            raise ValidationError('Chain name invalid. (Must not contain special characters or spaces.)')

    def validate_table(self, table):
        table = Table.query.filter_by(name=table.data).first()
        if not table:
            print("has llegado aqui tablaa")
            raise ValidationError('Table does not exist.')
 
    def validate_family(self, family):
        if family.data not in ['ip', 'inet', 'arp', 'bridge', 'netdev']:
            print("has llegado aqui familia")
            raise ValidationError('Family must be one of: ip, inet, arp, bridge, netdev.')

    def validate_policy(self, policy):
        if policy.data not in ['accept', 'drop', 'reject', 'dnat', 'snat', 'masquerade', 'redirect', 'log', 'continue', 'return', 'jump', 'queue', 'unreachable', 'error', 'broadcast', 'dnat', 'snat', 'redirect', 'mirror', 'tproxy', 'netmap', 'nflog', 'nfqueue', 'nfacct', 'nfct', 'nftrace', 'nftlb']:
            print("has llegado aqui politica")
            raise ValidationError('Policy must be one of: accept, drop, reject, dnat, snat, masquerade, redirect, log, continue, return, jump, queue, unreachable, error, broadcast, dnat, snat, redirect, mirror, tproxy, netmap, nflog, nfqueue, nfacct, nfct, nftrace, nftlb.')

    def validate_type(self, type):
        if type.data not in ['filter', 'nat', 'route', 'mangle', 'raw']:
            print("has llegado aqui tipo")
            raise ValidationError('Type must be one of: filter, nat, route, mangle, raw.')

        
        
class BaseChainForm(ChainForm):
    hook_type = SelectField('Hook Type', choices=[('prerouting', 'prerouting'), ('input', 'input'), ('forward', 'forward'), ('output', 'output'), ('postrouting', 'postrouting')], validators=[DataRequired()])
    priority = IntegerField('Priority', validators=[DataRequired()])
    type = SelectField('Type', choices=[('filter', 'filter'), ('nat', 'nat'), ('route', 'route'), ('mangle', 'mangle'), ('raw', 'raw')], validators=[DataRequired()])
    
    def validate_hook_type(self, hook_type):
        if hook_type.data not in ['prerouting', 'input', 'forward', 'output', 'postrouting']:
            raise ValidationError('Hook type must be one of: prerouting, input, forward, output, postrouting.')
          
    def validate_priority(self, priority):
        if priority.data > 300 or priority.data < -400 or priority.data != int(priority.data):
            raise ValidationError('Priority must be between -400 and 300.')

class StatementForm(FlaskForm):
    type = SelectField('Type', choices=[('terminal', 'terminal'), ('not_terminal', 'not_terminal')], validators=[DataRequired()])
    src_ip = StringField('Source IP')
    dst_ip = StringField('Destination IP')
    src_port = StringField('Source Port')
    dst_port = StringField('Destination Port')
    protocol = StringField('Protocol')
    description = StringField('Description')
    submit = SubmitField('Add Statement')
    
    def validate_src_ip(self, src_ip):
        if src_ip.data and not src_ip.data.replace(".", "").replace("/", "").replace(":", "").isdigit():
            raise ValidationError('Source IP must be a valid IP address.')
        
    def validate_dst_ip(self, dst_ip):
        if dst_ip.data and not dst_ip.data.replace(".", "").replace("/", "").replace(":", "").isdigit():
            raise ValidationError('Destination IP must be a valid IP address.')
        
    def validate_src_port(self, src_port):
        if src_port.data and not src_port.data.isdigit():
            raise ValidationError('Source Port must be a valid port number.')
        
    def validate_dst_port(self, dst_port):
        if dst_port.data and not dst_port.data.isdigit():
            raise ValidationError('Destination Port must be a valid port number.')
        
    def validate_protocol(self, protocol):
        if protocol.data and protocol.data not in ['tcp', 'udp', 'icmp', 'all']:
            raise ValidationError('Protocol must be one of: tcp, udp, icmp, all.')

class TerminalStatementForm(StatementForm):
    reject = SelectField('Reject', choices=[('True', 'True'), ('False', 'False')])
    drop = SelectField('Drop', choices=[('True', 'True'), ('False', 'False')])
    accept = SelectField('Accept', choices=[('True', 'True'), ('False', 'False')])
    queue = StringField('Queue')
    return_ = SelectField('Return', choices=[('True', 'True'), ('False', 'False')])
    jump = StringField('Jump')
    go_to = StringField('Go To')
    
    def validate_queue(self, queue):
        if queue.data and not queue.data.isdigit():
            raise ValidationError('Queue must be a valid number.')
        
    def validate_jump(self, jump):
        if jump.data and not jump.data.replace(":", "").replace("-", "").replace("_", "").replace(".", "").replace("/", "").replace(" ", "").isalnum():
            raise ValidationError('Jump must be a valid chain name.')
        
    def validate_go_to(self, go_to):
        if go_to.data and not go_to.data.replace(":", "").replace("-", "").replace("_", "").replace(".", "").replace("/", "").replace(" ", "").isalnum():
            raise ValidationError('Go To must be a valid chain name.')
        
class NotTerminalStatementForm(StatementForm):
    limit = IntegerField('Limit')
    log = StringField('Log')
    counter = StringField('Counter')
    nflog = StringField('NFLog')
    
    def validate_limit(self, limit):
        if limit.data and not limit.data.isdigit():
            raise ValidationError('Limit must be a valid number.')   
        
    def validate_log(self, log):
        if log.data and not log.data.replace(":", "").replace("-", "").replace("_", "").replace(".", "").replace("/", "").replace(" ", "").isalnum():
            raise ValidationError('Log must be a valid log.')
        
    def validate_counter(self, counter):
        if counter.data and not counter.data.replace(":", "").replace("-", "").replace("_", "").replace(".", "").replace("/", "").replace(" ", "").isalnum():
            raise ValidationError('Counter must be a valid counter.')
        
    def validate_nflog(self, nflog):
        if nflog.data and not nflog.data.replace(":", "").replace("-", "").replace("_", "").replace(".", "").replace("/", "").replace(" ", "").isalnum():
            raise ValidationError('NFLog must be a valid NFLog.')

class RuleForm(FlaskForm):
    chain = StringField('Chain', validators=[DataRequired()])
    family = StringField('Family', validators=[DataRequired()])
    expr = StringField('Expression', validators=[DataRequired()])
    handle = StringField('Handle', validators=[DataRequired()])
    description = StringField('Description')
    submit = SubmitField('Add Rule')
    
    def validate_chain(self, chain):
        chain = Chain.query.filter_by(name=chain.data).first()
        if not chain:
            raise ValidationError('Chain does not exist.')
        
    def validate_family(self, family):
        if family.data not in ['ip', 'inet', 'arp', 'bridge', 'netdev']:
            raise ValidationError('Family must be one of: ip, inet, arp, bridge, netdev.')
        
    def validate_expr(self, expr):
        if expr.data and not expr.data.replace(":", "").replace("-", "").replace("_", "").replace(".", "").replace("/", "").replace(" ", "").isalnum():
            raise ValidationError('Expression must be a valid expression.')
        
    def validate_handle(self, handle):
        if handle.data and not handle.data.replace(":", "").replace("-", "").replace("_", "").replace(".", "").replace("/", "").replace(" ", "").isalnum():
            raise ValidationError('Handle must be a valid handle.')
        
    