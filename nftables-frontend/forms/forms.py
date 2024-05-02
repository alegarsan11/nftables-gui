from ipaddress import ip_address
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, IntegerField, FormField, FieldList, BooleanField
from wtforms.validators import DataRequired, Email, EqualTo, Optional
from wtforms import ValidationError
from models import Chain, Table, User
import service

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
    policy = SelectField('Policy', choices=[
        ('accept', 'accept'),
        ('drop', 'drop'),
        ('reject', 'reject')    ], validators=[DataRequired()])    
    description = StringField('Description')
    submit = SubmitField('Create Chain')
    
    def validate_name(self, name):
        if " " in name.data or "-" in name.data or "/" in name.data or "." in name.data or "," in name.data or ";" in name.data or ":" in name.data or "@" in name.data or "#" in name.data or "$" in name.data or "%" in name.data or "^" in name.data or "&" in name.data or "*" in name.data or "(" in name.data or ")" in name.data or "+" in name.data or "=" in name.data or "[" in name.data or "]" in name.data or "{" in name.data or "}" in name.data or "|" in name.data or "<" in name.data or ">" in name.data or "?" in name.data or "!" in name.data or "'" in name.data or '"' in name.data or "\\" in name.data or "`" in name.data or "~" in name.data:
            raise ValidationError('Chain name invalid. (Must not contain special characters or spaces.)')

    def validate_table(self, table):
        table = Table.query.filter_by(name=table.data).first()
        if not table:
            raise ValidationError('Table does not exist.')
 
    def validate_family(self, family):
        if family.data not in ['ip', 'inet', 'arp', 'bridge', 'netdev']:
            raise ValidationError('Family must be one of: ip, inet, arp, bridge, netdev.')

    def validate_policy(self, policy):
        if policy.data not in ['accept', 'drop', 'reject', 'dnat', 'snat', 'masquerade', 'redirect', 'log', 'return', 'jump', 'queue', 'unreachable', 'error', 'broadcast', 'dnat', 'snat', 'redirect', 'mirror', 'tproxy', 'netmap', 'nfqueue', 'nfacct', 'nfct', 'nftrace', 'nftlb']:
            raise ValidationError('Policy must be one of: accept, drop, reject, dnat, snat, masquerade, redirect, log, return, jump, queue, unreachable, error, broadcast, dnat, snat, redirect, mirror, tproxy, netmap, nfqueue, nfacct, nfct, nftrace, nftlb.')

    def validate_type(self, type):
        if type.data not in ['filter', 'nat', 'route', 'mangle', 'raw']:
            raise ValidationError('Type must be one of: filter, nat, route, mangle, raw.')

        
        
class BaseChainForm(ChainForm):
    hook_type = SelectField('Hook Type', choices=[('prerouting', 'prerouting'), ('input', 'input'), ('forward', 'forward'), ('output', 'output'), ('postrouting', 'postrouting')], validators=[DataRequired()])
    priority = IntegerField('Priority', validators=[Optional()])
    type = SelectField('Type', choices=[('filter', 'filter'), ('nat', 'nat'), ('route', 'route'), ('mangle', 'mangle'), ('raw', 'raw')], validators=[DataRequired()])
    
    def validate_hook_type(self, hook_type):
        if hook_type.data not in ['prerouting', 'input', 'forward', 'output', 'postrouting']:
            raise ValidationError('Hook type must be one of: prerouting, input, forward, output, postrouting.')
          
    def validate_priority(self, priority):
        if priority.data > 300 or priority.data < -400 :
            raise ValidationError('Priority must be between -400 and 300.')

class StatementForm(FlaskForm):
    src_ip = StringField('Source IP', validators=[Optional()])
    dst_ip = StringField('Destination IP', validators=[Optional()])
    src_port = StringField('Source Port', validators=[Optional()])
    dst_port = StringField('Destination Port', validators=[Optional()])
    submit = SubmitField('Add Statement', validators=[Optional()])
    
    def validate_src_ip(self, src_ip):
        try:
            ip_address(src_ip.data)
        except ValueError:
            raise ValidationError('Source IP must be a valid IP address with a network mask.')

    def validate_dst_ip(self, dst_ip):
        try:
            ip_address(dst_ip.data)
        except ValueError:
            raise ValidationError('Destination IP must be a valid IP address with a network mask.')
                
    def validate_src_port(self, src_port):
        if src_port.data and (not src_port.data.isdigit() or not 0 <= int(src_port.data) <= 65535):
            raise ValidationError('Source Port must be a valid port number between 0 and 65535.')

    def validate_dst_port(self, dst_port):
        if dst_port.data and (not dst_port.data.isdigit() or not 0 <= int(dst_port.data) <= 65535):
            raise ValidationError('Destination Port must be a valid port number between 0 and 65535.')        

class TerminalStatementForm(StatementForm):
    reject = BooleanField('Reject',validators=[Optional()])
    drop = BooleanField('Drop',  validators=[Optional()])
    accept = BooleanField('Accept', validators=[Optional()])
    queue = IntegerField('Queue', validators=[Optional()])
    return_ = BooleanField('Return',  validators=[Optional()])
    jump = StringField('Jump', validators=[Optional()])
    go_to = StringField('Go To', validators=[Optional()])
    
    def validate_not_all_empty(self, reject, drop, accept, queue, return_, jump, go_to):
        if not (reject.data or drop.data or accept.data or queue.data or return_.data or jump.data or go_to.data):
            raise ValidationError('At least one field must be filled.')
    
    def validate_queue(self, queue):
        if queue.data and not isinstance(queue.data, int):
            raise ValidationError('Queue must be a valid number.')
        
    def validate_jump(self, jump):
        if jump.data and not jump.data.replace(":", "").replace("-", "").replace("_", "").replace(".", "").replace("/", "").replace(" ", "").isalnum():
            raise ValidationError('Jump must be a valid chain name.')
        
        
    def validate_go_to(self, go_to):
        if go_to.data and not go_to.data.replace(":", "").replace("-", "").replace("_", "").replace(".", "").replace("/", "").replace(" ", "").isalnum():
            raise ValidationError('Go To must be a valid chain name.')
        
class NotTerminalStatementForm(StatementForm):
    limit = IntegerField('Limit', validators=[Optional()] )
    log = BooleanField('Log', validators=[Optional()])
    counter = BooleanField('Counter', validators=[Optional()])
    masquerade = BooleanField('Masquerade', validators=[Optional()])
    redirect = StringField('Redirect', validators=[Optional()])
    src_nat = StringField('SRC_NAT', validators=[Optional()])
    dst_nat = StringField('DST_NAT', validators=[Optional()])
    limit_per = StringField('Limit Per', validators=[Optional()])
    
    def validate_not_all_empty(self, limit, log, counter, masquerade, redirect, src_nat, dst_nat, limit_per):
        if not (limit.data or log.data or counter.data or masquerade.data or redirect.data or src_nat.data or dst_nat.data or limit_per.data):
            raise ValidationError('At least one field must be filled.')
    
    def validate_limit_per(self, limit_per):
        if limit_per.data and not limit_per.data.replace(":", "").replace("-", "").replace("_", "").replace(".", "").replace("/", "").replace(" ", "").isalnum():
            raise ValidationError('Limit Per must be a valid chain name.')
        if limit_per.data not in ['second', 'minute', 'hour']:
            raise ValidationError('Limit Per must be one of: second, minute, hour.')
    
    def validate_src_nat(self, src_nat):
        try:
            ip_address(src_nat.data)
        except ValueError:
            raise ValidationError('Source IP must be a valid IP address with a network mask.')

    def validate_dst_nat(self,dst_nat):
        try:
            if ":" in dst_nat.data:
                ip_address(dst_nat.data.split(":")[0])
                if not dst_nat.data.split(":")[1].isdigit() or not 0 <= int(dst_nat.data.split(":")[1]) <= 65535:
                    raise ValidationError('Destination IP must be a valid IP address or port number between 0 and 65535.')
            elif (dst_nat.data and (not dst_nat.data.isdigit() or not 0 <= int(dst_nat.data) <= 65535) or ip_address(dst_nat.data)):
                ValidationError('Destination IP must be a valid IP address or port number between 0 and 65535.')
        except ValueError:
            raise ValidationError('Destination IP must be a valid IP address or port number between 0 and 65535.')

    
    def validate_limit(self, limit):
        if limit.data and not isinstance(limit.data, int) or 0 > limit.data:
            raise ValidationError('Limit must be a valid number.')   
        if limit.data and self.limit_per.data == "":
            raise ValidationError('Limit Per must be specified if limit is specified.')
        
    def validate_redirect(self, redirect):
        try:
            if redirect.data and not (self.dst_port.data or self.src_port.data):
                raise ValidationError('Condition on dst or src port must be especified to create redirect.')
            elif not isinstance(int(redirect.data), int) or not 0 <= int(redirect.data) <= 65535:
                raise ValidationError('Redirect must be a port number between 0 and 65535.')
        except ValueError:
            raise ValidationError('Redirect must be a valid IP address')

class RuleForm(FlaskForm):
    chain = StringField('Chain', validators=[DataRequired()])
    family = StringField('Family', validators=[DataRequired()])
    handle = StringField('Handle', validators=[Optional()])
    statements = FormField(NotTerminalStatementForm)
    statements_term = FormField(TerminalStatementForm)
    description = StringField('Description', validators=[Optional()])
    statement_select = SelectField('Statement Type', choices=[('terminal', 'Terminal'), ('not_terminal', 'Not Terminal')], validators=[DataRequired()])
    submit = SubmitField('Add Rule')
            
    def validate_family(self, family):
        if family.data not in ['ip', 'inet', 'arp', 'bridge', 'netdev']:
            raise ValidationError('Family must be one of: ip, inet, arp, bridge, netdev.')
        
    def validate_expr(self, expr):
        if expr.data and not expr.data.replace(":", "").replace("-", "").replace("_", "").replace(".", "").replace("/", "").replace(" ", "").isalnum():
            raise ValidationError('Expression must be a valid expression.')
        
    def validate_handle(self, handle):
        if handle.data and not handle.data.replace(":", "").replace("-", "").replace("_", "").replace(".", "").replace("/", "").replace(" ", "").isalnum():
            raise ValidationError('Handle must be a valid handle.')
        
class AddElementSetForm(FlaskForm):
    element = StringField('Element', validators=[DataRequired()])
    
class SetForm(FlaskForm):
    VALID_TYPES = [('ipv4_addr', 'ipv4_addr'), ('ipv6_addr', 'ipv6_addr'), ('ether_addr', 'ether_addr'), ('inet_service', 'inet_service'), ('inet_proto', 'inet_proto'), ('mark', 'mark')]

    name = StringField('Name', validators=[DataRequired()])
    family = StringField('Family', validators=[DataRequired()])
    table = StringField('Table Name', validators=[DataRequired()])
    type = SelectField('Type', choices=VALID_TYPES, validators=[DataRequired()])
    description = StringField('Description', validators=[Optional()])
    submit = SubmitField('Create Set')
    
    def validate_family(self, family):
        if family.data not in ['ip', 'inet', 'arp', 'bridge', 'netdev']:
            raise ValidationError('Family must be one of: ip, inet, arp, bridge, netdev.')
        
    def validate_name(self, name):
        if " " in name.data or "-" in name.data or "/" in name.data or "." in name.data or "," in name.data or ";" in name.data or ":" in name.data or "@" in name.data or "#" in name.data or "$" in name.data or "%" in name.data or "^" in name.data or "&" in name.data or "*" in name.data or "(" in name.data or ")" in name.data or "+" in name.data or "=" in name.data or "[" in name.data or "]" in name.data or "{" in name.data or "}" in name.data or "|" in name.data or "<" in name.data or ">" in name.data or "?" in name.data or "!" in name.data or "'" in name.data or '"' in name.data or "\\" in name.data or "`" in name.data or "~" in name.data:
            raise ValidationError('Set name invalid. (Must not contain special characters or spaces.)')
        
    def validate_type(self, type):
        if type.data not in [choice[0] for choice in self.VALID_TYPES]:
            raise ValidationError('Type must be one of: ' + ', '.join([choice[0] for choice in self.VALID_TYPES]))    
        
class DeleteElementSet(FlaskForm):
    element = StringField('Element', validators=[DataRequired()])
    