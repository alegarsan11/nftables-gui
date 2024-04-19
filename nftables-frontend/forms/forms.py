from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, IntegerField
from wtforms.validators import DataRequired, Email, EqualTo
from wtforms import ValidationError
from models import Table, User

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
    table = SelectField('Table', validators=[DataRequired()])
    type = SelectField('Type', choices=[('filter', 'filter'), ('nat', 'nat'), ('route', 'route'), ('mangle', 'mangle'), ('raw', 'raw')], validators=[DataRequired()])
    family = SelectField('Family', validators=[DataRequired()])
    policy = SelectField('Policy', choices=[('accept', 'accept'), ('drop', 'drop'), ('reject', 'reject'), ('dnat', 'dnat'), ('snat', 'snat'), ('masquerade', 'masquerade'), ('redirect', 'redirect'), ('log', 'log'), ('continue', 'continue'), ('return', 'return'), ('jump', 'jump'), ('queue', 'queue'), ('unreachable', 'unreachable'), ('error', 'error'), ('broadcast', 'broadcast'), ('dnat', 'dnat'), ('snat', 'snat'), ('redirect', 'redirect'), ('mirror', 'mirror'), ('tproxy', 'tproxy'), ('netmap', 'netmap'), ('nflog', 'nflog'), ('nfqueue', 'nfqueue'), ('nfacct', 'nfacct'), ('nfct', 'nfct'), ('nftrace', 'nftrace'), ('nftlb', 'nftlb')], validators=[DataRequired()])
    description = StringField('Description')
    hook_type = SelectField('Hook Type', choices=[('prerouting', 'prerouting'), ('input', 'input'), ('forward', 'forward'), ('output', 'output'), ('postrouting', 'postrouting')], validators=[DataRequired()])
    priority = IntegerField('Priority', validators=[DataRequired()])
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
        if policy.data not in ['accept', 'drop', 'reject', 'dnat', 'snat', 'masquerade', 'redirect', 'log', 'continue', 'return', 'jump', 'queue', 'unreachable', 'error', 'broadcast', 'dnat', 'snat', 'redirect', 'mirror', 'tproxy', 'netmap', 'nflog', 'nfqueue', 'nfacct', 'nfct', 'nftrace', 'nftlb']:
            raise ValidationError('Policy must be one of: accept, drop, reject, dnat, snat, masquerade, redirect, log, continue, return, jump, queue, unreachable, error, broadcast, dnat, snat, redirect, mirror, tproxy, netmap, nflog, nfqueue, nfacct, nfct, nftrace, nftlb.')
        
    def validate_hook_type(self, hook_type):
        if hook_type.data not in ['prerouting', 'input', 'forward', 'output', 'postrouting']:
            raise ValidationError('Hook type must be one of: prerouting, input, forward, output, postrouting.')
        
    def validate_type(self, type):
        if type.data not in ['filter', 'nat', 'route', 'mangle', 'raw']:
            raise ValidationError('Type must be one of: filter, nat, route, mangle, raw.')
        
    def validate_priority(self, priority):
        if priority.data > 300 or priority.data < -400 or priority.data != int(priority.data):
            raise ValidationError('Priority must be between -400 and 300.')
        
