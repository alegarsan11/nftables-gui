from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
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
    email = StringField('Email', validators=[DataRequired(), Email()])
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
