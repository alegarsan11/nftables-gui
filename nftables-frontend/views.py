from flask import Blueprint, render_template, flash, redirect, url_for
from flask_login import login_user, logout_user, login_required, current_user
from models import Chain, Rule, Table, User
from forms.forms import LoginForm, CreateUserForm, TableForm, UpdateUserForm
import service, api, os, matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

visualization_bp = Blueprint('visualization', __name__)
creation_bp = Blueprint('creation', __name__)

@visualization_bp.route('/list_ruleset')
def list_ruleset():
    result = api.list_ruleset_request()    
    return render_template('ruleset.html', ruleset=result)

@visualization_bp.route('/')
def main_view():
    if current_user.is_authenticated:
        host = os.uname().nodename
        ip_address = os.popen('hostname -I').read().split(" ")[0] 
        categories = ['Reglas', 'Cadenas', 'Tablas']
        # Get the number of rules, chains and tables
        n_tables = Table.query.count()
        n_chains = Chain.query.count()
        n_rules = Rule.query.count()
        values = [n_rules, n_chains, n_tables]
        plt.figure(figsize=(8, 6))
        plt.bar(categories, values, color=['blue', 'green', 'orange'])
        plt.xlabel('Elemento nftables')
        plt.ylabel('Número')
        plt.title('Número de elementos nftables')
        plt.grid(axis='y')
        if os.path.exists('static/nftables_info.png'):
            os.remove('static/nftables_info.png')
        plt.savefig('static/nftables_info.png')
        plt.close()       
        return render_template('main.html', nftables_info_image=url_for('static', filename='nftables_info.png') , current_user=current_user, hostname=host, ip_address=ip_address)
    else:
        form = LoginForm()
        return render_template('login.html', form=form)
    
@visualization_bp.route('/users', methods=['GET'])  
def users():
    users = User.query.all()
    return render_template('users/users.html', users=users)

@visualization_bp.route('/edit_user/<user_id>')
def edit_user(user_id):
    user = service.get_user(user_id)
    form = UpdateUserForm(object=user)
    return render_template('users/edit_user.html',user=user, form=form)

@visualization_bp.route('/table/<table_id>')
def get_table(table_id):
    table = service.get_table(table_id)
    chains = api.list_table_request(table.name, table.family)
 
    for chain in chains:
        print(chain)
        if(service.check_existing_chain(chain["name"], table_id) == False):
            hook_type = None
            priority = None
            if("hook_type" in chain):
                hook_type = chain['hook_type']
            if("priority" in chain):
                priority = chain['priority']
            service.insert_chain(chain_name=chain["name"], family=chain["family"], type=chain['type'], policy=chain['policy'], table_id=table_id, hook_type=hook_type, priority=priority)
    chains = service.get_chains_from_table(table_id)
    return render_template('tables/table.html', table=table, chains=chains)


@creation_bp.route('/edit_user/<user_id>', methods=['POST'])
def edit_user_post(user_id):
    form = UpdateUserForm()
    if form.validate_on_submit():
        service.edit_user(user_id, form.username.data, form.email.data, form.password.data, form.role.data, form.is_active.data)
        flash('User edited successfully.')
        return redirect('/users')
    else:
        flash('Error editing user.')
        print(form.errors)
        user = service.get_user(user_id)
        return render_template('users/edit_user.html', user=user ,form=form)

@visualization_bp.route('/delete_user/<user_id>')
def delete_user(user_id):
    user = User.query.get(user_id)
    if(user != None):
        service.delete_user(user_id)
    return redirect('/users')

@visualization_bp.route('/login')
def login_view():
    form = LoginForm()
    return render_template('login.html', form=form)

@visualization_bp.route('/tables')
def tables():
    result = api.list_tables_request()
    family = []
    names = []
    for line in result.split("table "):
        family.append(line.split(" ")[0])
        variable = line.split(" ")[-1]
        names.append(variable)
    for i in range(len(names)):
        if(i != 0) and service.check_existing_table(names[i], family[i]) == False:
            service.insert_in_table(names[i], family[i])
    tables = service.get_tables()
    print(tables)
    return render_template('tables/tables.html', tables=tables)

@creation_bp.route('/add_table')
def add_table_get():
    return render_template('tables/add_table.html', form=TableForm())

@creation_bp.route('/add_table', methods=['POST'])
def add_table_post():
    form = TableForm()
    if form.validate_on_submit():
        result = service.insert_in_table(form.name.data, form.family.data, form.description.data)
        if result == "Success":
            response = api.create_table_request(form.name.data, form.family.data)
            if(response == "Success"):
                flash('Table created successfully.')
                return redirect('/tables')
            else:
                flash('Error creating table.')
                print(response)
                return render_template('tables/add_table.html', form=form)
        else:
            flash('Error creating table.')
            print(result)
    else:
        flash('Error creating table.')
        print(form.errors)
    return render_template('tables/add_table.html', form=form)

@creation_bp.route('/delete_table/<table_id>')
def delete_table(table_id):
    table = Table.query.get(table_id)
    response = api.delete_table_request(table.name, table.family)
    service.delete_table(table_id)
    return redirect('/tables')

@creation_bp.route('/login', methods=['POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        print('Validating login form...')
        user = User.query.filter_by(username=form.username.data).first()
        if user is not None and user.check_password(form.password.data):
            login_user(user)
            flash('Logged in successfully.')
            return redirect('/')
        else:
            form.validate_username(form.username)
            flash('Invalid username or password.')
    else:
        print('Invalid username or password.')
        print(form.errors)
        flash('Invalid username or password.')
    return render_template('login.html', form=form)

@visualization_bp.route('/create_user')
def create_user():
    
    return render_template('users/create_user.html', form=CreateUserForm())

@creation_bp.route('/create_user', methods=['POST'])
def create_user_post():
    form = CreateUserForm()
    if form.validate_on_submit():
        service.create_user(form.username.data, form.email.data, form.password.data, form.role.data, True)
        flash('User created successfully.')
        return redirect('/users')
    else:
        flash('Error creating user.')
        print(form.errors)
        return render_template('users/create_user.html', form=form)

@creation_bp.route("/logout")
def logout():
    '''Cerrar sesión'''
    logout_user()
    return redirect('/')
    
