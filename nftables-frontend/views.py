from flask import Blueprint, render_template, flash, redirect, url_for
from flask_login import login_user, logout_user, login_required, current_user
from models import BaseChain, Chain, Rule, Statement, Table, User
from forms.forms import BaseChainForm, ChainForm, LoginForm, CreateUserForm, RuleForm, TableForm, UpdateUserForm
import service, api, os, matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

visualization_bp = Blueprint('visualization', __name__)
creation_bp = Blueprint('creation', __name__)

@visualization_bp.route('/list_ruleset')
@login_required
def list_ruleset():
    result = api.list_ruleset_request()    
    return render_template('ruleset.html', ruleset=result)

@visualization_bp.route('/')
@login_required
def main_view():
    if current_user.is_authenticated:
        host = os.uname().nodename
        ip_address = os.popen('hostname -I').read().split(" ")[0] 
        categories = ['Reglas', 'Cadenas', 'Tablas']
        # Get the number of rules, chains and tables
        values = service.load_data(False)
        image_path = 'static/img/nftables_info.png'
        plt.figure(figsize=(8, 6))
        plt.bar(categories, values, color=['blue', 'green', 'orange'])
        plt.xlabel('Elemento nftables')
        plt.ylabel('Número')
        plt.title('Número de elementos nftables')
        plt.grid(axis='y')
        if os.path.exists(image_path):
            os.remove(image_path)
        plt.savefig(image_path)
        plt.close()       
        return render_template('main.html', nftables_info_image=url_for('static', filename='/img/nftables_info.png') , current_user=current_user, hostname=host, ip_address=ip_address)
    else:
        form = LoginForm()
        return render_template('login.html', form=form)
    
@visualization_bp.route('/users', methods=['GET'])  
@login_required
def users():
    users = User.query.all()
    return render_template('users/users.html', users=users)

@visualization_bp.route('/edit_user/<user_id>')
def edit_user(user_id):
    user = service.get_user(user_id)
    form = UpdateUserForm(object=user)
    return render_template('users/edit_user.html',user=user, form=form)

@visualization_bp.route('/table/<table_id>/<family>')
def get_table(table_id, family):
    table = service.get_table(table_id,family=family)
    chains = api.list_table_request(table.name, table.family)
    for chain in chains:    
        if(service.check_existing_chain(chain["name"], table_id, table.family) == True):
            hook_type = None
            priority = None
            type = None
            if("hook_type" in chain):
                hook_type = chain['hook_type']
            if("priority" in chain):
                priority = chain['priority']
            if("type" in chain):
                type = chain['type']
            if("policy" not in chain):
                chain["policy"] = None
            service.insert_chain(chain_name=chain["name"], family=chain["family"], type=type, policy=chain['policy'], table_id=table_id, hook_type=hook_type, priority=priority)
    chains = service.get_chains_from_table(table_id,family=table.family)
    return render_template('tables/table.html', table=table, chains=chains)

@visualization_bp.route('/flush_table/<table_id>/<family>')
def flush_table(table_id, family):
    table = service.get_table(table_id, family)
    response = api.flush_table_request(table.name, table.family)
    return redirect('/tables')


@creation_bp.route('/edit_user/<user_id>', methods=['POST'])
def edit_user_post(user_id):
    form = UpdateUserForm()
    if form.validate_on_submit():
        service.edit_user(user_id, form.username.data, form.email.data, form.password.data, form.role.data, form.is_active.data)
        flash('User edited successfully.')
        return redirect('/users')
    else:
        flash('Error editing user.')
        user = service.get_user(user_id)
        return render_template('users/edit_user.html', user=user ,form=form)

@visualization_bp.route('/delete_user/<user_id>')
def delete_user(user_id):
    user = User.query.get(user_id)
    if(user != None):
        service.delete_user(user_id)
    return redirect('/users')

@visualization_bp.route('/create_base_chain')
def create_base_chain():
    form = BaseChainForm()
    tables = Table.query.all()
    return render_template('chains/create_base_chain.html', form=form, tables=tables)

@visualization_bp.route('/create_chain')
def create_chain():
    form = ChainForm()
    tables = Table.query.all()
    return render_template('chains/create_chain.html', form=form, tables=tables)



@visualization_bp.route('/chain/<chain_id>/<family>/<table>')
def get_chain(chain_id, family, table):
    chain = service.get_chain(chain_id, family, table)
    rules = api.list_chain_request(chain.name, chain.family, chain.table.name)
    rules = rules["rules"]["nftables"]
    statements = []
    for i, rule in enumerate(rules):
        
        if i == 0 or i == 1:
            continue
        else:                    
            service.iteration_on_chains(rule, chain_id, family, True)
            statements = service.get_statements_from_chain(chain_id=chain.name, family=family)
    return render_template('chains/chain.html', chain=chain, statements=statements)

@visualization_bp.route('/chains/<chain_id>/<family>/<table>/edit')
def edit_chain(chain_id, family,table):
    chain = service.get_chain(chain_id, family=family, table=table)

    tables = Table.query.all()
    if chain.priority != None:
        chain.priority = int(chain.priority)
        form = BaseChainForm()
    else:
        form = ChainForm()
    form.name.data = chain.name
    form.family.data = chain.table.family
    form.policy.data = chain.policy
    form.table.data = chain.table.name
    if chain.type != None:
        form.type.data = chain.type
    if chain.priority != None:
        form.priority.data = chain.priority
    if chain.hook_type != None:
        form.hook_type.data = chain.hook_type
    form.description.data = chain.description
    
    
    if(chain.hook_type != None):
        return render_template('chains/edit_base_chain.html',chain=chain, form=form, tables=tables)
    return render_template('chains/edit_chain.html',chain=chain, form=form, tables=tables)

@creation_bp.route('/chains/<chain_id>/<family>/<table>/edit', methods=['POST'])
def edit_chain_post(chain_id, family, table):
    form = ChainForm()
    table = service.get_table(form.table.data)
    response = None
    form.family.data = table.family
    if form.hook_type.data == None:
        response = api.edit_chain_request(name=form.name.data, family=form.family.data, policy=form.policy.data, table=form.table.data, type=form.type.data, priority=form.priority.data, hook_type=form.hook_type.data)
    if form.hook_type.data != None:
        response = api.edit_base_chain_request(name=form.name.data, family=form.family.data, policy=form.policy.data, table=form.table.data, type=form.type.data, priority=form.priority.data, hook_type=form.hook_type.data)  
    if(response == "Success"):
        service.edit_chain(chain_description=form.description.data, chain_name=form.name.data, family=form.family.data, policy=form.policy.data, type=form.type.data, priority=str(form.priority.data), hook_type=form.hook_type.data)
        flash('Chain edited successfully.')
        return redirect('/chains')
    else:
        flash('Error editing chain.')
        chain = service.get_chain(chain_id, family, table)
        form.name.data = chain.name
        form.family.data = chain.table.family
        form.policy.data = chain.policy
        form.table.data = chain.table.name
        form.type.data = chain.type
        form.priority.data = chain.priority
        form.hook_type.data = chain.hook_type
        form.description.data = chain.description
        return render_template('chains/edit_chain.html', chain=chain, form=form)

@creation_bp.route('/create_base_chain/', methods=['POST'])
def create_base_chain_post():
    form = BaseChainForm()
    table = service.get_table(form.table.data, form.family.data)
    form.family.data = table.family
    if form.valdate_on_submit():
        response = api.create_base_chain_request(form.name.data, form.family.data, form.table.data, priority=form.priority.data, hook_type=form.hook_type.data, policy=form.policy.data, type=form.type.data)
    else:
        return render_template('chains/create_base_chain.html', form=form, tables=Table.query.all())
    if(response == "Success"):
        flash('Base chain created successfully.')
    else:
        flash('Error creating base chain.')
    return redirect('/chains')

@creation_bp.route('/create_chain/', methods=['POST'])
def create_chain_post():
    form = ChainForm()
    form.table.data = form.table.data.split(" -")[0]
    table = service.get_table(form.table.data, form.family.data)
    form.family.data = table.family
    if form.validate_on_submit():
        response = api.create_chain_request(form.name.data, form.family.data, form.table.data, policy=form.policy.data)
    else:
        return render_template('chains/create_chain.html', form=form, tables=Table.query.all())
    if response == "Success":
        flash('Chain created successfully.')
    else:
        flash('Error creating chain.')
    return redirect('/chains')

@visualization_bp.route('/login')
def login_view():
    form = LoginForm()
    return render_template('login.html', form=form)

@visualization_bp.route('/tables')
@login_required
def tables():
    result = api.list_tables_request()
    family = []
    names = []
    for line in result.split("table "):
        family.append(line.split(" ")[0])
        variable = line.split(" ")[-1]
        variable = str(variable)
        names.append(variable)
    for i in range(len(names)):
        names[i] = names[i].replace("\n", "")
        if(i != 0) and service.check_existing_table(names[i], family[i]) == False:
            service.insert_in_table(names[i], family[i])
    tables = service.get_tables()
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
                return render_template('tables/add_table.html', form=form)
        else:
            flash('Error creating table.')
    else:
        flash('Error creating table.')
    return render_template('tables/add_table.html', form=form)

@creation_bp.route('/delete_table/<table_id>/<family>')
def delete_table(table_id, family):
    table = service.get_table(table_id, family)
    response = api.delete_table_request(table.name, table.family)
    service.delete_table(table_id)
    return redirect('/tables')

@creation_bp.route('/login', methods=['POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is not None and user.check_password(form.password.data):
            login_user(user)
            flash('Logged in successfully.')
            return redirect('/')
        else:
            form.validate_username(form.username)
            flash('Invalid username or password.')
    else:
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
        return render_template('users/create_user.html', form=form)

@creation_bp.route("/logout")
def logout():
    '''Cerrar sesión'''
    logout_user()
    return redirect('/')

@visualization_bp.route("/chains")
@login_required
def get_chains():
    result = api.list_chains_request()
    for item in result["chains"]["nftables"]:
        if("chain" in item):
            if(service.check_existing_chain(item["chain"]["name"], item["chain"]["table"], item["chain"]["family"]) == True):
                prio = None
                hook = None
                type = None
                if("prio" in item["chain"]):
                    prio = item["chain"]["prio"]
                if("hook" in item["chain"]):
                    hook = item["chain"]["hook"]
                if("policy" not in item["chain"]):
                    item["chain"]["policy"] = None
                if("type" in item["chain"]):
                    type = item["chain"]["type"]
                service.insert_chain(item["chain"]["name"], item["chain"]["family"], item["chain"]["policy"], item["chain"]["table"],type=type,  priority=prio, hook_type=hook)
    chains = service.get_chains()
    return render_template('chains/chains.html', chains=chains)

@creation_bp.route('/chains/<chain_id>/<family>/<table>/delete')
def delete_chain(chain_id, family, table):
    chain = service.get_chain(chain_id,family, table)
    response = api.delete_chain_request(chain.name, chain.family, chain.get_table().name)
    service.delete_chain(chain_id, family, table)
    return redirect('/chains')

@creation_bp.route('/chains/<chain_id>/<family>/<table>/flush')
def flush_chain(chain_id, family,table):
    chain = service.get_chain(chain_id,family,table)
    response = api.flush_chain_request(chain.name, chain.family, chain.table.name)
    service.delete_rules_form_chain(chain_id, family, table)
    return redirect('/chains')

@visualization_bp.route('/rules')
@login_required
def get_rules():
    rules = service.get_rules()

    return render_template('rules/rules.html', rules=rules)

@visualization_bp.route('/rules/<rule_id>')
def get_rule(rule_id):
    rule = service.get_rule(rule_id)
    rule_result = api.list_chain_request(rule.chain.name, rule.family, rule.chain.table.name)
    service.delete_statements_from_rule(rule_id)
    for i, rule_aux in enumerate(rule_result["rules"]["nftables"]):
        if i == 0 or i == 1:
            continue
        else:
            service.iteration_on_chains(rule=rule_aux, chain_id=rule.chain.name, family=rule.family, condicion=True)
    
    statements = service.get_statements_from_rule(rule_id)
    return render_template('rules/rule.html', rule=rule, statements=statements)

@visualization_bp.route('/rules/create_rule')
def create_rule():
    form = RuleForm()
    chains = service.get_chains()
    return render_template('rules/create_rule.html', form=form, chains=chains)

@creation_bp.route('/rules/create_rule', methods=['POST'])
def create_rule_post():
    form = RuleForm()
    # El handle ha de asignarse con la peticion de la api y el resultado que se obtenga de esta rule
    chain_name = form.chain.data.split("-")[0]
    table_name = form.chain.data.split("-")[2]
    family = form.chain.data.split("-")[1]
    form.chain.data = chain_name
    form.family.data = family
    if form.validate_on_submit():
        id_ = service.get_rules()[-1].id + 1
        expr = str(form.statements.data) + str(form.statements_term.data)
        print("Statements")
        print(form.statements.data)
        print(form.statements_term.data)
        if (form.statements.data != None or form.statements_term.data != None):
            print("HA ENTRADO")
            service.from_form_to_statement(form.statements.data, form.statements_term.data, id_)
        service.insert_rule_with_table(chain_id=form.chain.data, handle=2, expr=expr, family=form.family.data, description=form.description.data, table_id=table_name)    
        result = api.create_rule_request(id_, chain_name, family, table_name)
        # Añadir el Handle desde otra peticion para obtener datos
        return redirect('/rules/' + str(id_))
    else:
        flash('Error creating rule.')
    chains = service.get_chains()
    return render_template('rules/create_rule.html', form=form, chains=chains)