from flask import Blueprint, render_template, flash, redirect, url_for
from flask_login import login_user, logout_user, login_required, current_user
from models import BaseChain, Chain, Rule, Statement, Table, User, db
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
    service.clean_table(table_id, family)
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
            service.iteration_on_chains(rule, chain_id, family, handle=rule["rule"]["handle"])
            statements = service.get_statements_from_chain(chain_id=chain.name, family=family)
    return render_template('chains/chain.html', chain=chain, statements=statements)

@creation_bp.route('/create_base_chain/', methods=['POST'])
def create_base_chain_post():
    form = BaseChainForm()
    form.family.data = form.table.data.split("&&")[0]
    form.table.data = form.table.data.split("&&")[1]
    if form.priority.data == None:
        form.priority.data = 0
    table = service.get_table(form.table.data, form.family.data)
    if form.validate_on_submit():
        response = api.create_base_chain_request(form.name.data, form.family.data, form.table.data, priority=form.priority.data, hook_type=form.hook_type.data, policy=form.policy.data, type=form.type.data)
        if(response == "Success"):
            flash('Base chain created successfully.')
        else:
            flash('Error creating base chain.')
            return render_template('chains/create_base_chain.html', form=form, tables=Table.query.all())
    else:
        return render_template('chains/create_base_chain.html', form=form, tables=Table.query.all())

    return redirect('/chains')

@creation_bp.route('/create_chain/', methods=['POST'])
def create_chain_post():
    form = ChainForm()
    form.family.data = form.table.data.split("&&")[1]
    form.table.data = form.table.data.split("&&")[0]
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
    service.delete_table(table_id, family)
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
    service.load_data(True)
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
            rule_ = service.get_rule_by_chain_and_handle(rule.chain.id,rule.family ,rule_aux["rule"]["handle"])
            if(rule_ == None):
                rule.handle = rule_aux["rule"]["handle"]
                db.session.commit()
            if str(rule.handle) == str(rule_aux["rule"]["handle"]):    
                service.iteration_on_chains(rule=rule_aux, chain_id=rule.chain.name, family=rule.family, handle=rule_aux["rule"]["handle"], rule_id=rule_id)

    statements = service.get_statements_from_rule(rule_id)
    statements = [s for s in statements if s and not s.is_empty()]

    return render_template('rules/rule.html', rule=rule, statements=statements)

@visualization_bp.route('/rules/create_rule')
def create_rule():
    form = RuleForm()
    chains = service.get_chains()
    return render_template('rules/create_rule.html', form=form, chains=chains)

@visualization_bp.route('/rules/<rule_id>/delete')
def delete_rule(rule_id):
    response = api.delete_rule_request(rule_id)
    service.delete_rule(rule_id)
    return redirect('/rules')

@creation_bp.route('/rules/create_rule', methods=['POST'])
def create_rule_post():
    form = RuleForm()
    # El handle ha de asignarse con la peticion de la api y el resultado que se obtenga de esta rule
    chaind_id = form.chain.data.split("&&")[0]
    table_name = form.chain.data.split("&&")[2]
    family = form.chain.data.split("&&")[1]
    chain_name = form.chain.data.split("&&")[3]
    form.chain.data = chaind_id
    form.family.data = str(family)
    chains = service.get_chains()
    if form.validate_on_submit():
        if (not (form.statements.limit.data or form.statements.log.data or form.statements.counter.data or form.statements.masquerade.data or form.statements.redirect.data or form.statements.src_nat.data or form.statements.dst_nat.data or form.statements.limit_per.data) or (form.statements.data == None and form.statements_term.data == None)):
            flash('Error creating rule.')
            return render_template('rules/create_rule.html', form=form, chains=chains)
        if form.statements_term.jump.data != "--Selects--":
            if service.get_chain(chain_id=form.statements_term.jump.data ,table=table_name, family=family) == None:
                flash('Error creating rule.')
                return render_template('rules/create_rule.html', form=form, chains=chains)
        if  form.statements_term.go_to.data != "--Selects--":
            if service.get_chain(chain_id=form.statements_term.go_to.data ,table=table_name, family=family) == None:
                flash('Error creating rule.')
                return render_template('rules/create_rule.html', form=form, chains=chains)
        if service.get_rules() != []:
            id_ = service.get_rules()[-1].id + 1
        else:
            id_ = 1
        expr = str(form.statements.data) + str(form.statements_term.data)
        #if (form.statements.data != None or form.statements_term.data != None):
            #service.from_form_to_statement(form.statements.data, form.statements_term.data, id_, form.statement_select.data)
        service.insert_rule_with_table(chain_id=form.chain.data, expr=expr, family=form.family.data, description=form.description.data, table_id=table_name)    
        result = api.create_rule_request(rule_id=id_, chain_name=chain_name, family=family, chain_table=table_name, statement=form.statements.data, statement_term=form.statements_term.data, statement_type=form.statement_select.data)
        if(result == "Success"):
            flash('Rule created successfully.')
        else:
            flash('Error creating rule.')
            
            return render_template('rules/create_rule.html', form=form, chains=chains)
        return redirect('/rules/' + str(id_))
    else:
        flash('Error creating rule.')

    return render_template('rules/create_rule.html', form=form, chains=chains)