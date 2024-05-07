import ast
from flask import Blueprint, render_template, flash, redirect, url_for, request
from flask_login import login_user, logout_user, login_required, current_user
from models import BaseChain, Chain, Rule, Statement, Table, User, db
from forms.forms import AddElementMap, AddElementSetForm, AddListForm, BaseChainForm, ChainForm, DeleteElementMap, DeleteElementSet, LoginForm, CreateUserForm, MapForm, RuleForm, SetForm, TableForm, UpdateUserForm
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

@creation_bp.route('/list_ruleset', methods=['POST'])
@login_required
def list_ruleset_post():
    result = api.list_ruleset_request()
    service.delete_all_data()
    service.load_data(True)
    return render_template('ruleset.html', ruleset=result)

@visualization_bp.route('/')
def main_view():
    if current_user.is_authenticated:
        host = os.uname().nodename
        ip_address = os.popen('hostname -I').read().split(" ")[0] 
        categories = ['Rules', 'Chains', 'Tables']
        # Get the number of rules, chains and tables
        values = service.load_data(False)
        image_path = 'static/img/nftables_info.png'
        plt.figure(figsize=(8, 6))
        plt.bar(categories, values, color=['blue', 'green', 'orange'])
        plt.xlabel('nftables elements')
        plt.ylabel('Number')
        plt.title('Number of nftables elements')
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
        service.create_user(form.username.data, form.password.data, form.role.data, True)
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
    objects = service.get_objects()
    return render_template('rules/create_rule.html', form=form, chains=chains, objects=objects)

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
        if (not (form.statements.limit.data or form.statements.log.data or form.statements.counter.data or form.statements.masquerade.data or form.statements.redirect.data or form.statements.src_nat.data or form.statements.dst_nat.data or form.statements.limit_per.data or form.statements_term.accept.data or form.statements_term.reject.data or form.statements_term.drop.data or form.statements_term.queue.data or form.statements_term.jump.data or form.statements_term.go_to.data or form.statements_term.return_.data) 
            or (form.statements.data == None and form.statements_term.data == None)):
            flash('Error creating rule.')
            objects = service.get_objects()
            return render_template('rules/create_rule.html', form=form, chains=chains, objects=objects)
        if form.statements_term.jump.data != "--Selects--":
            if service.get_chain(chain_id=form.statements_term.jump.data ,table=table_name, family=family) == None:
                flash('Error creating rule.')
                objects = service.get_objects()
                return render_template('rules/create_rule.html', form=form, chains=chains, objects=objects)
        if  form.statements_term.go_to.data != "--Selects--":
            if service.get_chain(chain_id=form.statements_term.go_to.data ,table=table_name, family=family) == None:
                flash('Error creating rule.')
                objects = service.get_objects()
                return render_template('rules/create_rule.html', form=form, chains=chains, objects=objects)
        if service.get_rules() != []:
            id_ = service.get_rules()[-1].id + 1
        else:
            id_ = 1
        expr = str(form.statements.data) + str(form.statements_term.data)
        service.insert_rule_with_table(chain_id=form.chain.data, expr=expr, family=form.family.data, description=form.description.data, table_id=table_name)    
        result = api.create_rule_request(rule_id=id_, chain_name=chain_name, family=family, chain_table=table_name, statement=form.statements.data, statement_term=form.statements_term.data, statement_type=form.statement_select.data)
        if(result == "Success"):
            flash('Rule created successfully.')
        else:
            flash('Error creating rule.')
            
            objects = service.get_objects()
            return render_template('rules/create_rule.html', form=form, chains=chains, objects=objects)
        return redirect('/rules/' + str(id_))
    else:
        flash('Error creating rule.')

    return render_template('rules/create_rule.html', form=form, chains=chains)

@visualization_bp.route('/sets')
def get_sets():
    service.insert_sets()
    return render_template('sets/sets.html', sets=service.get_sets())

@visualization_bp.route('/sets/<set_id>')
def get_set(set_id):
    set_ = service.get_set(set_id)
    result = api.list_elements_in_set(set_.name, set_.family, set_.table_id)
    elements = ""
    for i, item in enumerate(result[1]["nftables"]):
        if("set" in item) and item["set"]["name"] == set_.name and item["set"]["family"] == set_.family and item["set"]["table"] == set_.table_id:
            if item.get("set").get("elem", None) != None:
                elements = str(item["set"]["elem"])
    service.insert_elements_in_set(set_id, elements)
    return render_template('sets/set.html', set=set_)

@visualization_bp.route('/sets/<set_id>/add_element')
def add_element(set_id):
    form = AddElementSetForm()
    return render_template('sets/add_element.html', form=form)

@creation_bp.route('/sets/<set_id>/add_element', methods=['POST'])
def add_element_post(set_id):
    form = AddElementSetForm()
    set_ = service.get_set(set_id)
    if service.validate_element(form.element.data, set_id) and (form.element.data != None or form.element.data != ""):
        response = api.add_element_to_set_request(set_family=set_.family, element=form.element.data, set_name=set_.name, set_table=set_.table_id)
        if response == "Success":
            flash('Element added successfully.')
        else:
            flash('Error adding element.')
        return redirect('/sets/' + set_id)
    else:
        flash('Error adding element.')
        return render_template('sets/add_element.html', form=form)
    
@visualization_bp.route('/sets/new')
def add_set():
    form = SetForm()
    tables = service.get_tables()
    return render_template('sets/create_set.html', form=form, tables=tables)

@creation_bp.route('/sets/new', methods=['POST'])
def add_set_post():
    form = SetForm()
    form.family.data = form.table.data.split("&&")[1]
    form.table.data = form.table.data.split("&&")[0]
    if form.validate_on_submit():
        service.insert_set_form(form.name.data, form.family.data, form.table.data, form.type.data, form.description.data)
        response = api.create_set_request(set_name=form.name.data, set_family=form.family.data, set_table=form.table.data, set_type=form.type.data)
        if response == "Success":
            flash('Set created successfully.')
        else:
            flash('Error creating set.')
        return redirect('/sets')
    else:
        flash('Error creating set.')
        return render_template('sets/create_set.html', form=form)
    
@visualization_bp.route('/sets/<set_id>/delete')
def delete_set(set_id):
    set_ = service.get_set(set_id)
    response = api.delete_set_request(set_name=set_.name, set_family=set_.family, set_table=set_.table_id)
    service.delete_set(set_id)
    return redirect('/sets')

@visualization_bp.route('/sets/<set_id>/delete_element')
def delete_element_set(set_id):
    form = DeleteElementSet()
    elements = service.get_elements_from_set(set_id)
    elements = ast.literal_eval(elements)
    return render_template('sets/delete_element.html', form=form, aux=elements)

@creation_bp.route('/sets/<set_id>/delete_element', methods=['POST'])
def delete_element_set_post(set_id):
    form = DeleteElementSet()
    set_ = service.get_set(set_id)
    if form.element.data != None or form.element.data != "":
        response = api.delete_element_from_set_request(set_family=set_.family, element=form.element.data, set_name=set_.name, set_table=set_.table_id)
        if response == "Success":
            flash('Element deleted successfully.')
        else:
            flash('Error deleting element.')
        return redirect('/sets/' + set_id)
    else:
        flash('Error deleting element.')
        elements = service.get_elements_from_set(set_id)
        elements = ast.literal_eval(elements)
        return render_template('sets/delete_element.html', form=form,aux=elements)
    
@visualization_bp.route('/maps')
def get_maps():
    service.insert_maps()
    maps = service.get_maps()
    return render_template('maps/maps.html', maps=maps)

@visualization_bp.route('/maps/<map_id>')
def get_map(map_id):
    map_ = service.get_map(map_id)
    result = api.list_elements_in_map(map_.name, map_.family, map_.table_id)
    elements = ""
    for i, item in enumerate(result[1]["nftables"]):
        if("map" in item) and item["map"]["name"] == map_.name and item["map"]["family"] == map_.family and item["map"]["table"] == map_.table_id:
            if item.get("map").get("elem", None) != None:
                elements = str(item["map"]["elem"])
    service.insert_elements_in_map(map_id, elements)
    return render_template('maps/map.html', map=map_)

@visualization_bp.route('/maps/new')
def add_map():
    form = MapForm()
    tables = service.get_tables()
    return render_template('maps/create_map.html', form=form, tables=tables)

@creation_bp.route('/maps/new', methods=['POST'])
def add_map_post():
    form = MapForm()
    form.family.data = form.table.data.split("&&")[1]
    form.table.data = form.table.data.split("&&")[0]
    if form.validate_on_submit():
        service.insert_map_form(form.name.data, form.family.data, form.table.data, form.type.data, form.map_type.data, form.description.data)
        response = api.create_map_request(map_name=form.name.data, map_family=form.family.data, map_table=form.table.data, map_type=form.map_type.data, type=form.type.data)
        if response == "Success":
            flash('Map created successfully.')
        else:
            flash('Error creating map.')
        return redirect('/maps')
    else:
        flash('Error creating map.')
        return render_template('maps/create_map.html', form=form)
    
@visualization_bp.route('/maps/<map_id>/delete')
def delete_map(map_id):
    map_ = service.get_map(map_id)
    response = api.delete_map_request(map_name=map_.name, map_family=map_.family, map_table=map_.table_id)
    service.delete_map(map_id)
    return redirect('/maps')

@visualization_bp.route('/maps/<map_id>/add_element')
def add_element_map(map_id):
    form = AddElementMap()
    map_ = service.get_map(map_id)
    return render_template('maps/add_element.html', form=form, map=map_)

@creation_bp.route('/maps/<map_id>/add_element', methods=['POST'])
def add_element_map_post(map_id):
    form = AddElementMap()
    map_ = service.get_map(map_id)
    if service.validate_element_map(form.key.data, form.value.data, map_id) and (form.key.data != None or form.key.data != "") and (form.value.data != None or form.value.data != ""):
        response = api.add_element_to_map_request(map_family=map_.family, key=form.key.data, value=form.value.data, map_name=map_.name, map_table=map_.table_id)
        if response == "Success":
            flash('Element added successfully.')
        else:
            flash('Error adding element.')
        return redirect('/maps/' + map_id)
    else:
        flash('Error adding element.')
        return render_template('maps/add_element.html', form=form)
    
@visualization_bp.route('/maps/<map_id>/delete_element')
def delete_element_map(map_id):
    form = DeleteElementMap()
    elements_str = service.get_elements_from_map(map_id)
    # Convierte la cadena de texto en un diccionario
    elements_dict = ast.literal_eval(elements_str)
    # Obtiene las claves del diccionario
    keys = elements_dict.keys()
    aux = list(keys)

    return render_template('maps/delete_element.html', form=form, aux=aux)

@creation_bp.route('/maps/<map_id>/delete_element', methods=['POST'])
def delete_element_map_post(map_id):
    form = DeleteElementMap()
    map_ = service.get_map(map_id)
    if form.key.data != None or form.key.data != "":
        valor = service.get_element_from_map(element=form.key.data, map_id=map_id)
        response = api.delete_element_from_map_request(map_family=map_.family, key=form.key.data , value=valor, map_name=map_.name, map_table=map_.table_id)
        if response == "Success":
            service.delete_element_from_map(element=form.key.data, map_id=map_id)
            flash('Element deleted successfully.')
        else:
            flash('Error deleting element.')
        return redirect('/maps/' + map_id)
    else:
        flash('Error deleting element.')
        elements_str = service.get_elements_from_map(map_id)
        elements_dict = ast.literal_eval(elements_str)
        keys = elements_dict.keys()
        aux = list(keys)
        return render_template('maps/delete_element.html', form=form, aux=aux)
    
@visualization_bp.route('/save-changes')
def save_changes():
    return render_template('save-changes.html')

@creation_bp.route('/save-changes', methods=['POST'])
def save_changes_post():
    type_ = request.form.get('save')
    print("TYPE")
    print(type_)
    if type_ != "" or type_ != None:
        if type_ == 'config':
            service.save_changes_permanent()
            flash('Changes saved successfully.')
        elif type_ == 'file':
            service.save_changes_on_file()
            flash('Changes discarded successfully.')
        
    return redirect('/')

@visualization_bp.route('/add-list')
def add_list():
    form = AddListForm()
    tables = service.get_tables()
    return render_template('sets/add-list.html', form=form, tables=tables)

@creation_bp.route('/add-list', methods=['POST'])
def add_list_post():
    form = AddListForm()
    lista = request.files['list'].read().decode('utf-8').split("\n")
    form.element.data = lista
    if 'txt' not in request.files['list'].filename:

        flash('Error adding list.')
        tables = service.get_tables()
        return render_template('sets/add-list.html', form=form, tables=tables, mssg="The file must be a txt file.")
    form.family.data = form.table.data.split("&&")[1]
    form.table.data = form.table.data.split("&&")[0]
    if form.validate_on_submit():
        service.create_list(form.name.data, form.family.data, form.table.data, form.type.data, lista)
        print("biuen")
        api.create_set_request(set_name=form.name.data, set_family=form.family.data, set_table=form.table.data, set_type=form.type.data)
        print("mejor")
        for item in lista:
            api.add_element_to_set_request(set_family=form.family.data, element=item, set_name=form.name.data, set_table=form.table.data)
        flash('List added successfully.')
    else:
        print("mal")
        flash('Error adding list.')
        tables = service.get_tables()
        return render_template('sets/add-list.html', form=form, tables=tables)
    return redirect('/sets')