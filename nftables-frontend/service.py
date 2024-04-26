import json
from models import Chain, NotTerminalStatement, Rule, Statement, Table, BaseChain, TerminalStatement, db, User
from flask_login import LoginManager
import api

login_manager = LoginManager()

def create_default_user():
    user = User.query.filter_by(username='default').first()
    if not user:
        user = User(username='default',password="defaultpassword" ,role="administrator" ,is_active=True)
        db.session.add(user)
        db.session.commit()
        
def create_user(username, email, password, role, is_active):
    user = User(username=username, email=email, password=password, role=role, is_active=is_active)
    db.session.add(user)
    db.session.commit()
    
def check_existing_table(name, family):
    table = Table.query.filter_by(name=name, family=family).first()
    if table:
        return True
    return False
    
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def edit_user(user_id, username, email, role, is_active):
    user = User.query.get(user_id)
    user.username = username
    user.email = email
    user.role = role
    user.is_active = is_active
    db.session.commit()
    
def get_table(table_id):
    table = Table.query.filter_by(name=table_id).first()
    return table

def get_table(table_id, family):
    table = Table.query.filter_by(name=table_id, family=family).first()
    return table


def get_users():
    return User.query.all()

def get_user(user_id):
    user = User.query.get(user_id)
    return user

def delete_user(user_id):
    user = User.query.get(user_id)
    db.session.delete(user)
    db.session.commit()


def insert_in_table(name, family, description=None):
    try:
        Table(name=name, family=family, description=description).save()
    except Exception as e:
        db.session.rollback()
        return str(e)
    return "Success"

def delete_table(table_id):
    table = Table.query.get(table_id)
    db.session.delete(table)
    db.session.commit()
    

def get_tables():
    return Table.query.all()

def insert_chains(table_id, chains):
    table = Table.query.get(table_id)
    table.chains = chains
    db.session.commit()
    
def insert_chain(chain_name, family, policy, table_id, type,  hook_type=None, priority=None):
    if(hook_type != None and priority != None):
        chain = BaseChain(name=chain_name, family=family, type=type, policy=policy, table_id=table_id, hook_type=hook_type, priority=priority)
    else:
        chain = Chain(name=chain_name, family=family, table_id=table_id, policy=policy)
    db.session.add(chain)
    db.session.commit()
    
def check_existing_chain(chain_name, table_id, family):
    chain = Chain.query.filter_by(name=chain_name, table_id=table_id, family=family).first()
    if chain:
        return False
    return True

def get_chains_from_table(table_id, family):
    table = Table.query.filter_by(name=table_id, family=family).first()
    return table.chains

def get_chains():
    return Chain.query.all()


def get_chain(chain_id, family, table):
    chain = Chain.query.filter_by(name=chain_id, family=family, table_id=table).first()
    base_chain = BaseChain.query.filter_by(name=chain_id, family=family, table_id=table).first()
    if base_chain:
        return base_chain
    return chain


def check_existing_rule(chain_id, handle, family):
    rule = Rule.query.filter_by(chain_id=chain_id, handle=handle, family=family).first()
    if rule:
        return True
    return False

def insert_rule_with_table(chain_id, family, expr, table_id, description=None):
    chain = get_chain(chain_id, family, table_id)
    print(chain.table.name)
    rule = Rule(chain_id=chain.name, family=family, expr=expr, description=description)
    db.session.add(rule)
    db.session.commit()
    return rule.id

def insert_rule(chain_id, family, expr, handle, description=None):
    rule = Rule(chain_id=chain_id, family=family, expr=expr, handle=handle, description=description)
    db.session.add(rule)
    db.session.commit()
    return rule.id
    
def get_rules_from_chain(chain_id):
    chain = Chain.query.get(chain_id)
    return chain.rules

def get_rules():
    return Rule.query.all()

def from_form_to_statement(statement, statement_term, rule_id, statement_select):
    saddr = None
    daddr = None
    sport = None
    dport = None
    accept = None
    drop = None
    reject = None
    log = None
    nflog = None
    limit = None
    return_ = None
    jump = None
    masquerade = None
    go_to = None
    queue = None
    counter = None
    protocol = None
    snat = None
    dnat = None
    input_interface = None
    output_interface = None
    redirect = None
    if statement_select == "terminal":
        saddr = statement_term.get("src_ip")
        daddr = statement_term.get("dst_ip")
        sport = statement_term.src_port.data
        dport = statement_term.dst_port.data
        protocol = statement_term.protocol.data
        input_interface = statement_term.input_interface.data
        output_interface = statement_term.output_interface.data
        if statement_term.accept.data == True:
            accept = True
        else:
            accept = None
        if statement_term.drop.data == True:
            drop = True
        else:
            drop = None
        if statement_term.reject.data == True:
            reject = True
        else:
            reject = None
        if statement_term.return_.data == True:
            return_ = True
        else:
            return_ = None
        if statement_term.jump.data != None:
            jump = True
        else:
            jump = None
        if statement_term.go_to.data != None:
            go_to = True
        else:
            go_to = None
        if statement_term.queue.data != None:
            queue = True
        else:
            queue = None

        insert_statement(rule_id=rule_id, sport=sport, dport=dport, saddr=saddr, daddr=daddr, protocol=protocol, accept=accept, drop=drop, reject=reject, log=log, nflog=nflog , limit=limit, counter=counter, return_=return_, jump=jump, go_to=go_to, queue=queue, masquerade=masquerade, snat=snat, dnat=dnat, redirect=redirect, input_interface=input_interface, output_interface=output_interface)

    else:
        saddr = statement.get("src_ip")
        daddr = statement.get("dst_ip")
        sport = statement.get('src_port')
        dport = statement.get('dst_port')
        protocol = statement.get('protocol')
        input_interface = statement.get('input_interface')
        output_interface = statement.get('output_interface')
        if statement_term.get("log") != None:
            log = True
        else:
            log = None
        if statement_term.get("nflog") != None:
            nflog = True
        else:
            nflog = None
        if statement_term.get("limit") != None:
            limit = True
        else:
            limit = None
        if statement_term.get("counter") == True:
            counter = True
        else:
            counter = None
        if statement_term.get("masquerade") == True:
            masquerade = True
        else:
            masquerade = None
        if statement_term.get("snat") != None:
            snat = True
        else:
            snat = None
        if statement_term.get("dnat") != None:
            dnat = True
        else:
            dnat = None
        if statement_term.get("redirect") == True:
            redirect = True
        else:
            redirect = None
        insert_statement(rule_id=rule_id, sport=sport, dport=dport, saddr=saddr, daddr=daddr, protocol=protocol, accept=accept, drop=drop, reject=reject, log=log, nflog=nflog , limit=limit, counter=counter, return_=return_, jump=jump, go_to=go_to, queue=queue, masquerade=masquerade, snat=snat, dnat=dnat, redirect=redirect, input_interface=input_interface, output_interface=output_interface)

def edit_chain(chain_description, chain_name, family, policy, type, hook_type=None, priority=None):
    chain = Chain.query.get(chain_name)
    chain.name = chain_name
    chain.family = family
    chain.policy = policy
    chain.type = type
    chain.description = chain_description
    if(hook_type != None and priority != None):
        base_chain = BaseChain.query.get(chain_name)
        base_chain.name = chain_name
        base_chain.family = family
        base_chain.policy = policy
        base_chain.type = type
        base_chain.hook_type = hook_type
        base_chain.priority = priority
        base_chain.description = chain_description
        
    db.session.commit()
    
def delete_chain(chain_id, family, table):
    chain = get_chain(chain_id, family, table)
    db.session.delete(chain)
    db.session.commit()
    
def delete_rules_form_chain(chain_id, family, table):
    chain = get_chain(chain_id, family=family, table=table)
    rules = chain.rules
    for rule in rules:
        db.session.delete(rule)
    db.session.commit()
    
def insert_statement(rule_id, saddr, daddr, sport, dport, protocol, reject=None, log=None, nflog=None, drop=None, accept=None, queue=None, limit=None, counter=None, return_=None, jump=None, go_to=None, masquerade=None, snat=None, dnat=None, redirect=None, input_interface=None, output_interface=None):
    statement_ = None
    statement = None
    
    if limit != None or log != None or nflog != None or counter != None or masquerade != None or snat != None or dnat != None or redirect != None:
        statement = NotTerminalStatement(rule_id=rule_id, src_ip=saddr, dst_ip=daddr, src_port=sport, dst_port=dport,input_interface=input_interface, output_interface=output_interface, protocol=protocol, limit=limit, log=log, nflog=nflog, counter=counter, masquerade=masquerade, snat=snat, dnat=dnat, redirect=redirect)
        db.session.add(statement)
    if reject != None or drop != None or accept != None or queue != None or return_ != None or jump != None or go_to != None :
        statement_ = TerminalStatement(rule_id=rule_id, src_ip=saddr, dst_ip=daddr, src_port=sport, dst_port=dport, input_interface=input_interface, output_interface=output_interface, protocol=protocol, reject=reject, drop=drop, accept=accept, queue=queue, return_=return_, jump=jump, go_to=go_to)
        db.session.add(statement_)
    else:
        statement_2 = Statement(rule_id=rule_id, src_ip=saddr, dst_ip=daddr, src_port=sport, dst_port=dport,input_interface=input_interface, output_interface=output_interface, protocol=protocol)
        db.session.add(statement_2)
    db.session.commit()

def check_existing_statement( saddr, daddr, sport, dport, protocol, accept, drop, reject, log, nflog, limit, counter, return_, jump, go_to, queue, masquerade):
    if limit != None or log != None or nflog != None or counter != None:
        statement = NotTerminalStatement( src_ip=saddr, dst_ip=daddr, src_port=sport, dst_port=dport, protocol=protocol, limit=limit, log=log, nflog=nflog, counter=counter)
    if reject != None or drop != None or accept != None or queue != None or return_ != None or jump != None or go_to != None != masquerade != None:
        statement = TerminalStatement( src_ip=saddr, dst_ip=daddr, src_port=sport, dst_port=dport, protocol=protocol, reject=reject, drop=drop, accept=accept, queue=queue, return_=return_, jump=jump, go_to=go_to)
    else:
        statement = Statement( src_ip=saddr, dst_ip=daddr, src_port=sport, dst_port=dport, protocol=protocol)
    return statement.rule_id

def check_terminal_or_not_terminal(statement):
    if statement.reject != None or statement.drop != None or statement.accept != None or statement.queue != None or statement.return_ != None or statement.jump != None or statement.go_to != None:
        return "terminal"
    return "not_terminal"

def get_statements_from_rule(rule_id):
    rule = Rule.query.filter_by(id=rule_id).first()
    statements = []
    for statement in rule.statement:
        not_terminal = NotTerminalStatement.query.filter_by(id=statement.id).first()
        terminal = TerminalStatement.query.filter_by(id=statement.id).first()
        if check_terminal_or_not_terminal(terminal) == "not_terminal":
            statements.append(not_terminal)
        elif check_terminal_or_not_terminal(terminal) == "terminal":
            statements.append(terminal)
        else:
            statements.append(statement)
    return statements

def delete_statements_from_rule(rule_id):
    rule = Rule.query.filter_by(id=rule_id).first()
    statements = rule.statement
    for statement in statements:
        db.session.delete(statement)
    db.session.commit()

def iteration_on_chains(rule, chain_id, family, handle=None, rule_id=None):
    if rule_id != None:
        rule_ = Rule.query.filter_by(id=rule_id).first()
        rule_.handle = handle
        rule_.expr = str(rule["rule"]["expr"])
        db.session.commit()
    elif check_existing_rule(handle=handle, chain_id=chain_id, family=family) == False :   
        rule_id = insert_rule(handle=str(rule["rule"]["handle"]), chain_id=rule["rule"]["chain"], family=rule["rule"]["family"], expr=str(rule["rule"]["expr"]))
    elif check_existing_rule(handle=handle, chain_id=chain_id, family=family) == True: 
        rule_ = Rule.query.filter_by(expr=str(rule["rule"]["expr"]), chain_id=chain_id, family=family).first()
        rule_id = rule_.id
        rule_.handle = handle
        rule_.expr = str(rule["rule"]["expr"])
        db.session.commit()
    print(rule["rule"]["expr"][0])
    saddr = None
    daddr = None
    sport = None
    dport = None
    accept = None
    drop = None
    reject = None
    log = None
    nflog = None
    limit = None
    return_ = None
    jump = None
    masquerade = None
    go_to = None
    queue = None
    counter = None
    protocol = None
    protocol = None
    snat = None
    dnat = None
    input_interface = None
    output_interface = None
    redirect = None
    for j, expr in enumerate(rule["rule"]["expr"]):
        
        if expr.get("match", None) != None and expr.get("match").get("left", None) != None and expr.get("match").get("left").get("payload", None) != None:
            match = expr.get("match")
            payload = match.get("left").get("payload")
            right = match.get("right")
            if payload.get("field") == "saddr":
                saddr = str(right)
            if payload.get("field") == "daddr":
                daddr = str(right)
            if payload.get("field") == "sport":
                sport = str(right)
            if payload.get("field") == "dport":
                dport = str(right)
            if payload.get("protocol", None) != None :
                protocol = str(payload.get("protocol"))
        if expr.get("match", None) != None and expr.get("match").get("left", None) != None and expr.get("match").get("left").get("meta", None) != None and expr.get("match").get("left").get("meta").get("key", None) != None:
            meta = expr.get("match").get("left").get("meta")
            if "iifname" in meta.get("key"): 
                input_interface = str(expr.get("match").get("op") + " " + expr.get("match").get("right"))
            if "oifname" in meta.get("key") :
                output_interface = str(expr.get("match").get("op") + " " + expr.get("match").get("right"))
        if expr.get("counter", None) != None:
            counter = str(expr.get("counter"))
        if expr.get("accept", None) != None:
            accept = str(expr.get("accept"))
        if expr.get("drop", None) != None:
            drop = str(expr.get("drop"))
        if expr.get("reject", None) != None:
            reject = str(expr.get("reject"))
        if expr.get("log", None) != None:
            log = str(expr.get("log"))
        if expr.get("nflog", None) != None:
            nflog = str(expr.get("nflog"))
        if expr.get("limit", None) != None:
            limit = str(expr.get("limit"))
        if expr.get("snat", None) != None:
            snat = str(expr.get("snat"))
        if expr.get("dnat", None) != None:
            dnat = str(expr.get("dnat"))
        if expr.get("redirect", None) != None:
            redirect = str(expr.get("redirect"))
        if "masquerade" in expr:
            masquerade = True
        if "return" in expr:
            return_ = True
        if expr.get("jump", None) != None:
            jump = str(expr.get("jump"))
        if expr.get("go_to", None) != None:
            go_to = str(expr.get("go_to"))
        if expr.get("queue", None) != None:
            queue = str(expr.get("queue"))
    if saddr != None or daddr != None or sport  != None or dport != None or protocol != None or counter != None or limit != None or log != None or nflog != None or reject != None or drop != None or accept != None or queue != None or return_ != None or jump != None or go_to != None or masquerade != None or snat != None or dnat != None or redirect != None or input_interface != None or output_interface != None:
        insert_statement(rule_id=rule_id, sport=sport, dport=dport, saddr=saddr, daddr=daddr, protocol=protocol, accept=accept, drop=drop, reject=reject, log=log, nflog=nflog, limit=limit, counter=counter, return_=return_, jump=jump, go_to=go_to, queue=queue, masquerade=masquerade, snat=snat, dnat=dnat, redirect=redirect, input_interface=input_interface, output_interface=output_interface)

                
                
def get_statements_from_chain(chain_id, family):
    chain = Chain.query.filter_by(name=chain_id, family=family).first()
    rules = chain.rules
    statements = []
    for rule in rules:
        for statement in rule.statement:
            statements.append(statement)
            
    return statements

def get_statements():
    statements = []
    rules = Rule.query.all()
    statements_all_nt = NotTerminalStatement.query.all()
    statements_all_t = TerminalStatement.query.all()
    for rule in rules:
        for statement in statements_all_nt:
            if statement.rule_id == rule.id:
                statements.append(statement)
        for statement in statements_all_t:
            if statement.rule_id == rule.id:
                statements.append(statement)

    return statements

def get_rules_from_api():
    result = api.list_tables_request()
    return result

def load_data(condicion):
    result_tables = api.list_tables_request()
    result_chains = api.list_chains_request()
    family = []
    names = []
    for line in result_tables.split("table "):
        family.append(line.split(" ")[0])
        variable = line.split(" ")[-1]
        variable = str(variable)
        names.append(variable)
    for i in range(len(names)):
        names[i] = names[i].replace("\n", "")
        if(i != 0) and check_existing_table(names[i], family[i]) == False:
            insert_in_table(names[i], family[i])
    for item in result_chains["chains"]["nftables"]:
        if("chain" in item):
            if(check_existing_chain(item["chain"]["name"], item["chain"]["table"], item["chain"]["family"]) == True):
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
                
                insert_chain(item["chain"]["name"], item["chain"]["family"], item["chain"]["policy"], item["chain"]["table"],type=type,  priority=prio, hook_type=hook)
    chains = get_chains()
    for chain in chains:
        result_rules = api.list_chain_request(chain.name, chain.family, chain.table.name)
        result_rules = result_rules["rules"]["nftables"]
        for i, rule in enumerate(result_rules):
            if i ==0 or i ==1:
                continue
            else:
                if check_existing_rule(handle=str(rule["rule"]["handle"]), chain_id=chain.name, family=chain.family) == False:
                    insert_rule(handle=str(rule["rule"]["handle"]), chain_id=rule["rule"]["chain"], family=rule["rule"]["family"], expr=str(rule["rule"]["expr"]))

    return  [Rule.query.count(), Chain.query.count(), Table.query.count()]
    
def get_rule(rule_id):
    rule = Rule.query.filter_by(id=rule_id).first()
    return rule

def delete_all_statements():
    statements = Statement.query.all()
    for statement in statements:
        db.session.delete(statement)
    db.session.commit()
    
