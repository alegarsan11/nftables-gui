import glob
import json
import re
from models import Chain, Map, NotTerminalStatement, Rule, Statement, Table, BaseChain, TerminalStatement, db, User, Set
from flask_login import LoginManager
import api, os
import ipaddress
import ast
from Levenshtein import ratio


login_manager = LoginManager()

def create_default_user():
    user = User.query.filter_by(username='default').first()
    if not user:
        user = User(username='default',password="defaultpassword" ,role="administrator" ,is_active=True)
        db.session.add(user)
        db.session.commit()
        
def clean_table(table_id, family):
    table = Table.query.filter_by(name=table_id, family=family).first()
    chains = table.chains
    for chain in chains:
        rules = chain.rules
        for rule in rules:
            statements = rule.statement
            for statement in statements:
                db.session.delete(statement)
            db.session.delete(rule)
        db.session.delete(chain)
    db.session.commit()
        
def create_user(username, password, role, is_active):
    user = User(username=username, password=password, role=role, is_active=is_active)
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

def edit_user(user_id, username, role):
    user = User.query.filter_by(id=user_id).first()
    user.username = username
    user.role = role
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


def insert_in_table(name, family, description=None, username=None):
    try:
        Table(name=name, family=family, description=description, username=username).save()
    except Exception as e:
        db.session.rollback()
        return str(e)
    return "Success"

def delete_table(table_id, family):
    table = Table.query.filter_by(name=table_id, family=family).first()
    db.session.delete(table)
    db.session.commit()
    

def get_tables():
    return Table.query.all()

def insert_chains(table_id, chains):
    table = Table.query.get(table_id)
    table.chains = chains
    db.session.commit()
    
def insert_chain(chain_name, family, policy, table_id, type, hook_type=None, priority=None):
    table = Table.query.filter_by(name=table_id, family=family).first()
    if table is not None:
        if hook_type is not None and priority is not None:
            chain = BaseChain(name=chain_name, type=type, policy=policy, table_id=table.id, hook_type=hook_type, priority=priority)
        else:
            chain = Chain(name=chain_name, table_id=table.id, policy=policy)
        db.session.add(chain)
        db.session.commit()

def check_existing_chain(chain_name, table_id, family):
    table = Table.query.filter_by(name=table_id, family=family).first()
    chain = Chain.query.filter_by(name=chain_name, table_id=table.id).first()
    if chain in table.chains:
        return False
    return True

def get_chains_from_table(table_id, family):
    table = Table.query.filter_by(name=table_id, family=family).first()
    return table.chains

def get_chains():
    return Chain.query.all()


def get_chain(chain_id, table):
    chain = Chain.query.filter_by(name=chain_id, table_id=table).first()
    base_chain = BaseChain.query.filter_by(name=chain_id, table_id=table).first()
    if base_chain:
        return base_chain
    return chain

def get_chain_by_id(chain_id):
    chain = Chain.query.filter_by(id=chain_id).first()
    return chain


def check_existing_rule(chain_id, handle=None, family=None, expr=None):
    rules = Rule.query.filter_by(chain_id=chain_id).all()
    chain = Chain.query.filter_by(id=chain_id).first()
    if handle:
        rule = Rule.query.filter_by(handle=handle, chain_id=chain_id, expr=str(expr)).first()
        if rule in chain.rules:
            return True
    for rule in rules:
        if rule in chain.rules and ratio(str(rule.expr), str(expr)) > 0.98:  # Ajusta el umbral según tus necesidades
            return True
    return False
def get_chain_id(chain_id, table):
    chain = Chain.query.filter_by(id=chain_id, table_id=table).first()
    base_chain = BaseChain.query.filter_by(id=chain_id, table_id=table).first()
    if base_chain:
        return base_chain
    return chain

def insert_rule_with_table(chain_id, expr, table_id, description=None):
    chain = get_chain_id(chain_id, table_id)
    if description == "":
        description = None
    rule = Rule(chain_id=chain.id, expr=expr, description=description)
    db.session.add(rule)
    db.session.commit()
    return rule.id

def insert_rule(chain_id, expr, handle, description=None):
    rule = Rule(chain_id=chain_id, expr=expr, handle=handle, description=description)
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

        insert_statement(rule_id=rule_id, sport=sport, dport=dport, saddr=saddr, daddr=daddr, protocol=protocol, accept=accept, drop=drop, reject=reject, log=log , limit=limit, counter=counter, return_=return_, jump=jump, go_to=go_to, queue=queue, masquerade=masquerade, snat=snat, dnat=dnat, redirect=redirect, input_interface=input_interface, output_interface=output_interface)

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
        insert_statement(rule_id=rule_id, sport=sport, dport=dport, saddr=saddr, daddr=daddr, protocol=protocol, accept=accept, drop=drop, reject=reject, log=log, limit=limit, counter=counter, return_=return_, jump=jump, go_to=go_to, queue=queue, masquerade=masquerade, snat=snat, dnat=dnat, redirect=redirect, input_interface=input_interface, output_interface=output_interface)
    
def delete_chain(chain_id):
    chain = Chain.query.get(chain_id)
    db.session.delete(chain)
    db.session.commit()
    
def delete_rule(rule_id):
    rule = get_rule(rule_id)
    db.session.delete(rule)
    db.session.commit()
    
def delete_rules_form_chain(chain_id):
    chain = Chain.query.get(chain_id)
    rules = chain.rules
    for rule in rules:
        db.session.delete(rule)
    db.session.commit()
    
def insert_statement(rule_id, saddr, daddr, sport, dport, protocol, reject=None, log=None, drop=None, accept=None, queue=None, limit=None, counter=None, return_=None, jump=None, go_to=None, masquerade=None, snat=None, dnat=None, redirect=None, input_interface=None, output_interface=None):
    statement_ = None
    statement = None
    
    if limit != None or log != None or counter != None or masquerade != None or snat != None or dnat != None or redirect != None:
        statement = NotTerminalStatement(rule_id=rule_id, src_ip=saddr, dst_ip=daddr, src_port=sport, dst_port=dport,input_interface=input_interface, output_interface=output_interface, protocol=protocol, limit=limit, log=log, counter=counter, masquerade=masquerade, snat=snat, dnat=dnat, redirect=redirect)
        db.session.add(statement)
    if reject != None or drop != None or accept != None or queue != None or return_ != None or jump != None or go_to != None :
        statement_ = TerminalStatement(rule_id=rule_id, src_ip=saddr, dst_ip=daddr, src_port=sport, dst_port=dport, input_interface=input_interface, output_interface=output_interface, protocol=protocol, reject=reject, drop=drop, accept=accept, queue=queue, return_=return_, jump=jump, go_to=go_to)
        db.session.add(statement_)
    else:
        statement_2 = Statement(rule_id=rule_id, src_ip=saddr, dst_ip=daddr, src_port=sport, dst_port=dport,input_interface=input_interface, output_interface=output_interface, protocol=protocol)
        db.session.add(statement_2)
    db.session.commit()

def check_existing_statement( saddr, daddr, sport, dport, protocol, accept, drop, reject, log, limit, counter, return_, jump, go_to, queue, masquerade):
    if limit != None or log != None or counter != None:
        statement = NotTerminalStatement( src_ip=saddr, dst_ip=daddr, src_port=sport, dst_port=dport, protocol=protocol, limit=limit, log=log, counter=counter)
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
        rule_.expr = str(rule["rule"]["expr"])
        db.session.commit()
    elif check_existing_rule(handle=str(rule["rule"]["handle"]), chain_id=chain_id, family=family, expr=rule["rule"]["expr"]) == False :   
        rule_id = insert_rule(handle=str(rule["rule"]["handle"]), chain_id=rule["rule"]["chain"], family=rule["rule"]["family"], expr=str(rule["rule"]["expr"]))
    elif check_existing_rule(handle=str(rule["rule"]["handle"]), chain_id=chain_id, family=family, expr=str(rule["rule"]["expr"])) == True: 
        rule_ = Rule.query.filter_by(handle=str(rule["rule"]["handle"]), chain_id=chain_id, family=family, expr=str(rule["rule"]["expr"])).first()
        rule_id = rule_.id
        rule_.expr = str(rule["rule"]["expr"])
        db.session.commit()
    else:
        rule_id = insert_rule(handle=str(rule["rule"]["handle"]), chain_id=rule["rule"]["chain"], family=rule["rule"]["family"], expr=str(rule["rule"]["expr"]))
    saddr = None
    daddr = None
    sport = None
    dport = None
    accept = None
    drop = None
    reject = None
    log = None
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
        if "accept" in expr:
            accept = True
        if "drop" in expr:
            drop = True
        if expr.get("reject", None) != None:
            reject = str(expr.get("reject"))
        if expr.get("log", None) != None:
            log = str(expr.get("log"))
        if expr.get("limit", None) != None:
            limit = str(expr.get("limit"))
        if expr.get("snat", None) != None:
            snat = str(expr.get("snat"))
        if expr.get("dnat", None) != None:
            dnat = str(expr.get("dnat"))
        if "redirect" in expr:
            redirect = True
            if expr.get("redirect", None) != None:
                redirect = str(expr.get("redirect"))
        if "masquerade" in expr:
            masquerade = True
        if "return" in expr:
            return_ = True
        if expr.get("jump", None) != None:
            jump = str(expr.get("jump"))
        if expr.get("goto", None) != None:
            go_to = str(expr.get("goto"))
        if expr.get("queue", None) != None:
            queue = str(expr.get("queue"))
    if saddr != None or daddr != None or sport  != None or dport != None or protocol != None or counter != None or limit != None or log != None or reject != None or drop != None or accept != None or queue != None or return_ != None or jump != None or go_to != None or masquerade != None or snat != None or dnat != None or redirect != None or input_interface != None or output_interface != None:
        if str(get_rule(rule_id).handle) == str(handle):
            insert_statement(rule_id=rule_id, sport=sport, dport=dport, saddr=saddr, daddr=daddr, protocol=protocol, accept=accept, drop=drop, reject=reject, log=log, limit=limit, counter=counter, return_=return_, jump=jump, go_to=go_to, queue=queue, masquerade=masquerade, snat=snat, dnat=dnat, redirect=redirect, input_interface=input_interface, output_interface=output_interface)

                
                
def get_statements_from_chain(chain_id, family,  table_id):
    table = Table.query.filter_by(id=table_id, family=family).first()
    chain = Chain.query.filter_by(name=chain_id, table_id=table_id).first()
    rules = chain.rules
    if chain in table.chains:    
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
    insert_sets()
    insert_maps()
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
                
                insert_chain(item["chain"]["name"], item["chain"]["family"] ,item["chain"]["policy"], item["chain"]["table"],type=type,  priority=prio, hook_type=hook)
    chains = get_chains()
    for chain in chains:
        print(chain.name, chain.table.name, chain.table.family)
        result_rules = api.list_chain_request(chain.name, chain.table.family, chain.table.name)
        if(result_rules["rules"] != ""):
            result_rules = result_rules["rules"]["nftables"]
            for i, rule in enumerate(result_rules):
                if i ==0 or i ==1:
                    continue
                else:
                    if check_existing_rule(handle=str(rule["rule"]["handle"]), expr=rule["rule"]["expr"], chain_id=chain.id, family=chain.table.family) == False:
                        insert_rule(handle=str(rule["rule"]["handle"]), chain_id=chain.id, expr=str(rule["rule"]["expr"]))

    return  [Rule.query.count(), Chain.query.count(), Table.query.count()]
    
def get_rule(rule_id):
    rule = Rule.query.filter_by(id=rule_id).first()
    return rule

def delete_all_statements():
    statements = Statement.query.all()
    for statement in statements:
        db.session.delete(statement)
    db.session.commit()

def get_rules_by_chain_and_table(chain_id, family, table):
    chain = get_chain(chain_id, family, table)
    rules = chain.rules
    return rules
def get_rule_by_chain_and_table(chain_id, family, table):
    rule = Rule.query.filter_by(chain_id=chain_id, family=family).first()
    return rule
def get_rule_by_chain_and_handle(chain_id, family, handle):
    rule = Rule.query.filter_by(chain_id=chain_id, family=family, handle=handle).first()
    return rule

def insert_sets():
    result = api.list_sets_request()
    for i, item in enumerate(result):
        if("set" in item):
            table = get_table(item["set"]["table"], item["set"]["family"])
            if(check_existing_set(item["set"]["name"], table.id) == True):
                
                insert_set(item["set"]["name"],table.id, item["set"]["type"])
    return "Success"

def check_existing_set(name, table):
    _set = Set.query.filter_by(name=name, table_id=table).first()
    if _set:
        return False
    return True

def insert_set(name, table_id, type):
    _set = Set(name=name, table_id=table_id, type=type)
    db.session.add(_set)
    db.session.commit()
    
def get_sets():
    return Set.query.all()

def get_set(set_id):
    _set = Set.query.get(set_id)
    return _set

def insert_elements_in_set(set_id, elements):
    _set = get_set(set_id)
    _set.elements = elements
    db.session.commit()
    
def validate_element(element, set_id):
    _set = get_set(set_id)
    
    if element in _set.elements:
        return False
    if _set.type == 'ipv4_addr':
        try:
            ipaddress.IPv4Address(element)
        except ipaddress.AddressValueError:
            return False
    elif _set.type == 'ipv6_addr':
        try:
            ipaddress.IPv6Address(element)
        except ipaddress.AddressValueError:
            return False
    elif _set.type == 'inet_service':
        try:
            if not isinstance(int(element), int) or not (0 <= int(element) <= 65535):
                return False
        except ValueError:
            return False
    elif _set.type == 'inet_proto':
        try:
            if not isinstance(int(element), int) or not (0 <= int(element) <= 255):
                return False
        except ValueError: 
            return False
    elif _set.type == 'mark':
        try:
            if not isinstance(int(element), int):
                return False
        except ValueError:
            return False
    elif _set.type == 'ether_addr':
        if not isinstance(element, str) or not validate_mac_address(element):
            return False
    return True

def validate_mac_address(mac):
    return bool(re.match("^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", mac))

def insert_set_form(set_name, table, type, description=None):
    if description == "":
        description = None
    if check_existing_set(set_name, table) == False:
        return "Set already exists"
    _set = Set(name=set_name, table_id=table, type=type, description=description)
    db.session.add(_set)
    db.session.commit()

    return "Success"
 
def delete_set(set_id):
    _set = get_set(set_id)
    db.session.delete(_set)
    db.session.commit()
    
def get_elements_from_set(set_id):
    _set = get_set(set_id)
    return _set.elements

def insert_maps():
    result = api.list_maps_request()
    for i, item in enumerate(result):
        if("map" in item):
            table = get_table(item["map"]["table"], item["map"]["family"])
            if(check_existing_map(item["map"]["name"], table.id) == True):
                insert_map(name=item["map"]["name"], table_id=table.id, type=item["map"]["type"], map=item["map"]["map"])
    return "Success"

def check_existing_map(name, table):
    _map = Map.query.filter_by(name=name, table_id=table).first()
    if _map:
        return False
    return True

def insert_map(name, table_id, type, map):
    _map = Map(name=name, table_id=table_id, type=type, map=map)
    db.session.add(_map)
    db.session.commit()
    
def get_maps():
    return Map.query.all()

def insert_elements_in_map(map_id, elements):
    _map = get_map(map_id)
    if(elements != ""):
        list_elements = ast.literal_eval(elements)
        dict_elements = {item[0]: item[1] for item in list_elements}
        _map.elements = str(dict_elements)
    db.session.commit()
    
def get_map(map_id):
    _map = Map.query.get(map_id)
    return _map

def insert_map_form(map_name, table, type, map_type, description=None):
    if description == "":
        description = None
    if check_existing_map(map_name, table) == False:
        return "Map already exists"
    _map = Map(name=map_name, table_id=table, type=type, description=description, map=map_type)
    db.session.add(_map)
    db.session.commit()

    return "Success"

def delete_map(map_id):
    _map = get_map(map_id)
    db.session.delete(_map)
    db.session.commit()
    
def validate_element_map(element , element_map, map_id):
    _map = get_map(map_id)
    if _map.type == 'ipv4_addr':
        try:
            ipaddress.IPv4Address(element)
        except ipaddress.AddressValueError:
            return False
    elif _map.type == 'ipv6_addr':
        try:
            ipaddress.IPv6Address(element)
        except ipaddress.AddressValueError:
            return False
    elif _map.type == 'inet_service':
        try:
            if not isinstance(int(element), int) or not (0 <= int(element) <= 65535):
                return False
        except ValueError:
            return False
    elif _map.type == 'inet_proto':
        try:
            if not isinstance(int(element), int) or not (0 <= int(element) <= 255):
                return False
        except ValueError: 
            return False
    elif _map.type == 'mark':
        try:
            if not isinstance(int(element), int):
                return False
        except ValueError:
            return False
    elif _map.type == 'ether_addr':
        if not isinstance(element, str) or not validate_mac_address(element):
            return False
    elif _map.map == 'ipv4_addr':
        try:
            ipaddress.IPv4Address(element_map)
        except ipaddress.AddressValueError:
            return False
    elif _map.map == 'ipv6_addr':
        try:
            ipaddress.IPv6Address(element_map)
        except ipaddress.AddressValueError:
            return False
    elif _map.map == 'inet_service':
        try:
            if not isinstance(int(element_map), int) or not (0 <= int(element_map) <= 65535):
                return False
        except ValueError:
            return False
    elif _map.map == 'inet_proto':
        try:
            if not isinstance(int(element_map), int) or not (0 <= int(element_map) <= 255):
                return False
        except ValueError: 
            return False
    elif _map.map == 'mark':
        try:
            if not isinstance(int(element_map), int):
                return False
        except ValueError:
            return False
    elif _map.map == 'ether_addr':
        if not isinstance(element_map, str) or not validate_mac_address(element_map):
            return False
    return True

def get_elements_from_map(map_id):
    _map = get_map(map_id)
    return _map.elements

def  delete_element_from_map(map_id, element):
    _map = get_map(map_id)
    elements = _map.elements
    elements = ast.literal_eval(elements)
    elements.pop(element)
    _map.elements = str(elements)
    db.session.commit()
    
def get_element_from_map(map_id, element):
    _map = get_map(map_id)
    elements = _map.elements
    elements = ast.literal_eval(elements)
    return elements[element]

def delete_all_data():
    meta = db.metadata
    for table in reversed(meta.sorted_tables):
        if table.name != 'user':
            db.session.execute(table.delete())
    db.session.commit()
    
def get_objects():
    names = [] 
    set_ = Set.query.all()
    map_ = Map.query.all()
    for item in set_:
        names.append(item)
    for item in map_:
        names.append(item)
    return names
        
def check_set_or_map(name):
    _set = Set.query.filter_by(name=name).first()
    _map = Map.query.filter_by(name=name).first()
    if _set:
        return _set.type
    if _map:
        return _map.type
    return None

def save_changes_permanent():
    os.system("sudo su")
    os.system("sudo rm -f /etc/nftables.conf")
    os.system("sudo nft list ruleset > /etc/nftables.conf")
    os.system("sudo systemctl restart nftables")
    delete_all_data_except_users()
    
def save_changes_on_file():
    files = glob.glob("./temp_config/nftables_temp*.conf")
    numbers = [int(f.replace("./temp_config/nftables_temp", "").replace(".conf", "")) for f in files]
    highest_number = max(numbers) if numbers else 0
    os.system(f"sudo nft list ruleset > ./temp_config/nftables_temp{highest_number + 1}.conf")
    
def delete_all_data_except_users():
    meta = db.metadata
    for table in reversed(meta.sorted_tables):
        if table.name != 'user':
            db.session.execute(table.delete())
    db.session.commit()
    
def create_list(name, family, table_name, type, elements):
    if check_existing_set(name, table_name) == False:
        return "Set already exists"
    _set = Set(name=name, table_id=table_name, type=type)
    if elements != "" or elements != None:
        elements = str(elements)
        _set.elements = elements
    db.session.add(_set)
    db.session.commit()
    return "Success"

def reload_service():
    delete_all_data_except_users
    os.system("sudo systemctl restart nftables")