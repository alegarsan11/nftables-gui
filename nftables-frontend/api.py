import os
import requests
import service

def create_table_request(name , family):
    json_data = {"json_data": {"nftables": [{"add": {"table":{"name": name, "family": family}}}]}}
    response = requests.post('http://localhost:8000/tables/create_table', json=json_data)
    if(response.json()["status"] == "success"):
        return "Success"
    else:
        return "Error creating table."
    
def list_tables_request():
    response = requests.get('http://localhost:8000/tables/list_tables')
    return format_nftables_config(response.json()["tables"])

def list_ruleset_request():
    response = requests.get('http://localhost:8000/tables/list_ruleset')
    return format_nftables_config(response.json()["ruleset"])

def delete_table_request(name, family):
    json_data = {"json_data": {"nftables": [{"delete": {"table":{"name": name, "family": family}}}]}}
    response = requests.post('http://localhost:8000/tables/delete_table', json=json_data)
    if(response.json()["status"] == "success"):
        return "Success", response.json()
    else:
        return "Error deleting table."
    
def list_table_request(name, family):
    json_data = {"json_data": {"nftables": [{"list": {"table":{"name": name, "family": family}}}]}}
    response = requests.get('http://localhost:8000/tables/list_table', json=json_data)
    return parse_chains(response.json()["result"][1]["nftables"])

def format_nftables_config(config_string):
    # Replace escape sequences with actual characters
    formatted_string = config_string.replace('\\n', '\n').replace('\\t', '\t')

    # Split the string into lines
    lines = formatted_string.split('\n')

    # Remove empty lines
    lines = [line for line in lines if line.strip() != '']

    # Join the lines back together with newline characters
    formatted_string = '\n'.join(lines)
    return formatted_string

def flush_table_request(name, family):
    json_data = {"json_data": {"nftables": [{"flush": {"table":{"name": name, "family": family}}}]}}
    response = requests.get('http://localhost:8000/tables/flush_table', json=json_data)
    if(response.json()["status"] == "success"):
        return "Success"
    else:
        return "Error flushing table."

def parse_chains(response):
    chains = []
    for item in response:
        if isinstance(item, dict) and 'chain' in item:
            chains.append(item['chain'])
    return chains

def list_chains_request():
    json_data = {"json_data": {"nftables": [{"list": {"chains": {}}}]}}
    response = requests.get('http://localhost:8000/chains/list_chains', json=json_data)
    return (response.json())

def create_chain_request(name, family, table, policy):
    json_data = {"json_data": {"nftables": [{"add": {"chain":{"name": name, "family": family, "table": table, "policy": policy}}}]}}
    response = requests.post('http://localhost:8000/chains/create_chain', json=json_data)
    if(response.json()["status"] == "success"):
        return "Success"
    else:
        return "Error creating chain."
    
def create_base_chain_request(name, family, table, type, priority, policy, hook_type):
    json_data = {"json_data": {"nftables": [{"add": {"base_chain":{"name": name, "family": family, "table": table, "type": type, "priority": priority, "policy": policy, "hook_type": hook_type}}}]}}
    response = requests.post('http://localhost:8000/chains/create_base_chain', json=json_data)
    if(response.json()["status"] == "success"):
        return "Success"
    else:
        return "Error creating base chain."
    
def list_chain_request(chain_name, chain_family, chain_table):
    json_data = {"json_data": {"nftables": [{"list": {"chain":{"name": chain_name, "family": chain_family, "table": chain_table}}}]}}
    response = requests.get('http://localhost:8000/chains/list_rule_chain', json=json_data)
    return response.json()
        
    
def delete_chain_request(name, family, table):
    json_data = {"json_data": {"nftables": [{"delete": {"chain":{"name": name, "family": family, "table": table}}}]}}
    response = requests.post('http://localhost:8000/chains/delete_chain', json=json_data)
    if(response.json()["status"] == "success"):
        return "Success"
    else:
        return "Error deleting chain."
    
def flush_chain_request(name, family, table):
    json_data = {"json_data": {"nftables": [{"flush": {"chain":{"table": table, "name": name, "family": family }}}]}}
    response = requests.post('http://localhost:8000/chains/flush_chain', json=json_data)
    if(response.json()["status"] == "success"):
        return "Success"
    else:
        return "Error flushing chain."
    
import requests

def create_rule_request(rule_id, chain_name, chain_table, family, statement, statement_term, statement_type):
    expr = []
    saddr = None
    daddr = None
    saddr_object = None
    daddr_object = None
    sport = None
    dport = None
    sport_object = None
    dport_object = None
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
    snat = None
    dnat = None
    input_interface = None
    output_interface = None
    redirect = None
    
    if statement_type == "terminal":
        saddr = statement_term["src_ip"]
        daddr = statement_term["dst_ip"]
        sport = statement_term["src_port"]
        dport = statement_term["dst_port"]
        if statement_term.get("src_ip_objects") != '--Selects--':
            saddr_object = statement_term.get("src_ip_objects")
        if statement_term.get("dst_ip_objects") != '--Selects--':
            daddr_object = statement_term.get("dst_ip_objects")
        if statement_term.get("src_port_objects") != '--Selects--':
            sport_object = statement_term.get("src_port_objects")
        if statement_term.get("dst_port_objects") != '--Selects--':
            dport_object = statement_term.get("dst_port_objects")
        input_interface = statement_term.get("input_interface")
        output_interface = statement_term.get("output_interface")
        accept = statement_term["accept"]
        drop = statement_term["drop"]
        reject = statement_term["reject"]
        return_ = statement_term["return_"]
        if statement_term.get("jump") != "--Selects--":
            jump = statement_term["jump"]
        if statement_term.get("go_to") != "--Selects--":
            go_to = statement_term["go_to"]
        queue = statement_term["queue"]
    
    else:
        saddr = statement.get("src_ip")
        daddr = statement.get("dst_ip")
        sport = statement.get('src_port')
        dport = statement.get('dst_port')
        if statement.get('src_ip_objects') != '--Selects--':
            saddr_object = statement.get('src_ip_objects')
        if statement.get('dst_ip_objects') != '--Selects--':
            daddr_object = statement.get('dst_ip_object')
        if statement.get('src_port_objects') != '--Selects--':
            sport_object = statement.get('src_port_objects')
        if statement.get('dst_port_objects') != '--Selects--':
            dport_object = statement.get('dst_port_objects')
        input_interface = statement.get('input_interface')
        output_interface = statement.get('output_interface')
        log = statement.get("log")
        limit = statement.get("limit")
        limit_per = statement.get("limit_per")
        counter = statement.get("counter")
        masquerade = statement.get("masquerade")
        snat = statement.get("src_nat")
        dnat = statement.get("dst_nat")
        redirect = statement.get("redirect")
    
    # Agrega los elementos al diccionario expr
    if saddr:
        if family == "inet":
            if ":" in saddr:
                expr.append({"match":{"op":"==","left":{"payload":{"protocol":"ip6", "field":"saddr"}}, "right": saddr}})
            elif "." in saddr:
                expr.append({"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr" }}, "right": saddr}})
        elif family == "bridge":
            expr.append({"match":{"op":"==","left":{"payload":{"protocol":"ether", "field":"saddr"}}, "right": daddr}})
    if daddr:
        if family == "inet":
            if ":" in daddr:
                expr.append({"match":{"op":"==","left":{"payload":{"protocol":"ip6" ,"field":"daddr"}}, "right": daddr}})
            elif "." in daddr:
                expr.append({"match":{"op":"==","left":{"payload":{ "protocol":"ip", "field":"daddr"}}, "right": daddr}})
        elif family == "bridge":
            expr.append({"match":{"op":"==","left":{"payload":{"protocol":"ether", "field":"daddr" }}, "right": daddr}})
    if sport:
        expr.append({"match":{"op":"==","left":{"payload":{"protocol":"tcp", "field":"sport"}}, "right": sport}})
    if dport:
        expr.append({"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}}, "right": dport}})
    if input_interface:
        expr.append({"input_interface": input_interface})
    if output_interface:
        expr.append({"output_interface": output_interface})
    if counter:
        expr.append({"counter": None})
    if saddr_object:
        if service.check_set_or_map == "ipv4_addr":
            expr.append({"match":{"op":"in","left":{"payload":{"protocol": "ip","field":"saddr" }}, "right": "@"+saddr_object}})
        if service.check_set_or_map == "ipv6_addr":
            expr.append({"match":{"op":"in","left":{"payload":{ "protocol": "ip6", "field":"saddr"}}, "right": "@"+saddr_object}})
        if service.check_set_or_map == "ether_addr":
            expr.append({"match":{"op":"in","left":{"payload":{ "protocol": "ether", "field":"saddr"}}, "right": "@"+saddr_object}})
    if daddr_object:
        if service.check_set_or_map == "ipv4_addr":
            expr.append({"match":{"op":"in","left":{"payload":{"protocol": "ip","field":"daddr"}}, "right": "@"+daddr_object}})
        if service.check_set_or_map == "ipv6_addr":
            expr.append({"match":{"op":"in","left":{"payload":{"protocol": "ip6", "field":"daddr" }}, "right": "@"+daddr_object}})
        if service.check_set_or_map == "ether_addr":
            expr.append({"match":{"op":"in","left":{"payload":{"protocol": "ether", "field":"daddr" }}, "right": "@"+daddr_object}})
    if sport_object:
        expr.append({"match":{"op":"in","left":{"payload":{ "protocol":"tcp", "field":"sport"}}, "right": "@"+sport_object}})
    if dport_object:
        expr.append({"match":{"op":"in","left":{"payload":{ "protocol":"tcp", "field":"dport"}}, "right": "@"+sport_object}})
    if accept:
        expr.append({"accept": None})
    if drop:
        expr.append({"drop": None})
    if reject:
        expr.append({"reject": {'type': 'icmp', 'expr': 'port-unreachable'}})
    if return_:
        expr.append({"return": None})
    if jump:
        expr.append({"jump": {"target": jump}})
    if go_to:
        expr.append({"goto": {"target": go_to}})
    if queue:
        expr.append({"queue": {"num": queue}})
    if log: 
        expr.append({"log": {"prefix": "Rule" + str(rule_id)+ " " , "level": "info"}})
    if limit:
        expr.append({"limit": {"rate": limit, "burst": 50, "per": limit_per}})
    if masquerade:
        expr.append({"masquerade": None})
    if snat:
        if(family == "inet"):
            if ":" in snat:
                expr.append({"snat": {"family": "ip6","addr": snat}})
            elif "." in snat:
                expr.append({"snat": {"family": "ip","addr": snat}})
        else:
            expr.append({"snat": {"addr": snat}})
    if dnat:
        if(family == "inet"):
            if ":" in dnat:
                expr.append({"dnat": {"family": "ip6","addr": dnat}})
            elif "." in dnat:
                expr.append({"dnat": {"family": "ip","addr": dnat}})
        else:
            expr.append({"dnat": {"addr": dnat}})
                    
    if redirect:
        if ":" in redirect:
            expr.append({"redirect": {"to": redirect.split(":")[0], "port": redirect.split(":")[1]}})
        else:
            expr.append({"redirect": {"port": redirect}}) 
    json_data = {
        "json_data": {
            "nftables": [{
                "add": {
                    "rule": {
                        "chain": chain_name,
                        "table": chain_table,
                        "family": family,
                        "expr": expr
                    }
                }
            }]
        }
    }
    if expr != []:
        response = requests.post('http://localhost:8000/rules/create_rule', json=json_data)
    else:
        return [], "Error creating rule."
    if response.json()["status"] == "success":
        return expr, "Success"
    else:
        return [], response.json()
    
def delete_rule_request(rule_id):
    rule= service.get_rule(rule_id)
    chain = service.get_chain_by_id(rule.chain_id)
    json_data = {"json_data": {"nftables": [{"delete": {"rule": {"chain": chain.name ,"table":rule.table().name, "family":rule.family, "handle": int(rule.handle)}}}]}}
    response = requests.post('http://localhost:8000/rules/delete_rule', json=json_data)
    if(response.json()["status"] == "success"):
        return "Success"
    else:
        return "Error deleting rule."

def list_sets_request():
    response = requests.get('http://localhost:8000/sets/list_sets')
    return response.json()[1]["nftables"]

def list_elements_in_set(set_name, set_family, set_table):
    json_data = {"json_data": {"nftables": [{"list": {"set": {"name": set_name, "family": set_family, "table": set_table}}}]}}
    response = requests.get('http://localhost:8000/sets/list_elements_in_set', json=json_data)
    return response.json()

def add_element_to_set_request(set_name, set_family, set_table, element):
    json_data = {"json_data": {"nftables": [{"add": {"element": {"family": set_family,  "table": set_table, "name": set_name,  "elem": element}}}]}}
    response = requests.post('http://localhost:8000/sets/add_element_to_set', json=json_data)
    if(response.json()[0] == 0):
        return "Success"
    else:
        return "Error adding element to set."
    
def create_set_request(set_name, set_family, set_table, set_type):
    json_data = {"json_data": {"nftables": [{"add": {"set": {"name": set_name, "family": set_family, "table": set_table, "type": set_type}}}]}}
    response = requests.post('http://localhost:8000/sets/create_set', json=json_data)
    if(response.json()[0] == 0):
        return "Success"
    else:
        return "Error creating set."
    
def delete_set_request(set_name, set_family, set_table):
    json_data = {"json_data": {"nftables": [{"delete": {"set": {"name": set_name, "family": set_family, "table": set_table}}}]}}
    response = requests.post('http://localhost:8000/sets/delete_set', json=json_data)
    if(response.json()[0] == 0):
        return "Success"
    else:
        return "Error deleting set."
def delete_element_from_set_request(set_name, set_family, set_table, element):
    json_data = {"json_data": {"nftables": [{"delete": {"element": {"family": set_family,  "table": set_table, "name": set_name,  "elem": element}}}]}}
    response = requests.post('http://localhost:8000/sets/delete_element_from_set', json=json_data)
    if(response.json()[0] == 0):
        return "Success"
    else:
        return "Error deleting element from set."
    
def list_maps_request():
    json_data = {"json_data": {"nftables": [{"list": {"maps": {}}}]}}
    response = requests.get('http://localhost:8000/maps/list_maps', json=json_data)
    return response.json()[1]["nftables"]

def list_elements_in_map(map_name, map_family, map_table):
    json_data = {"json_data": {"nftables": [{"list": {"map": { "family": map_family, "table": map_table, "name": map_name}}}]}}
    response = requests.get('http://localhost:8000/maps/list_elements_in_map', json=json_data)
    return response.json()

def create_map_request(map_name,type, map_family, map_table, map_type):
    json_data = {"json_data": {"nftables": [{"add": {"map": {"name": map_name, "family": map_family, "table": map_table, "type": type, "map": map_type}}}]}}
    response = requests.post('http://localhost:8000/maps/create_map', json=json_data)
    if(response.json()[0] == 0):
        return "Success"
    else:
        return "Error creating map."
    
def delete_map_request(map_name, map_family, map_table):
    json_data = {"json_data": {"nftables": [{"delete": {"map": {"name": map_name, "family": map_family, "table": map_table}}}]}}
    response = requests.post('http://localhost:8000/maps/delete_map', json=json_data)
    if(response.json()[0] == 0):
        return "Success"
    else:
        return "Error deleting map."
    
def add_element_to_map_request(map_name, map_family, map_table, key, value):
    json_data = {"json_data": {"nftables": [{"add": {"element": {"family": map_family,  "table": map_table, "name": map_name,  "elem": [[key, {"concat": [value]}]]
                                                                 }}}]}}    
    response = requests.post('http://localhost:8000/maps/add_element_to_map', json=json_data)
    if(response.json()[0] == 0):
        return "Success"
    else:
        return "Error adding element to map."
    
def delete_element_from_map_request(map_name, map_family, map_table, key, value):
    json_data = {"json_data": {"nftables": [{"delete": {"element": {"family": map_family,  "table": map_table, "name": map_name,  "elem": [[key, {"concat": [value]}]]}}}]}}
    response = requests.post('http://localhost:8000/maps/delete_element_from_map', json=json_data)
    if(response.json()[0] == 0):
        return "Success"
    else:
        return "Error deleting element from map."
    
def reload_service():
    response = requests.get('http://localhost:8000/service/reload_service')
    if(response.json()["status"] == "success"):
        return "Success"
    else:
        return "Error reloading service."
    
def save_service():
    response = requests.get('http://localhost:8000/service/save_service')
    if(response.json()["status"] == "success"):
        return "Success"
    else:
        return "Error saving service."
    
def save_service_temp():
    response = requests.get('http://localhost:8000/service/save_service_temp')
    if(response.json()["status"] == "success"):
        return "Success"
    else:
        return "Error saving service temp."