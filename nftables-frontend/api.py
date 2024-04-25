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
        
def edit_chain_request(name, family, table, type, priority, hook_type, policy):
    json_data = {"json_data": {"nftables": [{"edit": {"chain":{"name": name, "family": family, "table": table, "type": type, "priority": priority, "hook": hook_type, "policy": policy}}}]}}
    response = requests.post('http://localhost:8000/chains/edit_chain', json=json_data)
    if(response.json()["status"] == "success"):
        return "Success"
    else:
        return "Error editing chain."
    
def edit_base_chain_request(name, family, table, type, priority, policy, hook_type):
    json_data = {"json_data": {"nftables": [{"edit": {"base_chain":{"name": name, "family": family, "table": table, "type": type, "priority": priority, "policy": policy, "hook_type": hook_type}}}]}}
    response = requests.post('http://localhost:8000/chains/edit_base_chain', json=json_data)
    if(response.json()["status"] == "success"):
        return "Success"
    else:
        return "Error editing base chain."
    
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
    
def create_rule_request(rule_id, chain_name, chain_table, family):
    expr = {}
    rule = service.get_rule(rule_id)
    for statement in rule.statement:
        expr[statement] = statement
        print(expr)
    json_data = {"json_data": {"nftables": [{"add": {"rule":{"chain": chain_name, "table": chain_table, "family": family, "expr": expr}}}]}}
    # response = requests.post('http://localhost:8000/rules/create_rule', json=json_data)
    # if(response.json()["status"] == "success"):
    #     return "Success"
    # else:
    #     return "Error creating rule."