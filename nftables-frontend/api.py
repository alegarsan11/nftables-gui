import requests

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
    print(response.json())
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
    print(response.json())
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