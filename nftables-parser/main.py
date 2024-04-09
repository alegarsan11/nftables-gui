import json
from nftables import Nftables
import sys
import hug

@hug.post('/create_table')
def create_table(json_data: hug.types.json):
    nft = Nftables()

    try:
        result = nft.json_cmd(json_data)
        if 'error' in result:
            return {'status': 'error', 'message': result['error']}
        else:
            return {'status': 'success', 'result': result}
    except Exception as e:
        return {'status': 'error', 'message': str(e)}
    
@hug.get('/list_ruleset')
def list_ruleset():
    nft = Nftables()
    result = nft.cmd("list ruleset")
    result = format_nftables_config(result[1])
    print(result)
    return {"ruleset": result}

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
