import json
from nftables import Nftables
import sys
import hug

@hug.get('/list_chains')
def list_chains(json_data: hug.types.json):
    nft = Nftables()
    result = nft.json_cmd(json_data)
    return {"chains": result[1]}

@hug.post('/create_chain')
def create_chain(json_data: hug.types.json):
    nft = Nftables()
    result = nft.json_cmd(json_data)
    if(result[0] == 0):
        return {"status": "success"}
    else:
        return {"status": "error"}
    
@hug.post('/create_base_chain')
def create_base_chain(json_data: hug.types.json):
    nft = Nftables()
    result = nft.cmd("add table " + json_data["nftables"][0]["add"]["base_chain"]["family"] + " " + json_data["nftables"][0]["add"]["base_chain"]['table'])
    result = nft.cmd("add chain " + json_data["nftables"][0]["add"]["base_chain"]["family"] + " " + json_data["nftables"][0]["add"]["base_chain"]['table'] + " " + json_data["nftables"][0]["add"]["base_chain"]['name'] + " { type " + json_data["nftables"][0]["add"]["base_chain"]["type"] + " hook " + json_data["nftables"][0]["add"]["base_chain"]['hook_type'] + " priority " + str(json_data["nftables"][0]["add"]["base_chain"]['priority']) + " ; policy " + json_data["nftables"][0]["add"]["base_chain"]["policy"] + " ; }")    

    if(result[0] == 0):
        return {"status": "success"}
    else:
        return {"status": "error"}
    
@hug.get('/list_rule_chain')
def get_rule_chain(json_data: hug.types.json):
    nft = Nftables()
    result = nft.json_cmd(json_data)
    name = (json_data["nftables"][0]["list"]["chain"]["name"])
    table = (json_data["nftables"][0]["list"]["chain"]["table"])
    family = (json_data["nftables"][0]["list"]["chain"]["family"])
    name = name.replace("\n", "").replace("\r", "")    
    masquerade = nft.cmd("list chain " + family + " " + table + " " + name )
    aux = None
    if "masquerade" in masquerade:
        aux = True
    return {"rules": result[1], "masquerade": aux}

@hug.post('/edit_chain')
def edit_chain(json_data: hug.types.json):
    nft = Nftables()
    result = nft.json_cmd(json_data)
    if(result[0] == 0):
        return {"status": "success"}
    else:
        return {"status": "error"}
    
@hug.post('/edit_base_chain')
def edit_base_chain(json_data: hug.types.json):
    nft = Nftables()
    result = nft.cmd("chain " + json_data["nftables"][0]["edit"]["base_chain"]["family"] + " " + json_data["nftables"][0]["edit"]["base_chain"]['table'] + " " + json_data["nftables"][0]["edit"]["base_chain"]['name'] + " { type " + json_data["nftables"][0]["edit"]["base_chain"]["type"] + " hook " + json_data["nftables"][0]["edit"]["base_chain"]['hook_type'] + " priority " + str(json_data["nftables"][0]["edit"]["base_chain"]['priority']) + " ; policy " + json_data["nftables"][0]["edit"]["base_chain"]["policy"] + " ; }")    
    
    if(result[0] == 0):
        return {"status": "success"}
    else:
        return {"status": "error"}
    
@hug.post('/delete_chain')
def delete_chain(json_data: hug.types.json):
    nft = Nftables()
    result = nft.json_cmd(json_data)
    if(result[0] == 0):
        return {"status": "success"}
    else:
        return {"status": "error"}
    
@hug.post('/flush_chain')
def flush_chain(json_data: hug.types.json):
    nft = Nftables()
    result = nft.json_cmd(json_data)
    if(result[0] == 0):
        return {"status": "success"}
    else:
        return {"status": "error"}