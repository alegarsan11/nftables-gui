import json
from nftables import Nftables, Chain
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
    print(result)
    if(result[0] == 0):
        return {"status": "success"}
    else:
        return {"status": "error"}
    
@hug.post('/create_base_chain')
def create_base_chain(json_data: hug.types.json):
    nft = Nftables()
    chain = Chain(json_data["nftables"][0]["add"]["chain"])
    result = nft.json_cmd(json_data)
    if(result[0] == 0):
        return {"status": "success"}
    else:
        return {"status": "error"}