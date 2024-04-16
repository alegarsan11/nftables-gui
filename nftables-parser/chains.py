import json
from nftables import Nftables
import sys
import hug

@hug.get('/list_chains')
def list_chains(json_data: hug.types.json):
    nft = Nftables()
    result = nft.json_cmd(json_data)
    return {"chains": result[1]}