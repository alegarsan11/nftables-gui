from nftables import Nftables
import hug


@hug.post('/create_rule')
def create_rule(json_data: hug.types.json):
    nft = Nftables()
    result = nft.json_cmd(json_data)
    if(result[0] == 0):
        return {"status": "success"}
    else:
        return {"status": "error"}    
    
@hug.post('/delete_rule')
def delete_rule(json_data: hug.types.json):
    nft = Nftables()
    result = nft.json_cmd(json_data)
    if(result[0] == 0):
        return {"status": "success"}
    else:
        return {"status": "error"}