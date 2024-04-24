from nftables import Nftables
import hug


@hug.post('/create_rule')
def create_rule(json_data: hug.types.json):
    print(json_data)
    nft = Nftables()
    result = nft.json_cmd(json_data)
    return result 
    