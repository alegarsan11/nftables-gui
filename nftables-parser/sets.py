from nftables import Nftables
import hug


@hug.get('/list_sets')
def list_sets():
    nft = Nftables()
    result = nft.json_cmd({'nftables': [{'list': {'sets': None}}]})
    return result

@hug.get('/list_elements_in_set')
def list_elements_in_set(json_data: hug.types.json):
    nft = Nftables()
    result = nft.json_cmd(json_data)
    return result