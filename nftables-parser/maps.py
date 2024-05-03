from nftables import Nftables
import hug

@hug.get('/list_maps')
def list_maps(json_data: hug.types.json):
    nft = Nftables()
    result = nft.json_cmd(json_data)
    return result

@hug.get('/list_elements_in_map')
def list_elements_in_map(json_data: hug.types.json):
    nft = Nftables()
    result = nft.json_cmd(json_data)
    return result

@hug.post('/create_map')
def create_map(json_data: hug.types.json):
    nft = Nftables()
    result = nft.json_cmd(json_data)
    return result

@hug.post('/delete_map')
def delete_map(json_data: hug.types.json):
    nft = Nftables()
    result = nft.json_cmd(json_data)
    return result

@hug.post('/add_element_to_map')
def add_element_to_map(json_data: hug.types.json):
    nft = Nftables()
    result = nft.json_cmd(json_data)
    return result

@hug.post('/delete_element_from_map')
def delete_element_from_map(json_data: hug.types.json):
    nft = Nftables()
    result = nft.json_cmd(json_data)
    return result