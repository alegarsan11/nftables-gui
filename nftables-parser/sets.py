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

@hug.post('/add_element_to_set')
def add_element_to_set(json_data: hug.types.json):
    nft = Nftables()
    result = nft.json_cmd(json_data)
    print(result)
    return result

@hug.post('/create_set')
def create_set(json_data: hug.types.json):
    nft = Nftables()
    result = nft.json_cmd(json_data)
    print(result)
    return result

@hug.post('/delete_set')
def delete_set(json_data: hug.types.json):
    nft = Nftables()
    result = nft.json_cmd(json_data)
    return result

@hug.post('/delete_element_from_set')
def delete_element_from_set(json_data: hug.types.json):
    nft = Nftables()
    result = nft.json_cmd(json_data)
    return result