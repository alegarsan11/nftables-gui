import glob
import json
from nftables import Nftables
import sys, os
import hug

@hug.get('/reload_service')
def reload_service():
    os.system("sudo systemctl restart nftables")
    return {"status": "success"}

@hug.get('/save_service')
def save_service():
    os.system("sudo rm -f /etc/nftables.conf")
    os.system("sudo nft list ruleset > /etc/nftables.conf")
    os.system("sudo systemctl restart nftables")
    return {"status": "success"}

@hug.get('/save_service_temp')
def save_service_temp():
    files = glob.glob("./temp_config/nftables_temp*.conf")
    numbers = [int(f.replace("./temp_config/nftables_temp", "").replace(".conf", "")) for f in files]
    highest_number = max(numbers) if numbers else 0
    os.system(f"sudo nft list ruleset > ./temp_config/nftables_temp{highest_number + 1}.conf")