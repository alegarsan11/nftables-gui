#!/bin/bash

rm /nftables-frontend/instance/nftables.db

pip install -r requirements.txt

sudo apt install nftables python3-pip python3-hug python3-nftables 

cd nftables-frontend

python app.py &

cd ../nftables-parser

sudo hug -f main.py