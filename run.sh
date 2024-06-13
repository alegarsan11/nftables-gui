#!/bin/bash

sudo apt install nftables python3-pip python3-hug python3-nftables

pip install -r requirements.txt

cd nftables-frontend

python3 app.py &

cd ../nftables-parser

sudo hug -f main.py
