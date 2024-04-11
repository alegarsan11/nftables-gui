#!/bin/bash

pip install -r requirements.txt

cd nftables-frontend

python app.py &

cd ../nftables-parser

sudo hug -f main.py