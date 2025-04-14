import subprocess
import sys
import os
import multiprocessing

res = None
workers = multiprocessing.cpu_count() * 2 + 1
wsgi_app = "app:app"
bind = "0.0.0.0:10001"


def on_starting(server):
    global res
    res = subprocess.Popen(["/usr/bin/hug", "-f", "main.py"], cwd=os.path.abspath("../nftables-parser"), shell=False,
                           stdout=sys.stdout, stderr=sys.stderr)


def on_exit(server):
    res.terminate()
