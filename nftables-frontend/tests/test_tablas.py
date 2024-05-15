import pytest
from app import create_app
from models import db, User
from unittest.mock import patch
from api import parse_chains

@pytest.fixture()
def app():
    app = create_app()
    app.config.update({
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:"

    })
    with app.app_context():
        db.create_all()  # Crear las tablas de la base de datos
    yield app
    with app.app_context():
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()

@pytest.fixture()
def runner(app):
    return app.test_cli_runner()

@pytest.fixture()
def init_database():
    meta = db.metadata
    for table in reversed(meta.sorted_tables):
        db.session.execute(table.delete())
    user = User(username='default', password='defaultpassword')
    db.session.add(user)
    db.session.commit()

@pytest.fixture()
def logged_in_client(client):
    data = {"username": "default", "password": "defaultpassword"}
    client.post('/login', data=data)
    return client

@patch('api.list_tables_request')
def test_list_tables(mock_list_tables_request ,logged_in_client):
    data = {"tables": "table inet filter\ntable ip nat\ntable ip filter\n"}
    mock_list_tables_request.return_value = data["tables"]
    response = logged_in_client.get('/tables')
    assert response.status_code == 200
    assert b'Tables' in response.data


@patch('api.create_table_request')
def test_create_table(mock_create_table_request, logged_in_client):
    data = {"name": "creada", "family": "inet", "description": "filter table"}
    mock_create_table_request.return_value = "Success"
    response = logged_in_client.post('/add_table', data=data)
    assert response.status_code == 302
    mock_create_table_request.assert_called_once()

def test_view_create_table(logged_in_client):
    response = logged_in_client.get('/add_table')
    assert response.status_code == 200
    assert b'Create Table' in response.data

@patch('api.delete_table_request')
@patch('api.create_table_request')
def test_delete_table(mock_delete_table_request, mock_create_table_request, logged_in_client):
    mock_delete_table_request.return_value = "Success"
    mock_create_table_request.return_value = "Success"
    data = {"name": "filter", "family": "inet", "description": "filter table"}
    logged_in_client.post('/add_table', data=data)
    response = logged_in_client.get('/delete_table/filter/inet')
    assert response.status_code == 302
    mock_delete_table_request.assert_called_once()

@patch('api.list_tables_request')
@patch('api.list_chains_request')
@patch('api.list_sets_request')
@patch('api.list_maps_request')
@patch('api.list_chain_request')
@patch('api.flush_table_request')
def test_flush_table( mock_flush_table_request,mock_list_chain_request,mock_list_maps_request, mock_list_sets_request , mock_list_chains_requests, mock_list_tables_request , logged_in_client):
    tables = {"tables": "table inet filter\ntable ip nat\ntable ip filter\n"}
    chains = {"chains": {"nftables": [{"metainfo": {"version": "1.0.2", "release_name": "Lester Gooch", "json_schema_version": 1}}, {"chain": {"family": "inet", "table": "filter", "name": "input", "handle": 1, "type": "filter", "hook": "input", "prio": 0, "policy": "accept"}}, {"chain": {"family": "inet", "table": "filter", "name": "forward", "handle": 2, "type": "filter", "hook": "forward", "prio": 0, "policy": "accept"}}, {"chain": {"family": "inet", "table": "filter", "name": "output", "handle": 3, "type": "filter", "hook": "output", "prio": 0, "policy": "accept"}}, {"chain": {"family": "ip", "table": "nat", "name": "DOCKER", "handle": 1}}, {"chain": {"family": "ip", "table": "nat", "name": "POSTROUTING", "handle": 2, "type": "nat", "hook": "postrouting", "prio": 100, "policy": "accept"}}, {"chain": {"family": "ip", "table": "nat", "name": "PREROUTING", "handle": 3, "type": "nat", "hook": "prerouting", "prio": -100, "policy": "accept"}}, {"chain": {"family": "ip", "table": "nat", "name": "OUTPUT", "handle": 4, "type": "nat", "hook": "output", "prio": -100, "policy": "accept"}}, {"chain": {"family": "ip", "table": "filter", "name": "DOCKER", "handle": 1}}, {"chain": {"family": "ip", "table": "filter", "name": "DOCKER-ISOLATION-STAGE-1", "handle": 2}}, {"chain": {"family": "ip", "table": "filter", "name": "FORWARD", "handle": 4, "type": "filter", "hook": "forward", "prio": 0, "policy": "drop"}}, {"chain": {"family": "ip", "table": "filter", "name": "DOCKER-USER", "handle": 5}}, {"chain": {"family": "ip", "table": "filter", "name": "DOCKER-ISOLATION-STAGE-2", "handle": 40}}]}}
    sets = [0, {"nftables": [{"metainfo": {"version": "1.0.2", "release_name": "Lester Gooch", "json_schema_version": 1}}, {"set": {"family": "inet", "name": "my_map", "table": "filter", "type": "ipv4_addr", "handle": 4}}]}, ""]
    maps = [0, {"chains": {"nftables": [{"metainfo": {"version": "1.0.2", "release_name": "Lester Gooch", "json_schema_version": 1}}, {"map": {"family": "ip", "name": "my_map", "table": "filter", "type": "ipv4_addr", "handle": 62, "map": "ipv4_addr"}}]}}]
    mock_list_sets_request.return_value = sets[1]["nftables"]
    mock_list_maps_request.return_value = maps[1]["chains"]["nftables"]
    mock_list_chain_request.return_value ={"rules": {"nftables": [{"metainfo": {"version": "1.0.2", "release_name": "Lester Gooch", "json_schema_version": 1}}, {"chain": {"family": "ip", "table": "filter", "name": "FORWARD", "handle": 4, "type": "filter", "hook": "forward", "prio": 0, "policy": "drop"}}, {"rule": {"family": "ip", "table": "filter", "chain": "FORWARD", "handle": 61, "expr": [{"counter": {"packets": 137, "bytes": 41966}}, {"jump": {"target": "DOCKER-USER"}}]}}, {"rule": {"family": "ip", "table": "filter", "chain": "FORWARD", "handle": 58, "expr": [{"counter": {"packets": 137, "bytes": 41966}}, {"jump": {"target": "DOCKER-ISOLATION-STAGE-1"}}]}}, {"rule": {"family": "ip", "table": "filter", "chain": "FORWARD", "handle": 57, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "docker0"}}, {"xt": None}, {"counter": {"packets": 0, "bytes": 0}}, {"accept": None}]}}, {"rule": {"family": "ip", "table": "filter", "chain": "FORWARD", "handle": 56, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "docker0"}}, {"counter": {"packets": 0, "bytes": 0}}, {"jump": {"target": "DOCKER"}}]}}, {"rule": {"family": "ip", "table": "filter", "chain": "FORWARD", "handle": 55, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "docker0"}}, {"match": {"op": "!=", "left": {"meta": {"key": "oifname"}}, "right": "docker0"}}, {"counter": {"packets": 0, "bytes": 0}}, {"accept": None}]}}, {"rule": {"family": "ip", "table": "filter", "chain": "FORWARD", "handle": 54, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "docker0"}}, {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "docker0"}}, {"counter": {"packets": 0, "bytes": 0}}, {"accept": None}]}}, {"rule": {"family": "ip", "table": "filter", "chain": "FORWARD", "handle": 50, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "br-e68c7fe6e768"}}, {"xt": None}, {"counter": {"packets": 136, "bytes": 41906}}, {"accept": None}]}}, {"rule": {"family": "ip", "table": "filter", "chain": "FORWARD", "handle": 20, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "docker0"}}, {"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": ["established", "related"]}}, {"counter": {"packets": 0, "bytes": 0}}, {"accept": None}]}}, {"rule": {"family": "ip", "table": "filter", "chain": "FORWARD", "handle": 21, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "docker0"}}, {"counter": {"packets": 0, "bytes": 0}}, {"jump": {"target": "DOCKER"}}]}}, {"rule": {"family": "ip", "table": "filter", "chain": "FORWARD", "handle": 22, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "docker0"}}, {"match": {"op": "!=", "left": {"meta": {"key": "oifname"}}, "right": "docker0"}}, {"counter": {"packets": 0, "bytes": 0}}, {"accept": None}]}}, {"rule": {"family": "ip", "table": "filter", "chain": "FORWARD", "handle": 23, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "docker0"}}, {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "docker0"}}, {"counter": {"packets": 0, "bytes": 0}}, {"accept": None}]}}, {"rule": {"family": "ip", "table": "filter", "chain": "FORWARD", "handle": 24, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "br-e68c7fe6e768"}}, {"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": ["established", "related"]}}, {"counter": {"packets": 131, "bytes": 41646}}, {"accept": None}]}}, {"rule": {"family": "ip", "table": "filter", "chain": "FORWARD", "handle": 25, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "br-e68c7fe6e768"}}, {"counter": {"packets": 2, "bytes": 120}}, {"jump": {"target": "DOCKER"}}]}}, {"rule": {"family": "ip", "table": "filter", "chain": "FORWARD", "handle": 26, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "br-e68c7fe6e768"}}, {"match": {"op": "!=", "left": {"meta": {"key": "oifname"}}, "right": "br-e68c7fe6e768"}}, {"counter": {"packets": 0, "bytes": 0}}, {"accept": None}]}}, {"rule": {"family": "ip", "table": "filter", "chain": "FORWARD", "handle": 27, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "br-e68c7fe6e768"}}, {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "br-e68c7fe6e768"}}, {"counter": {"packets": 2, "bytes": 120}}, {"accept": None}]}}, {"rule": {"family": "ip", "table": "filter", "chain": "FORWARD", "handle": 28, "expr": [{"counter": {"packets": 132, "bytes": 41706}}, {"jump": {"target": "DOCKER-USER"}}]}}, {"rule": {"family": "ip", "table": "filter", "chain": "FORWARD", "handle": 29, "expr": [{"counter": {"packets": 132, "bytes": 41706}}, {"jump": {"target": "DOCKER-ISOLATION-STAGE-1"}}]}}, {"rule": {"family": "ip", "table": "filter", "chain": "FORWARD", "handle": 30, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "docker0"}}, {"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": ["established", "related"]}}, {"counter": {"packets": 0, "bytes": 0}}, {"accept": None}]}}, {"rule": {"family": "ip", "table": "filter", "chain": "FORWARD", "handle": 31, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "docker0"}}, {"counter": {"packets": 0, "bytes": 0}}, {"jump": {"target": "DOCKER"}}]}}, {"rule": {"family": "ip", "table": "filter", "chain": "FORWARD", "handle": 32, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "docker0"}}, {"match": {"op": "!=", "left": {"meta": {"key": "oifname"}}, "right": "docker0"}}, {"counter": {"packets": 0, "bytes": 0}}, {"accept": None}]}}, {"rule": {"family": "ip", "table": "filter", "chain": "FORWARD", "handle": 33, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "docker0"}}, {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "docker0"}}, {"counter": {"packets": 0, "bytes": 0}}, {"accept": None}]}}, {"rule": {"family": "ip", "table": "filter", "chain": "FORWARD", "handle": 34, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "br-e68c7fe6e768"}}, {"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": ["established", "related"]}}, {"counter": {"packets": 131, "bytes": 41646}}, {"accept": None}]}}, {"rule": {"family": "ip", "table": "filter", "chain": "FORWARD", "handle": 35, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "br-e68c7fe6e768"}}, {"counter": {"packets": 1, "bytes": 60}}, {"jump": {"target": "DOCKER"}}]}}, {"rule": {"family": "ip", "table": "filter", "chain": "FORWARD", "handle": 36, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "br-e68c7fe6e768"}}, {"match": {"op": "!=", "left": {"meta": {"key": "oifname"}}, "right": "br-e68c7fe6e768"}}, {"counter": {"packets": 0, "bytes": 0}}, {"accept": None}]}}, {"rule": {"family": "ip", "table": "filter", "chain": "FORWARD", "handle": 37, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "br-e68c7fe6e768"}}, {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "br-e68c7fe6e768"}}, {"counter": {"packets": 1, "bytes": 60}}, {"accept": None}]}}]}}
    mock_list_chains_requests.return_value = chains
    mock_list_tables_request.return_value = tables["tables"]
    mock_flush_table_request.return_value = "Success"
    response = logged_in_client.get('/')
    response = logged_in_client.get('/flush_table/filter/ip')
    assert response.status_code == 302
    mock_flush_table_request.assert_called_once()
    
@patch('api.create_table_request')
@patch('api.list_table_request')
def test_view_table(mock_list_table_request ,mock_create_table_request, logged_in_client):
    mock_create_table_request.return_value = "Success"
    data = {"name": "filter", "family": "inet", "description": "filter table"}
    logged_in_client.post('/add_table', data=data)
    data = {"status": "success", "result": [0, {"nftables": [{"metainfo": {"version": "1.0.2", "release_name": "Lester Gooch", "json_schema_version": 1}}, {"table": {"family": "inet", "name": "filter", "handle": 15}}, {"set": {"family": "inet", "name": "my_map", "table": "filter", "type": "ipv4_addr", "handle": 4}}, {"chain": {"family": "inet", "table": "filter", "name": "input", "handle": 1, "type": "filter", "hook": "input", "prio": 0, "policy": "accept"}}, {"chain": {"family": "inet", "table": "filter", "name": "forward", "handle": 2, "type": "filter", "hook": "forward", "prio": 0, "policy": "accept"}}, {"chain": {"family": "inet", "table": "filter", "name": "output", "handle": 3, "type": "filter", "hook": "output", "prio": 0, "policy": "accept"}}]}, ""]}
    mock_list_table_request.return_value = parse_chains(data["result"][1]["nftables"])
    response = logged_in_client.get('/table/filter/inet')
    assert response.status_code == 200
    assert b'Table' in response.data
    assert b'filter' in response.data
    mock_list_table_request.assert_called_once()