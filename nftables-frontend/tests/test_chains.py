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
@pytest.fixture()
@patch('api.create_table_request')
def created_table(mock_create_table_request, logged_in_client):
    data = {"name": "creada", "family": "inet", "description": "filter table"}
    mock_create_table_request.return_value = "Success"
    logged_in_client.post('/add_table', data=data)
    return logged_in_client

@patch('api.create_chain_request')
@patch('api.create_table_request')
def test_create_chain(mock_create_chain_request, mock_create_table_request ,logged_in_client):
    data = {"name": "creada", "family": "inet", "description": "filter table"}
    mock_create_table_request.return_value = "Success"
    logged_in_client.post('/add_table', data=data)
    mock_create_chain_request.return_value = "Success"
    data = {"table": "1&&inet", "name": "chain1", "policy": "accept", "family": "inet"}
    response = logged_in_client.post('/create_chain/', data=data)
    mock_create_chain_request.assert_called_once()
    assert response.status_code == 302
    assert response.location == '/chains'
    
def test_create_chain_view(logged_in_client):
    response = logged_in_client.get('/create_chain')
    assert response.status_code == 200
    
def test_create_base_chain_view(logged_in_client):
    response = logged_in_client.get('/create_base_chain')
    assert response.status_code == 200
    
@patch('api.create_base_chain_request')
def test_create_base_chain(mock_create_base_chain_request, created_table):
    mock_create_base_chain_request.return_value = "Success"
    data = {"table": "inet&&1", "name": "chain1", "family": "inet", "type": "filter", "hook_type": "input", "prio": 0, "policy": "accept"}
    response = created_table.post('/create_base_chain/', data=data)
    assert response.status_code == 302
    assert response.location == '/chains'
    mock_create_base_chain_request.assert_called_once()

    
@patch('api.create_chain_request')
@patch('api.list_chains_request')   
@patch('api.flush_chain_request')
def test_flush_chain(mock_flush_chain_request, mock_list_chains_request, mock_create_chain_request, created_table):
    mock_create_chain_request.return_value = "Success"
    data = {"table": "1&&inet", "name": "chain1", "policy": "accept", "family": "inet"}
    created_table.post('/create_chain/', data=data)
    chains = {"chains": {"nftables": [{"metainfo": {"version": "1.0.2", "release_name": "Lester Gooch", "json_schema_version": 1}}, {"chain": {"family": "inet", "table": "creada", "name": "chain1", "handle": 1, "type": "filter", "hook": "input", "prio": 0, "policy": "accept"}}]}}
    mock_list_chains_request.return_value = chains
    created_table.get('/chains')
    mock_list_chains_request.assert_called_once()
    response = created_table.get('/chains/1/creada/flush') 
    assert response.status_code == 302
    mock_flush_chain_request.assert_called_once()
    
@patch('api.create_chain_request')
@patch('api.list_chains_request')
def test_list_chains(mock_list_chains_request, mock_create_chain_request, created_table):
    mock_create_chain_request.return_value = "Success"
    data = {"table": "1&&inet", "name": "chain1", "policy": "accept", "family": "inet"}
    created_table.post('/create_chain/', data=data)
    chains = {"chains": {"nftables": [{"metainfo": {"version": "1.0.2", "release_name": "Lester Gooch", "json_schema_version": 1}}, {"chain": {"family": "inet", "table": "creada", "name": "chain1", "handle": 1, "type": "filter", "hook": "input", "prio": 0, "policy": "accept"}}]}}
    mock_list_chains_request.return_value = chains
    response = created_table.get('/chains')
    assert response.status_code == 200
    assert b'Chains' in response.data
    assert b'chain1' in response.data
    
@patch('api.create_chain_request')
@patch('api.list_chains_request')
def test_view_chain(mock_list_chains_request, mock_create_chain_request, created_table):
    mock_create_chain_request.return_value = "Success"
    data = {"table": "1&&inet", "name": "chain1", "policy": "accept", "family": "inet"}
    created_table.post('/create_chain/', data=data)
    chains = {"chains": {"nftables": [{"metainfo": {"version": "1.0.2", "release_name": "Lester Gooch", "json_schema_version": 1}}, {"chain": {"family": "inet", "table": "creada", "name": "chain1", "handle": 1, "type": "filter", "prio": 0, "policy": "accept"}}]}}
    mock_list_chains_request.return_value = chains
    created_table.get('/chains')
    response = created_table.get('/chain/chain1/inet/1')
    assert response.status_code == 200
    assert b'Chain' in response.data
    assert b'chain1' in response.data
    assert b'accept' in response.data
    assert b'0' in response.data
    
@patch('api.create_chain_request')
@patch('api.delete_chain_request')
@patch('api.list_chains_request')
def test_delete_chain(mock_list_chains_request, mock_delete_chain_request, mock_create_chain_request, created_table):
    mock_create_chain_request.return_value = "Success"
    data = {"table": "1&&inet", "name": "chain1", "policy": "accept", "family": "inet"}
    created_table.post('/create_chain/', data=data)
    chains = {"chains": {"nftables": [{"metainfo": {"version": "1.0.2", "release_name": "Lester Gooch", "json_schema_version": 1}}, {"chain": {"family": "inet", "table": "creada", "name": "chain1", "handle": 1, "type": "filter", "prio": 0, "policy": "accept"}}]}}
    mock_list_chains_request.return_value = chains
    created_table.get('/chains')
    response = created_table.get('/chains/1/creada/delete')
    assert response.status_code == 302
    mock_delete_chain_request.assert_called_once()