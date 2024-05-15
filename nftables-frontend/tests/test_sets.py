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

def test_create_set_view(logged_in_client):
    response = logged_in_client.get('/sets/new')
    assert response.status_code == 200

@patch('api.create_table_request')
@patch('api.create_set_request')
def test_create_set(mock_create_set_request,mock_create_table_request ,logged_in_client):
    mock_create_table_request.return_value = "Success"
    data = {"name": "filter", "family": "inet", "description": "filter table"}
    logged_in_client.post('/add_table', data=data)
    data = {
        "name": "test_set",
        "type": "ipv4_addr",
        "elements": "",
        "table": "1&&inet"
    }
    mock_create_set_request.return_value = "Success"
    response = logged_in_client.post('/sets/new', data=data)
    assert response.status_code == 302
    assert response.headers['Location'] == '/sets'


@patch('api.create_table_request')
@patch('api.create_set_request')
@patch('api.delete_set_request')
def test_delete_set(mock_delete_set_request,mock_create_set_request,mock_create_table_request ,logged_in_client):
    mock_create_table_request.return_value = "Success"
    data = {"name": "filter", "family": "inet", "description": "filter table"}
    logged_in_client.post('/add_table', data=data)
    data = {
        "name": "test_set",
        "type": "ipv4_addr",
        "elements": "",
        "table": "1&&inet"
    }
    mock_create_set_request.return_value = "Success"
    logged_in_client.post('/sets/new', data=data)
    mock_delete_set_request.return_value = "Success"
    response = logged_in_client.get('/sets/1/delete')
    assert response.status_code == 302
    assert response.headers['Location'] == '/sets'
    
@patch('api.create_table_request')
@patch('api.create_set_request')
def test_edit_set_view(mock_create_set_request,mock_create_table_request,logged_in_client):
    mock_create_table_request.return_value = "Success"
    data = {"name": "filter", "family": "inet", "description": "filter table"}
    logged_in_client.post('/add_table', data=data)
    data = {
        "name": "test_set",
        "type": "ipv4_addr",
        "elements": "",
        "table": "1&&inet"
    }
    mock_create_set_request.return_value = "Success"
    logged_in_client.post('/sets/new', data=data)
    response = logged_in_client.get('/sets/1/add_element')
    assert response.status_code == 200
    
    
@patch('api.create_table_request')
@patch('api.create_set_request')
@patch('api.list_elements_in_set')
@patch('api.add_element_to_set_request')
def test_add_element(mock_add_element_to_set_request,mock_list_elements_in_set, mock_create_set_request,mock_create_table_request,logged_in_client):
    mock_create_table_request.return_value = "Success"
    data = {"name": "filter", "family": "inet", "description": "filter table"}
    logged_in_client.post('/add_table', data=data)
    data = {
        "name": "test_set",
        "type": "ipv4_addr",
        "table": "1&&inet"
    }
    mock_create_set_request.return_value = "Success"
    logged_in_client.post('/sets/new', data=data)
    mock_list_elements_in_set.return_value = [0, {"nftables": [{"metainfo": {"version": "1.0.2", "release_name": "Lester Gooch", "json_schema_version": 1}}, {"set": {"family": "inet", "name": "my_map", "table": "filter", "type": "ipv4_addr", "handle": 4, "elements": ""}}]}, ""]
    logged_in_client.get('/sets/1')
    mock_add_element_to_set_request.return_value = "Success"
    data = {"element": "21.34.65.23"}
    response = logged_in_client.post('/sets/1/add_element', data=data)
    assert response.status_code == 302

@patch('api.create_table_request')
@patch('api.create_set_request')
@patch('api.list_elements_in_set')
def test_delete_element_view(mock_list_elements_in_set, mock_create_set_request, mock_create_table_request ,logged_in_client):
    mock_create_table_request.return_value = "Success"
    data = {"name": "filter", "family": "inet", "description": "filter table"}
    logged_in_client.post('/add_table', data=data)
    data = {
        "name": "test_set",
        "type": "ipv4_addr",
        "table": "1&&inet"
    }
    mock_create_set_request.return_value = "Success"
    logged_in_client.post('/sets/new', data=data)
    mock_list_elements_in_set.return_value = [0, {"nftables": [{"metainfo": {"version": "1.0.2", "release_name": "Lester Gooch", "json_schema_version": 1}}, {"set": {"family": "inet", "name": "my_map", "table": "filter", "type": "ipv4_addr", "handle": 4, "elements": ""}}]}, ""]
    logged_in_client.get('/sets/1')
    response = logged_in_client.get('/sets/1/add_element')
    assert response.status_code == 200
    
@patch('api.create_table_request')
@patch('api.create_set_request')
@patch('api.list_elements_in_set')
@patch('api.add_element_to_set_request')
@patch('api.delete_element_from_set_request')
def test_delete_element(mock_delete_element_from_set_request, mock_add_element_to_set_request,mock_list_elements_in_set, mock_create_set_request,mock_create_table_request,logged_in_client):
    mock_create_table_request.return_value = "Success"
    data = {"name": "filter", "family": "inet", "description": "filter table"}
    logged_in_client.post('/add_table', data=data)
    data = {
        "name": "test_set",
        "type": "ipv4_addr",
        "table": "1&&inet"
    }
    mock_create_set_request.return_value = "Success"
    logged_in_client.post('/sets/new', data=data)
    mock_list_elements_in_set.return_value = [0, {"nftables": [{"metainfo": {"version": "1.0.2", "release_name": "Lester Gooch", "json_schema_version": 1}}, {"set": {"family": "inet", "name": "my_map", "table": "filter", "type": "ipv4_addr", "handle": 4, "elements": ""}}]}, ""]
    logged_in_client.get('/sets/1')
    mock_add_element_to_set_request.return_value = "Success"
    data = {"element": "21.34.65.23"}
    logged_in_client.post('/sets/1/add_element', data=data)
    response = logged_in_client.post('/sets/1/delete_element', data=data)
    assert response.status_code == 302
    assert response.headers['Location'] == '/sets/1'
