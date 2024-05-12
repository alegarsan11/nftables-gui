import pytest
from app import create_app
from models import db, User
from unittest.mock import patch
from api import parse_chains
from flask import request
from forms.forms import RuleForm, NotTerminalStatementForm
import views

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
@patch('api.create_chain_request')
def created_chain(mock_create_chain_request ,mock_create_table_request, logged_in_client):
    data = {"name": "creada", "family": "inet", "description": "filter table"}
    mock_create_table_request.return_value = "Success"
    logged_in_client.post('/add_table', data=data)
    mock_create_chain_request.return_value = "Success"
    data = {"table": "1&&inet", "name": "chain1", "policy": "accept", "family": "inet"}
    logged_in_client.post('/create_chain/', data=data)
    return logged_in_client

def test_create_rule_view(logged_in_client):
    response = logged_in_client.get('/rules/create_rule')
    assert response.status_code == 200
    assert b"Create Rule" in response.data

@patch('api.create_rule_request')
def test_create_rule_error(mock_create_rule_request, created_chain, app):
    with app.test_request_context('/rules/create_rule'):
            request.form = {
                "chain": "1&&inet&&creada&&chain1",
                "handle": None,
                "statements": {
                    "counter": True
                },
                "statement_select": "not_terminal",
                "description": "rule1 description",
                "submit": True
            }
            mock_create_rule_request.return_value = "Success", [{'counter': True}] 

            response = views.create_rule_post()
            print(response)
            
            
        