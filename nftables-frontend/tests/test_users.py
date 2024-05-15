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

def test_view_users(logged_in_client):
    response = logged_in_client.get('/users')
    assert response.status_code == 200
    assert b'Users' in response.data
    
def test_add_user(logged_in_client):
    data = {"username": "test", "password": "testpassword","confirm_password": "testpassword" , "role": "administrator"}
    response = logged_in_client.post('/create_user', data=data)
    assert response.status_code == 302
    
def test_delete_user(logged_in_client):
    data = {"username": "test", "password": "testpassword","confirm_password": "testpassword" , "role": "administrator"}
    logged_in_client.post('/create_user', data=data)
    response = logged_in_client.get('/delete_user/2')
    assert response.status_code == 302
    assert response.location == '/users'
    
