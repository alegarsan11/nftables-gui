import pytest
from app import create_app
from models import db, User
from forms.forms import LoginForm

@pytest.fixture()
def app():
    app = create_app()
    app.config.update({
        "TESTING": True,
        "WTF_CSRF_ENABLED": False, 
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:"

    })
    
    yield app
    
@pytest.fixture()
def client(app):
    return app.test_client()

@pytest.fixture()
def runner(app):
    return app.test_cli_runner()

@pytest.fixture()
def init_database():
    user = User(username='default', password='defaultpassword')
    db.session.add(user)
    db.session.commit()


def test_main(client):
    response = client.get('/')
    assert response.status_code == 200 
    assert b'Login' in response.data
    
def test_main_login(client):
    data = {"username": "default", "password": "defaultpassword"}
    response = client.post('/login', data=data)
    assert response.status_code == 302
    response = client.get('/')
    print(response.data)
    assert b'Logout' in response.data
    
    