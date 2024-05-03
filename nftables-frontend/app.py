from flask import Flask, render_template
from views import visualization_bp, creation_bp
from flask_bootstrap import Bootstrap
from models import db
from flask_migrate import Migrate
import os
from service import create_default_user, login_manager


app = Flask(__name__)
app.register_blueprint(visualization_bp)
app.register_blueprint(creation_bp)
dir_path = os.path.dirname(os.path.realpath(__file__))
app.config['SECRET_KEY'] = 'hfds732klejds90ahg'
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{dir_path}/instance/nftables.db'
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['SESSION_COOKIE_SECURE'] = True
login_manager.init_app(app)
db.init_app(app)

with app.app_context():
    db.create_all()
    create_default_user()

migrate = Migrate(app, db)
Bootstrap(app)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', message='Page not found'), 404


@app.errorhandler(500)
def internal_error(e):
    return render_template('error.html', message="Internal server error"), 500

@app.route('/favicon.ico')
def favicon():
    return app.send_static_file('favicon.ico')

if __name__ == '__main__':
    app.run(debug=False)