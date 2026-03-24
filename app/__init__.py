import os
import logging
from logging.handlers import RotatingFileHandler

from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from flask_security import Security, SQLAlchemyUserDatastore
from werkzeug.security import generate_password_hash

db = SQLAlchemy()

from .models import User, Role
user_datastore = SQLAlchemyUserDatastore(db, User, Role)

def create_app():
    app = Flask(__name__)

    # Configuración básica
    app.config['SECRET_KEY'] = 'mi_clave_super_segura_123'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Cambia esto si tu usuario/contraseña de MySQL es diferente
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:root@localhost/flasksecurity'

    app.config['SECURITY_PASSWORD_HASH'] = 'pbkdf2_sha512'
    app.config['SECURITY_PASSWORD_SALT'] = 'thisissecretsalt'

    # Inicializar extensiones
    db.init_app(app)
    Security(app, user_datastore)

    # =========================
    # CONFIGURACIÓN DE LOGS
    # =========================
    if not os.path.exists('logs'):
        os.mkdir('logs')

    file_handler = RotatingFileHandler(
        'logs/app.log',
        maxBytes=10240,
        backupCount=5,
        encoding='utf-8'
    )

    formatter = logging.Formatter(
        '%(asctime)s | %(levelname)s | %(message)s'
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.INFO)

    if not app.logger.handlers:
        app.logger.addHandler(file_handler)

    app.logger.setLevel(logging.INFO)
    app.logger.info('Inicio de la aplicación Flask')

    # Log de cada petición
    @app.before_request
    def log_request_info():
        app.logger.info(
            f'Petición: método={request.method}, ruta={request.path}, ip={request.remote_addr}'
        )

    # Crear tablas, roles y usuarios de prueba
    with app.app_context():
        db.create_all()

        user_datastore.find_or_create_role(name='admin', description='Administrador')
        user_datastore.find_or_create_role(name='end-user', description='Usuario final')
        db.session.commit()

        encrypted_password = generate_password_hash('password', method='pbkdf2:sha512')

        if not user_datastore.find_user(email='juan@example.com'):
            user1 = user_datastore.create_user(
                name='Juan Pérez',
                email='juan@example.com',
                password=encrypted_password
            )
            db.session.commit()
            user_datastore.add_role_to_user(user1, 'end-user')
            db.session.commit()

        if not user_datastore.find_user(email='admin@example.com'):
            user2 = user_datastore.create_user(
                name='Ismael García',
                email='admin@example.com',
                password=encrypted_password
            )
            db.session.commit()
            user_datastore.add_role_to_user(user2, 'admin')
            db.session.commit()

    # Manejo global de errores
    @app.errorhandler(Exception)
    def handle_exception(error):
        app.logger.error(f'Error en la aplicación: {str(error)}')
        return "Ocurrió un error interno en la aplicación.", 500

    # Blueprints
    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)

    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    return app