from flask import Blueprint, render_template, redirect, url_for, request, flash, current_app
from werkzeug.security import generate_password_hash, check_password_hash

from flask_security.utils import login_user, logout_user
from flask_security import current_user

from .models import User
from . import db, user_datastore

auth = Blueprint('auth', __name__, url_prefix='/security')

@auth.route('/login')
def login():
    return render_template('security/login.html')

@auth.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(email=email).first()

    if not user:
        current_app.logger.warning(
            f'Intento de acceso fallido: correo={email}, motivo=usuario_no_existe'
        )
        flash('El usuario y/o la contraseña son incorrectos')
        return redirect(url_for('auth.login'))

    if not check_password_hash(user.password, password):
        current_app.logger.warning(
            f'Intento de acceso fallido: id={user.id}, correo={email}, motivo=password_incorrecto'
        )
        flash('El usuario y/o la contraseña son incorrectos')
        return redirect(url_for('auth.login'))

    login_user(user, remember=remember)

    current_app.logger.info(
        f'Acceso exitoso: id={user.id}, nombre="{user.name}", correo={user.email}'
    )

    return redirect(url_for('main.profile'))

@auth.route('/register')
def register():
    return render_template('security/register.html')

@auth.route('/register', methods=['POST'])
def register_post():
    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')

    user = User.query.filter_by(email=email).first()

    if user:
        current_app.logger.warning(
            f'Intento de registro fallido: correo={email}, motivo=correo_ya_existente'
        )
        flash('Ya existe un usuario con ese email')
        return redirect(url_for('auth.register'))

    try:
        new_user = user_datastore.create_user(
            name=name,
            email=email,
            password=generate_password_hash(password, method='pbkdf2:sha512')
        )
        db.session.commit()

        # Asignar rol por defecto
        user_datastore.add_role_to_user(new_user, 'end-user')
        db.session.commit()

        current_app.logger.info(
            f'Registro de nuevo usuario: id={new_user.id}, nombre="{new_user.name}", correo={new_user.email}'
        )

        return redirect(url_for('auth.login'))

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(
            f'Error en registro de usuario: correo={email}, error={str(e)}'
        )
        flash('Ocurrió un error al registrar el usuario')
        return redirect(url_for('auth.register'))

@auth.route('/logout')
def logout():
    if current_user.is_authenticated:
        current_app.logger.info(
            f'Cierre de sesión: id={current_user.id}, correo={current_user.email}'
        )

    logout_user()
    return redirect(url_for('main.index'))