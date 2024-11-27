# encoding=utf-8
__author__ = 'Zephyr369'

import random
import flasgger
import jwt
from flasgger import swag_from
from flask import request, jsonify, current_app, Blueprint, flash, url_for, render_template, session, make_response
from flask_login import logout_user, login_required, login_user, current_user
from flask_jwt_extended import jwt_required, get_jwt_identity, create_access_token
from werkzeug.exceptions import abort
from werkzeug.utils import redirect

from .. import logger
from ..forms.auth import EmailForm
from ..libs.captcha import CaptchaManager
from ..libs.email import send_mail
from ..models import Order
from ..models.CarItem import CartItem
from ..models.ShopUser import ShopUser
from ..models.base import db
from ..utils.verify_email import is_valid_email

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        nickname = request.form.get('nickname')
        email = request.form.get('email')
        password = request.form.get('password')

        if not all([nickname, email, password]):
            flash('所有字段都是必需的', 'error')
            return redirect(url_for('web.auth.register'))

        existing_user = ShopUser.query.filter_by(email=email).first()
        if existing_user:
            flash('该邮箱已被注册', 'error')
            return redirect(url_for('web.auth.register'))

        user = ShopUser(
            nickname=nickname,
            email=email,
            password=password
        )
        db.session.add(user)
        db.session.commit()

        # 生成验证码并发送激活邮件
        activation_code = ''.join([str(random.randint(0, 9)) for _ in range(6)])
        user.generate_captcha(activation_code)
        # send_mail(user, '激活您的账号', 'email/activate_account.html', code=activation_code)
        captcha_manager = CaptchaManager(user)
        captcha_manager.generate_captcha()
        captcha_manager.send_captcha_email("激活您的账户验证码", 'email/activate_account.html')
        flash('注册成功，请检查您的邮箱以激活账号', 'success')
        return redirect(url_for('web.auth.activate'))

    return render_template('auth/register.html')


@auth_bp.route('/activate', methods=['GET', 'POST'])
def activate():
    if request.method == 'POST':
        email = request.form.get('email')
        code = request.form.get('code')

        user = ShopUser.query.filter_by(email=email).first()
        if not user:
            flash('用户不存在', 'error')
            return redirect(url_for('web.auth.activate'))

        if user.is_active:
            flash('用户已激活，请直接登录', 'info')
            return redirect(url_for('web.auth.login'))

        if user.verify_captcha(code):
            user.is_active = True
            db.session.commit()
            flash('账户激活成功，请登录', 'success')
            return redirect(url_for('web.auth.login'))
        else:
            flash('验证码错误或已过期', 'error')
            return redirect(url_for('web.auth.activate'))

    return render_template('auth/activate_account.html')


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = ShopUser.query.filter_by(email=email).first()
        if not user:
            flash('用户不存在', 'error')
            return redirect(url_for('web.auth.login'))

        if not user.is_active:
            flash('账号未激活，请先激活', 'error')
            return redirect(url_for('web.auth.activate'))

        if not user.verify_password(password):
            flash('密码错误', 'error')
            return redirect(url_for('web.auth.login'))

        login_user(user)
        flash('登录成功', 'success')
        return redirect(url_for('web.shop.index'))

    return render_template('auth/login.html')

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('您已成功退出登录', 'info')
    return redirect(url_for('web.shop.index'))
