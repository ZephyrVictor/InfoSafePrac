# encoding=utf-8
__author__ = 'Zephyr369'

import flasgger
import jwt
from flasgger import swag_from
from flask import request, jsonify, current_app, Blueprint, flash, url_for, render_template, session, make_response
from flask_login import logout_user, login_required, login_user
from flask_jwt_extended import jwt_required, get_jwt_identity, create_access_token
from werkzeug.utils import redirect

from .. import logger
from ..forms.auth import EmailForm
from ..libs.captcha import CaptchaManager
from ..libs.email import send_mail
from ..models.BankUser import BankUser
from ..models.ShopUser import ShopUser
from ..models.base import db
from ..utils.verify_email import is_valid_email

auth_bp = Blueprint('auth', __name__)


@auth_bp.route("/bank/register", methods=['GET', 'POST'])
def bank_register():
    if request.method == 'POST':
        nickname = request.form.get('nickname')
        email = request.form.get('email')
        password = request.form.get('password')
        payPassword = request.form.get('payPassword')

        if not all([nickname, email, password, payPassword]):
            flash('所有字段都是必需的', 'error')
            return redirect(url_for('web.auth.bank_register'))

        # 验证邮箱格式是否有效
        if not is_valid_email(email):
            flash('无效的邮箱格式', 'error')
            return redirect(url_for('web.auth.bank_register'))

        existing_user = BankUser.query.filter_by(email=email).first()
        if existing_user:
            flash('该邮箱已被注册', 'error')
            return redirect(url_for('web.auth.bank_register'))

        user = BankUser(
            nickname=nickname,
            email=email,
            password=password,
            payPassword=payPassword
        )
        db.session.add(user)
        db.session.commit()

        flash('银行用户注册成功，请登录', 'success')
        return redirect(url_for('web.auth.bank_login'))
    return render_template('auth/bank_register.html')



@auth_bp.route('/bank/login', methods=['GET', 'POST'])
def bank_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = request.form.get('remember') == 'on'

        if not email or not password:
            flash('邮箱和密码是必需的', 'error')
            return redirect(url_for('web.auth.bank_login'))

        # 验证邮箱格式是否有效
        if not is_valid_email(email):
            flash('无效的邮箱格式', 'error')
            return redirect(url_for('web.auth.bank_login'))

        user = BankUser.query.filter_by(email=email).first()
        if user is None:
            flash('用户不存在', 'error')
            return redirect(url_for('web.auth.bank_login'))

        if not user.verify_password(password):
            logger.info(f"银行用户 {user.nickname} 密码输入错误")
            flash('密码不正确', 'error')
            return redirect(url_for('web.auth.bank_login'))

        access_token = user.generate_jwt(user, remember)
        logger.info(f"银行用户 {user.nickname} 登录成功")
        response = make_response(redirect(url_for('web.bank.dashboard')))
        response.set_cookie(
            'access_token',
            access_token,
            httponly=True,
            secure=False,  # 如果使用 HTTPS，请设为 True
            samesite='Lax',
            max_age=60 * 60 * 24 * 7 if remember else 60 * 60 * 24
        )
        csrf_token = create_access_token(identity=user.UserId)  # 生成 CSRF token
        response.set_cookie(
            'csrftoken',
            csrf_token,
            httponly=False,  # CSRF token 需要允许前端读取
            secure=True,  # 如果使用 HTTPS，请设为 True
            samesite='Lax',
            max_age=60 * 60 * 24 * 7 if remember else 60 * 60 * 24
        )
        flash('登录成功', 'success')
        return response
    return render_template('auth/bank_login.html')


@auth_bp.route("/bank/activate", methods=['GET', 'POST'])
@jwt_required()
def bank_activate():
    user_id = get_jwt_identity()
    user = BankUser.query.get(user_id)

    if user.isExamined:
        flash('您的账户已激活，无需再次激活。', 'info')
        return redirect(url_for('web.bank.dashboard'))

    if request.method == 'POST':
        # 处理表单提交，在 confirm_activate 函数中处理
        return redirect(url_for('web.auth.confirm_activate'))

    # 发送激活邮件
    captcha_manager = CaptchaManager(user)
    captcha_manager.generate_captcha()
    captcha_manager.send_captcha_email("激活您的账户验证码", 'email/activate_account.html')
    flash('激活验证码已发送，请查收您的邮箱。', 'info')
    return render_template('auth/activate_account.html')

@auth_bp.route("/bank/activate/confirm", methods=['POST'])
@jwt_required()
def confirm_activate():
    user_id = get_jwt_identity()
    user = BankUser.query.get(user_id)

    if user.isExamined:
        flash('您的账户已激活，无需再次激活。', 'info')
        return redirect(url_for('web.bank.dashboard'))

    captcha = request.form.get('captcha')

    if not captcha:
        flash('请输入验证码。', 'error')
        return redirect(url_for('web.auth.bank_activate'))

    captcha_manager = CaptchaManager(user)
    if captcha_manager.verify_captcha(captcha):
        user.isExamined = True
        db.session.commit()
        flash('账户激活成功！', 'success')
        return redirect(url_for('web.bank.dashboard'))
    else:
        flash('验证码错误或已过期，请重新获取。', 'error')
        return redirect(url_for('web.auth.bank_activate'))



@auth_bp.route("/bank/reset/password", methods=['GET', 'POST'])
def bank_reset_password_request():
    if request.method == 'POST':
        email = request.form.get('email')

        if not email:
            flash('请输入有效的邮箱地址', 'error')
            return redirect(url_for('web.auth.bank_reset_password_request'))

        # 验证邮箱格式是否有效
        if not is_valid_email(email):
            flash('无效的邮箱格式', 'error')
            return redirect(url_for('web.auth.bank_reset_password_request'))

        user = BankUser.query.filter_by(email=email).first()
        if user:
            captcha_manager = CaptchaManager(user)
            captcha_manager.generate_captcha()
            captcha_manager.send_captcha_email("重置您的密码验证码", 'email/reset_password.html')
            flash('重置密码验证码已发送，请查收', 'info')
            return redirect(url_for('web.auth.bank_reset_password', email=email))
        else:
            flash('用户不存在', 'error')
            return redirect(url_for('web.auth.bank_reset_password_request'))
    return render_template('auth/bank_reset_password_request.html')



@auth_bp.route("/bank/reset/password/confirm", methods=['GET', 'POST'])
def bank_reset_password():
    email = request.args.get('email')
    if request.method == 'POST':
        email = request.form.get('email')
        captcha = request.form.get('captcha')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not all([email, captcha, new_password, confirm_password]):
            flash('所有字段都是必需的', 'error')
            return redirect(url_for('web.auth.bank_reset_password', email=email))

        # 验证邮箱格式是否有效
        if not is_valid_email(email):
            flash('无效的邮箱格式', 'error')
            return redirect(url_for('web.auth.bank_reset_password', email=email))

        if new_password != confirm_password:
            flash('两次输入的密码不一致', 'error')
            return redirect(url_for('web.auth.bank_reset_password', email=email))

        user = BankUser.query.filter_by(email=email).first()
        if not user:
            flash('用户不存在', 'error')
            return redirect(url_for('web.auth.bank_reset_password_request'))

        captcha_manager = CaptchaManager(user)
        if captcha_manager.verify_captcha(captcha):
            if user.verify_password(new_password):
                flash('新密码不能与原密码相同', 'error')
                return redirect(url_for('web.auth.bank_reset_password', email=email))
            user.password = new_password
            db.session.commit()
            flash('密码重置成功，请登录', 'success')
            return redirect(url_for('web.auth.bank_login'))
        else:
            flash('验证码错误或已过期', 'error')
            return redirect(url_for('web.auth.bank_reset_password', email=email))
    return render_template('auth/bank_reset_password.html', email=email)



@auth_bp.route('/bank/logout')
@login_required
def logout():
    logout_user()
    flash('您已成功退出登录', 'info')
    return redirect(url_for('web.auth.bank_login'))


@auth_bp.route("/shop/reset/password", methods=['POST'])
# @swag_from('../docs/shop_reset_password_request.yml')
def shop_reset_password_request():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({"msg": "请输入有效的邮箱地址"}), 400

    # 验证邮箱格式是否有效
    if not is_valid_email(email):
        return jsonify({'msg': '无效的邮箱格式'}), 400

    user = ShopUser.query.filter_by(email=email).first()
    if user:
        captcha_manager = CaptchaManager(user)
        captcha_manager.generate_captcha()
        captcha_manager.send_captcha_email("重置您的密码验证码", 'email/reset_password.html')
        return jsonify({"msg": "重置密码验证码已发送，请查收"}), 200
    return jsonify({"msg": "用户不存在"}), 400


@auth_bp.route("/shop/reset/password", methods=['PUT'])
# @swag_from('../docs/shop_reset_password.yml')
def shop_reset_password():
    data = request.get_json()
    email = data.get('email')
    captcha = data.get('captcha')
    new_password = data.get('new_password')
    confirm_password = data.get('confirm_password')

    if not all([email, captcha, new_password, confirm_password]):
        return jsonify({"msg": "所有字段都是必需的"}), 400

    # 验证邮箱格式是否有效
    if not is_valid_email(email):
        return jsonify({'msg': '无效的邮箱格式'}), 400

    if new_password != confirm_password:
        return jsonify({"msg": "两次输入的密码不一致"}), 400

    user = ShopUser.query.filter_by(email=email).first()
    if not user:
        return jsonify({"msg": "用户不存在"}), 400

    captcha_manager = CaptchaManager(user)
    if captcha_manager.verify_captcha(captcha):
        if user.verify_password(new_password):
            return jsonify({"msg": "新密码不能与原密码相同"}), 400
        user.password = new_password
        db.session.commit()
        return jsonify({"msg": "密码重置成功"}), 200
    else:
        return jsonify({"msg": "验证码错误或已过期"}), 400


@auth_bp.route("/register", methods=['POST'])
def shop_register():
    data = request.get_json()
    nickname = data.get('nickname')
    email = data.get('email')
    password = data.get('password')

    if not all([nickname, email, password]):
        return jsonify({'msg': '所有字段都是必需的'}), 400

    # 验证邮箱格式是否有效
    if not is_valid_email(email):
        return jsonify({'msg': '无效的邮箱格式'}), 400

    existing_user = ShopUser.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({'msg': '该邮箱已被注册'}), 400

    shop_user = ShopUser()
    shop_user.set_attrs(data)
    db.session.add(shop_user)
    db.session.commit()
    logger.info(f"用户{shop_user.nickname}注册成功")
    return jsonify({'msg': '注册成功'}), 201


@auth_bp.route('/login', methods=['POST'])
def shop_login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    remember = data.get('remember', False)

    if not email or not password:
        return jsonify({"msg": "邮箱和密码是必需的"}), 400

    # 验证邮箱格式是否有效
    if not is_valid_email(email):
        return jsonify({'msg': '无效的邮箱格式'}), 400

    user = ShopUser.query.filter_by(email=email).first()
    if user is None:
        return jsonify({"msg": "用户不存在"}), 404

    if not user.verify_password(password):
        logger.info(f"用户{user.nickname}密码输入错误")
        return jsonify({"msg": "密码不正确"}), 401

    access_token = user.generate_jwt(user, remember)
    logger.info(f"用户{user.nickname}登录成功")
    response = jsonify({"msg": "登录成功", "access_token": access_token})
    response.set_cookie(
        'access_token',
        access_token,
        httponly=True,
        secure=True,
        samesite='Lax',
        max_age=60 * 60 * 24 * 7 if remember else 60 * 60 * 24
    )
    return response, 200
