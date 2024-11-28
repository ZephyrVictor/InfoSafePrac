# encoding=utf-8
__author__ = 'Zephyr369'

import base64

import requests
from Crypto.Random import get_random_bytes
from flasgger import swag_from
from flask import Blueprint, request, jsonify, url_for, flash, render_template, session, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity, verify_jwt_in_request, get_jwt
from werkzeug.urls import url_encode, url_decode
from werkzeug.utils import redirect

from app.models.BankCard import BankCard
from app.libs.email import send_mail
from app import db
from ..libs.captcha import CaptchaManager
from ..models.BankUser import BankUser
from ..models.Transaction import Transaction
from ..utils import Logger
from Crypto.Cipher import AES
from urllib.parse import quote, unquote

bank_bp = Blueprint('bank', __name__)


# 逻辑：
# 用户注册后，要经过管理员审核才有资格开卡
# 开卡的时候，会先生成一个银行卡，然后交到数据库里
# 用户经过验证码验证后银行卡才会激活 否则就是废卡

# 申请一张银行卡
@bank_bp.route('/apply_bank_card', methods=['GET', 'POST'])
@jwt_required()
def apply_bank_card():
    if request.method == "POST":
        user_id = get_jwt_identity()
        user = BankUser.query.get(user_id)

        if not user.isExamined:
            flash('用户未经过激活，无法申请银行卡', 'error')
            return redirect(url_for('web.auth.bank_activate'))

        new_card = BankCard(user_id=user.UserId)
        db.session.add(new_card)
        db.session.commit()

        captcha_manager = CaptchaManager(user)
        captcha_manager.generate_captcha()
        captcha_manager.send_captcha_email('绑定银行卡验证码', 'email/bind_bank_card.html')
        flash('验证码已发送到您的邮箱，请查收', 'info')

        aes_key = current_app.config['aes_key']
        card_number = new_card.card_number.encode('utf-8')
        iv = get_random_bytes(AES.block_size)

        # 加密
        aes = AES.new(aes_key, AES.MODE_OFB, iv)
        enc_card_number = aes.encrypt(card_number)

        # 合并 IV 和密文，编码后用 URL 传递
        enc_card_number_base64 = quote(base64.b64encode(iv + enc_card_number).decode('utf-8'))

        # 返回前端
        return redirect(url_for('web.bank.confirm_bank_card', card_number=enc_card_number_base64))
    return render_template('bank/apply_bank_card.html')


@bank_bp.route('/bank/confirm_bank_card/<card_number>', methods=['GET', 'POST'])
@jwt_required()
def confirm_bank_card(card_number):
    user_id = get_jwt_identity()
    user = BankUser.query.get(user_id)
    try:
        # 解码 URL 中的 Base64 数据
        data = base64.b64decode(unquote(card_number))
    except (ValueError, TypeError) as e:
        flash('银行卡数据无效', 'error')
        return redirect(url_for('web.bank.dashboard'))

        # 拆分 IV 和密文
    if len(data) < AES.block_size:
        flash('数据格式不正确', 'error')
        return redirect(url_for('web.bank.dashboard'))

    iv = data[:AES.block_size]
    enc_card_number = data[AES.block_size:]
    aes_key = current_app.config['aes_key']

    # 解密
    aes = AES.new(aes_key, AES.MODE_OFB, iv)
    dec_card_number = aes.decrypt(enc_card_number).decode('utf-8')
    bank_card = BankCard.query.filter_by(card_number=dec_card_number, user_id=user_id).first()
    if not bank_card:
        flash('银行卡不存在', 'error')
        return redirect(url_for('web.bank.dashboard'))

    if request.method == 'POST':
        captcha = request.form.get('captcha')

        captcha_manager = CaptchaManager(user)
        if not captcha_manager.verify_captcha(captcha):
            # 验证码错误或过期，删除未激活的银行卡
            db.session.delete(bank_card)
            db.session.commit()
            flash('验证码错误或已过期，银行卡已删除，请重新申请', 'error')
            return redirect(url_for('web.bank.dashboard'))

        bank_card.is_active = True
        db.session.commit()
        flash('银行卡激活成功', 'success')
        return redirect(url_for('web.bank.dashboard'))

    return render_template('bank/confirm_bank_card.html', card_number=dec_card_number)


@bank_bp.route('/deposit/<int:card_id>', methods=['GET', 'POST'])
@jwt_required()
def deposit(card_id):
    user_id = get_jwt_identity()
    bank_card = BankCard.query.filter_by(CardId=card_id, user_id=user_id, is_active=True).first()
    user = BankUser.query.filter_by(UserId=user_id).first()

    if not bank_card:
        flash('银行卡不存在或未激活', 'error')
        return redirect(url_for('web.bank.dashboard'))

    if request.method == 'POST':
        amount = float(request.form.get('amount'))

        if amount <= 0:
            flash('充值金额必须大于零', 'error')
            return redirect(url_for('web.bank.deposit', card_id=card_id))

        # 发送验证码
        captcha_manager = CaptchaManager(user, bank_card)
        captcha_manager.generate_captcha()
        captcha_manager.send_captcha_email('充值验证码', 'email/captcha.html')
        session['deposit_amount'] = amount
        session['deposit_card_id'] = card_id

        flash('验证码已发送到您的邮箱，请查收', 'info')
        return redirect(url_for('web.bank.confirm_deposit', card_id=card_id))

    return render_template('bank/deposit.html', card=bank_card)


@bank_bp.route('/confirm_deposit/<int:card_id>', methods=['GET', 'POST'])
@jwt_required()
def confirm_deposit(card_id):
    user_id = get_jwt_identity()
    bank_card = BankCard.query.filter_by(CardId=card_id, user_id=user_id, is_active=True).first()
    user = BankUser.query.filter_by(UserId=user_id).first()

    if not bank_card:
        flash('银行卡不存在或未激活', 'error')
        return redirect(url_for('web.bank.dashboard'))

    if request.method == 'POST':
        captcha = request.form.get('captcha')
        amount = session.get('deposit_amount')

        if not amount or not session.get('deposit_card_id') == card_id:
            flash('非法操作，请重新开始充值流程', 'error')
            return redirect(url_for('web.bank.deposit', card_id=card_id))

        # 验证验证码
        captcha_manager = CaptchaManager(user, bank_card)
        if not captcha_manager.verify_captcha(captcha):
            flash('验证码错误或已过期', 'error')
            return redirect(url_for('web.bank.confirm_deposit', card_id=card_id))

        # 完成充值操作
        if bank_card.deposit(amount):
            flash('充值成功', 'success')
        else:
            flash('充值失败', 'error')

        # 清除 session 数据
        session.pop('deposit_amount', None)
        session.pop('deposit_card_id', None)
        return redirect(url_for('web.bank.dashboard'))

    return render_template('bank/confirm_deposit.html', card=bank_card)


@bank_bp.route('/withdraw', methods=['POST'])
@jwt_required()
def withdraw():
    user_id = get_jwt_identity()
    data = request.get_json()
    card_id = data.get('card_id')
    amount = data.get('amount')
    captcha = data.get('captcha')

    bank_card = BankCard.query.filter_by(CardId=card_id, user_id=user_id, is_active=True).first()
    if not bank_card:
        return jsonify({'msg': '银行卡不存在或未激活'}), 404

    if not bank_card.verify_captcha(captcha):
        return jsonify({'msg': '验证码错误或已过期'}), 400

    if bank_card.withdraw(amount):
        return jsonify({'msg': '取款成功', 'balance': bank_card.balance}), 200
    else:
        return jsonify({'msg': '取款失败，余额不足'}), 400


@bank_bp.route("/deposit_request", methods=["POST"])
@jwt_required()
def deposit_request():
    """
    用户发起充值请求
    """
    user_id = get_jwt_identity()
    data = request.get_json()
    card_id = data.get('card_id')
    amount = data.get('amount')

    # 校验请求数据
    if not amount or not card_id:
        flash('非法操作', 'error')
        return redirect(url_for('web.bank.dashboard'))

    # 查找对应的银行卡
    bank_card = BankCard.query.filter_by(CardId=card_id, user_id=user_id, is_active=True).first()
    if not bank_card:
        flash('银行卡不存在或未激活', 'error')
        return redirect(url_for('web.bank.dashboard'))

    # 生成验证码并发送到用户邮箱
    captcha_manager = CaptchaManager(user=bank_card)
    captcha_manager.generate_captcha()
    captcha_manager.send_captcha_email('充值验证码', 'email/captcha.html')

    # 将充值信息暂存到 session 中
    session['deposit_amount'] = float(amount)
    session['deposit_card_id'] = card_id
    flash('验证码已发送到您的邮箱，请查收', 'info')

    # 跳转到验证码确认页面
    return redirect(url_for('web.bank.confirm_deposit'))


# 主界面
@bank_bp.route("/dashboard")
@jwt_required()
def dashboard():
    user_id = get_jwt_identity()
    print(f"当前登录用户ID: {user_id}")  # 打印用户ID
    user = BankUser.query.filter_by(UserId=user_id).first()
    bank_cards = BankCard.query.filter_by(user_id=user_id, is_active=True).all()
    return render_template("bank/dashboard.html", current_user=user, bank_cards=bank_cards)


@bank_bp.route('/transfer', methods=['GET', 'POST'])
@jwt_required()
def transfer():
    user_id = get_jwt_identity()  # 获取当前用户ID
    user = BankUser.query.get(user_id)  # 获取当前用户对象
    if request.method == 'POST':
        recipient_card_number = request.form['recipient_card_number']  # 收款卡号
        sender_card_number = request.form['sender_card_number']  # 付款卡号
        amount = float(request.form['amount'])  # 转账金额
        pay_password = request.form['pay_password']  # 支付密码
        captcha = request.form['captcha']  # 验证码

        if not user.verify_payPassword(pay_password):
            flash('支付密码错误', 'error')
            return redirect(url_for('web.bank.transfer'))

        captcha_manager = CaptchaManager(user)
        if not captcha_manager.verify_captcha(captcha):
            flash('验证码错误或已过期', 'error')
            return redirect(url_for('web.bank.transfer'))

        recipient_card = BankCard.query.filter_by(card_number=recipient_card_number).first()
        if not recipient_card:
            flash('收款卡号不存在', 'error')
            return redirect(url_for('web.bank.transfer'))

        sender_card = BankCard.query.filter_by(user_id=user.UserId, card_number=sender_card_number).first()
        if sender_card.balance < amount:
            flash('余额不足', 'error')
            return redirect(url_for('web.bank.transfer'))

        if sender_card.withdraw(amount):
            recipient_card.deposit(amount)
            db.session.commit()

            transaction = Transaction(sender_id=user.UserId, recipient_id=recipient_card.user_id,
                                      amount=amount, transaction_type='TRANSFER', status='SUCCESS')
            db.session.add(transaction)
            db.session.commit()

            flash('转账成功', 'success')
            return redirect(url_for('web.bank.transaction_history'))

    return render_template('bank/transfer.html', user=user)


@bank_bp.route('/send_captcha', methods=['POST'])
@jwt_required()
def send_captcha():
    user_id = get_jwt_identity()
    user = BankUser.query.get(user_id)

    captcha_manager = CaptchaManager(user)
    captcha_manager.generate_captcha()
    captcha_manager.send_captcha_email('转账验证码', 'email/transfer_captcha.html')

    flash('验证码已发送到您的邮箱，请查收', 'info')
    return redirect(url_for('web.bank.transfer'))


@bank_bp.route('/verify_captcha', methods=['POST'])
@jwt_required()
def verify_captcha():
    user_id = get_jwt_identity()
    user = BankUser.query.get(user_id)

    captcha = request.form['captcha']
    captcha_manager = CaptchaManager(user)

    if captcha_manager.verify_captcha(captcha):
        flash('验证码验证成功', 'success')
    else:
        flash('验证码错误或已过期', 'error')

    return redirect(url_for('web.bank.transfer'))


@bank_bp.route('/transaction_history', methods=['GET'])
@jwt_required()
def transaction_history():
    user_id = get_jwt_identity()
    transactions = Transaction.query.filter(
        (Transaction.sender_id == user_id) | (Transaction.recipient_id == user_id)
    ).order_by(Transaction.timestamp.desc()).all()

    return render_template('bank/transaction_history.html', transactions=transactions)


@bank_bp.route('/pay', methods=['POST'])
@jwt_required()
def pay():
    # 获取当前银行用户
    user_id = get_jwt_identity()
    user = BankUser.query.get(user_id)

    # 获取从商店端传递的数据
    order_id = request.form['order_id']
    buyer_id = request.form['buyer_id']
    seller_id = request.form['seller_id']
    amount = float(request.form['amount'])  # 支付金额

    # 校验支付密码
    pay_password = request.form['pay_password']
    if not user.verify_payPassword(pay_password):
        flash('支付密码错误', 'error')
        return redirect(url_for('web.bank.transfer'))

    # 发送验证码
    captcha_manager = CaptchaManager(user)
    captcha_manager.generate_captcha()
    captcha_manager.send_captcha_email('支付验证码', 'email/pay_captcha.html')

    flash('验证码已发送到您的邮箱，请查收', 'info')
    return render_template('bank/verify_captcha.html', order_id=order_id, buyer_id=buyer_id, seller_id=seller_id,
                           amount=amount)
@bank_bp.route('/verify_order_captcha', methods=['POST'])
@jwt_required()
def verify_order_captcha():
    user_id = get_jwt_identity()
    user = BankUser.query.get(user_id)

    captcha = request.form['captcha']
    order_id = request.form['order_id']
    buyer_id = request.form['buyer_id']
    seller_id = request.form['seller_id']
    amount = float(request.form['amount'])

    # 验证验证码
    captcha_manager = CaptchaManager(user)
    if captcha_manager.verify_captcha(captcha):
        # 获取付款银行卡
        sender_card = BankCard.query.filter_by(user_id=user.UserId).first()  # 假设用户有一张默认卡
        if sender_card.balance < amount:
            flash('余额不足', 'error')
            return redirect(url_for('web.bank.transfer'))

        # 获取卖家银行用户ID
        recipient_card = BankCard.query.filter_by(user_id=seller_id).first()

        # 执行转账
        if sender_card.withdraw(amount):
            recipient_card.deposit(amount)
            db.session.commit()

            # 记录交易
            transaction = Transaction(
                sender_id=user.UserId,
                recipient_id=recipient_card.user_id,
                amount=amount,
                transaction_type=f"Order-{order_id}",  # 记录订单ID
                status='SUCCESS'
            )
            db.session.add(transaction)
            db.session.commit()

            flash('支付成功', 'success')
            return redirect(url_for('web.bank.transaction_history'))

    else:
        flash('验证码错误或已过期', 'error')

    return redirect(url_for('web.bank.transfer'))