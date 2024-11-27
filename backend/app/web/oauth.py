# encoding=utf-8
__author__ = 'Zephyr369'

from datetime import datetime, timedelta

# app/web/oauth.py

from flask import Blueprint, request, redirect, url_for, render_template, session, flash, jsonify
from flask_login import current_user, login_required
from werkzeug.security import gen_salt

from app.models.OAuthClient import OAuthClient
from app.models.OAuthGrant import OAuthGrant
from app.models.BankUser import BankUser
from app.models.OAuthToken import OAuthToken
from app.models.base import db
import random
import string
from urllib.parse import urlencode

oauth_bp = Blueprint('oauth', __name__)


@oauth_bp.route('/oauth/authorize', methods=['GET', 'POST'])
@login_required
def authorize():
    client_id = request.args.get('client_id')
    redirect_uri = request.args.get('redirect_uri')
    state = request.args.get('state')
    scope = request.args.get('scope', '')

    client = OAuthClient.query.filter_by(client_id=client_id).first()
    if not client:
        flash('无效的客户端 ID', 'error')
        return redirect(url_for('web.bank.index'))

    if redirect_uri not in client.redirect_uris.split(','):
        flash('无效的重定向 URI', 'error')
        return redirect(url_for('web.bank.index'))

    if request.method == 'GET':
        # 显示授权页面
        return render_template('oauth/authorize.html', client=client, scope=scope)
    elif request.method == 'POST':
        if 'confirm' in request.form:
            # 用户同意授权，生成授权码
            code = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
            grant = OAuthGrant(
                user_id=current_user.UserId,
                client_id=client.client_id,
                code=code,
                redirect_uri=redirect_uri,
                scopes=scope,
                expires=datetime.utcnow() + timedelta(minutes=10)
            )
            db.session.add(grant)
            db.session.commit()

            # 重定向回客户端，附带授权码和状态参数
            params = {
                'code': code,
                'state': state
            }
            redirect_url = f"{redirect_uri}?{urlencode(params)}"
            return redirect(redirect_url)
        else:
            # 用户拒绝授权
            params = {
                'error': 'access_denied',
                'state': state
            }
            redirect_url = f"{redirect_uri}?{urlencode(params)}"
            return redirect(redirect_url)


@oauth_bp.route('/oauth/token', methods=['POST'])
def issue_token():
    grant_type = request.form.get('grant_type')
    if grant_type != 'authorization_code':
        return jsonify({'error': 'unsupported_grant_type'}), 400

    code = request.form.get('code')
    redirect_uri = request.form.get('redirect_uri')
    client_id = request.form.get('client_id')
    client_secret = request.form.get('client_secret')

    client = OAuthClient.query.filter_by(client_id=client_id).first()
    if not client or client.client_secret != client_secret:
        return jsonify({'error': 'invalid_client'}), 401

    grant = OAuthGrant.query.filter_by(code=code, client_id=client_id).first()
    if not grant or grant.redirect_uri != redirect_uri:
        return jsonify({'error': 'invalid_grant'}), 400

    if datetime.utcnow() > grant.expires:
        return jsonify({'error': 'expired_grant'}), 400

    # 生成访问令牌
    access_token = gen_salt(64)
    token = OAuthToken(
        client_id=client_id,
        user_id=grant.user_id,
        access_token=access_token,
        expires=datetime.utcnow() + timedelta(hours=1),
        scopes=grant.scopes
    )
    db.session.add(token)
    db.session.delete(grant)  # 删除授权码，防止重复使用
    db.session.commit()

    return jsonify({
        'access_token': access_token,
        'token_type': 'Bearer',
        'expires_in': 3600,
        'scope': token.scopes
    }), 200
