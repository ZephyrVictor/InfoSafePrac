# encoding=utf-8
__author__ = 'Zephyr369'

from datetime import datetime, timedelta

from flask import render_template, request, redirect, url_for, flash, jsonify
from app.web import web_bp
from app.models.certificate import Certificate
from app.utils.ca_manager import issue_certificate, revoke_certificate, is_certificate_revoked
from app import db


@web_bp.route('/', methods=['GET'])
def index():
    return render_template('index.html')


@web_bp.route('/certificates', methods=['GET'])
def certificates():
    certs = Certificate.query.all()
    return render_template('certificates.html', certificates=certs)


@web_bp.route('/issue_certificate', methods=['GET', 'POST'])
def issue_certificate_view():
    if request.method == 'POST':
        common_name = request.form.get('common_name')
        if not common_name:
            flash('Common Name is required.', 'danger')
            return redirect(url_for('web.issue_certificate_view'))

        existing_cert = Certificate.query.filter_by(common_name=common_name).first()
        if existing_cert:
            flash('Certificate already exists.', 'warning')
            return redirect(url_for('web.certificates'))

        cert_pem, key_pem = issue_certificate(common_name)
        flash('Certificate issued successfully.', 'success')
        return render_template('issue_certificate.html', certificate=cert_pem, private_key=key_pem)

    return render_template('issue_certificate.html')


@web_bp.route('/revoke_certificate/<int:cert_id>', methods=['POST'])
def revoke_certificate_view(cert_id):
    cert = Certificate.query.get_or_404(cert_id)
    revoke_certificate(cert.common_name)
    flash('Certificate revoked successfully.', 'success')
    return redirect(url_for('web.certificates'))


# API 接口，用于银行和商城应用请求证书
@web_bp.route('/api/issue_certificate', methods=['POST'])
def api_issue_certificate():
    data = request.get_json()
    common_name = data.get('common_name')
    if not common_name:
        return jsonify({'error': 'common_name is required'}), 400

    # 检查是否已有未吊销且未过期的证书
    existing_cert = Certificate.query.filter_by(common_name=common_name, revoked=False).first()
    if existing_cert:
        # 检查证书是否过期
        if existing_cert.expiry_date > datetime.utcnow():
            return jsonify({
                'certificate': existing_cert.certificate_pem,
                'private_key': existing_cert.private_key_pem
            }), 200
        else:
            # 证书已过期，更新为吊销状态
            existing_cert.revoked = True
            db.session.commit()

    # 颁发新证书
    cert_pem, key_pem = issue_certificate(common_name)
    new_cert = Certificate(
        common_name=common_name,
        certificate_pem=cert_pem,
        private_key_pem=key_pem,
        expiry_date=datetime.utcnow() + timedelta(days=365),  # 设置证书有效期为1年
        revoked=False
    )
    db.session.add(new_cert)
    db.session.commit()

    return jsonify({
        'certificate': cert_pem,
        'private_key': key_pem
    }), 200


# API 接口，用于验证证书是否被吊销
@web_bp.route('/api/verify_certificate', methods=['POST'])
def api_verify_certificate():
    data = request.get_json()
    common_name = data.get('common_name')
    if not common_name:
        return jsonify({'error': 'common_name is required'}), 400

    revoked = is_certificate_revoked(common_name)
    return jsonify({'revoked': revoked}), 200



