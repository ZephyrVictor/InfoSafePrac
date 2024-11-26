# encoding=utf-8
__author__ = 'Zephyr369'

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import CertificateBuilder, NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import datetime
import os
from app.models.certificate import Certificate
from app import db


# 加载 CA 私钥和证书
def load_ca():
    with open('../ca_key.pem', 'rb') as f:
        ca_private_key = serialization.load_pem_private_key(f.read(), password=None)
    with open('../ca_cert.pem', 'rb') as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    return ca_private_key, ca_cert


def issue_certificate(common_name):
    ca_private_key, ca_cert = load_ca()

    # 生成用户私钥
    user_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # 创建证书
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    cert_builder = CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        user_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow() - datetime.timedelta(days=1)
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    )

    cert = cert_builder.sign(private_key=ca_private_key, algorithm=hashes.SHA256())

    # 序列化证书和私钥
    certificate_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    private_key_pem = user_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()
    ).decode('utf-8')

    # 保存到数据库
    new_cert = Certificate(
        common_name=common_name,
        certificate_pem=certificate_pem,
        private_key_pem=private_key_pem,
        expiry_date=cert.not_valid_after
    )
    db.session.add(new_cert)
    db.session.commit()

    return certificate_pem, private_key_pem


def revoke_certificate(common_name):
    cert = Certificate.query.filter_by(common_name=common_name).first()
    if cert:
        cert.revoked = True
        db.session.commit()
        return True
    else:
        return False


def is_certificate_revoked(common_name):
    cert = Certificate.query.filter_by(common_name=common_name).first()
    if cert:
        return cert.revoked
    else:
        return False
