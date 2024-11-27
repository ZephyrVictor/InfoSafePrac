# encoding=utf-8
__author__ = 'Zephyr369'
# encoding=utf-8

import os
import requests
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# CA API 地址
CA_URL = 'https://127.0.0.1:443/api'
CA_CERT_PATH = os.path.join(os.getcwd(), 'ca_cert.pem')  # CA 根证书路径
CA_VERIFY_URL = f"{CA_URL}/verify_certificate"


# 证书验证函数
def is_certificate_valid(cert_path, common_name):
    """
    验证证书是否有效且匹配给定的 common_name。
    """
    if not os.path.exists(cert_path):
        return False

    try:
        with open(cert_path, 'rb') as f:
            cert_data = f.read()
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())

        # 检查证书是否过期
        if cert.not_valid_after < datetime.utcnow():
            print("证书已过期")
            return False

        # 检查证书的 common_name
        subject = cert.subject
        cert_common_name = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        if cert_common_name != common_name:
            print(f"证书的 Common Name 不匹配: {cert_common_name} != {common_name}")
            return False

        return True
    except Exception as e:
        print(f"证书验证失败: {e}")
        return False


# 验证证书是否被吊销
def is_certificate_revoked(common_name):
    try:
        response = requests.post(CA_VERIFY_URL, json={'common_name': common_name}, verify=False)
        return response.json().get('revoked', False)
    except Exception as e:
        print(f"验证证书吊销状态失败: {e}")
        return True


def request_new_certificate(common_name):
    """向 CA 请求新证书"""
    url = f"{CA_URL}/issue_certificate"
    data = {'common_name': common_name}

    try:
        response = requests.post(url, json=data, verify=False)
        response.raise_for_status()
        cert_data = response.json()
        cert = cert_data['certificate']
        private_key = cert_data['private_key']

        cert_dir = 'certs'
        os.makedirs(cert_dir, exist_ok=True)
        cert_path = os.path.join(cert_dir, f"{common_name}_cert.pem")
        key_path = os.path.join(cert_dir, f"{common_name}_key.pem")

        with open(cert_path, 'w') as f:
            f.write(cert)
        with open(key_path, 'w') as f:
            f.write(private_key)

        print(f"新证书和私钥已保存到 {cert_path} 和 {key_path}")
        return cert_path, key_path
    except Exception as e:
        print(f"请求证书失败: {e}")
        return None, None


def ensure_valid_certificate(common_name):
    """
    确保本地证书有效。如果无效或被吊销，则重新申请证书。
    """
    cert_dir = os.path.join(os.getcwd(), 'certs')
    cert_path = os.path.join(cert_dir, f"{common_name}_cert.pem")
    key_path = os.path.join(cert_dir, f"{common_name}_key.pem")

    if os.path.exists(cert_path) and is_certificate_valid(cert_path,common_name):
        if not is_certificate_revoked(common_name):
            print(f"证书有效且未被吊销: {common_name}")
            return cert_path, key_path
        else:
            print(f"证书已被吊销: {common_name}")
    else:
        print(f"证书无效或已过期: {common_name}")

    # 重新申请证书
    print(f"为 {common_name} 重新申请证书...")
    return request_new_certificate(common_name)
