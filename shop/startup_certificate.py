# encoding=utf-8
__author__ = 'Zephyr369'
# encoding=utf-8

import os
import requests
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.primitives import serialization

# CA API 地址
CA_URL = 'https://127.0.0.1:443/api'
CA_CERT_PATH = os.path.join(os.getcwd(), 'ca_cert.pem')  # 动态获取 CA 证书路径


def is_certificate_valid(cert_path):
    """验证本地证书是否存在且未过期"""
    if not os.path.exists(cert_path):
        print(f"证书文件不存在: {cert_path}")
        return False

    try:
        with open(cert_path, 'rb') as f:
            cert_data = f.read()
        cert = x509.load_pem_x509_certificate(cert_data)
        # 检查是否过期
        if cert.not_valid_after < datetime.utcnow():
            print("证书已过期")
            return False
        print("证书有效")
        return True
    except Exception as e:
        print(f"证书验证失败: {e}")
        return False


def request_new_certificate(common_name):
    """向 CA 请求新证书"""
    url = f"{CA_URL}/issue_certificate"
    data = {'common_name': common_name}

    if not os.path.exists(CA_CERT_PATH):
        print(f"CA 根证书不存在: {CA_CERT_PATH}")
        exit(1)

    try:
        response = requests.post(url, json=data, verify=False)
        response.raise_for_status()  # 检查 HTTP 响应状态
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
    except requests.exceptions.RequestException as e:
        print(f"请求证书失败: {e}")
        return None, None


def initialize_certificate(common_name):
    """初始化证书（验证或申请新证书）"""
    cert_dir = os.path.join(os.getcwd(), 'certs')
    os.makedirs(cert_dir, exist_ok=True)  # 确保目录存在

    cert_path = os.path.join(cert_dir, f"{common_name}_cert.pem")
    key_path = os.path.join(cert_dir, f"{common_name}_key.pem")

    if not is_certificate_valid(cert_path):
        print(f"证书无效或不存在，为 {common_name} 申请新证书...")
        cert_path, key_path = request_new_certificate(common_name)

    if not cert_path or not key_path:
        print("无法初始化证书，程序退出")
        exit(1)

    return cert_path, key_path
