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
CA_VERIFY_URL = f"{CA_URL}/verify_certificate"  # 验证证书吊销状态接口


def is_certificate_valid(cert_path):
    """
    验证本地证书是否存在且未过期。

    参数:
    - cert_path: 本地证书路径

    返回:
    - bool: True 表示证书有效，False 表示证书无效。
    """
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


def is_certificate_valid_and_revoked(cert_path, common_name):
    """
    验证本地证书是否有效且未被吊销。

    参数:
    - cert_path: 本地证书路径
    - common_name: 证书的通用名称 (Common Name)

    返回:
    - bool: True 表示证书有效且未被吊销，False 表示证书无效或已被吊销。
    """
    # 本地验证证书是否存在且未过期
    if not is_certificate_valid(cert_path):
        return False

    # 请求 CA 服务器检查证书是否被吊销
    try:
        response = requests.post(CA_VERIFY_URL, json={'common_name': common_name}, verify=CA_CERT_PATH)
        if response.status_code == 200:
            revoked = response.json().get('revoked', False)
            if revoked:
                print(f"证书已被吊销: {common_name}")
                return False
            print(f"证书未被吊销: {common_name}")
            return True
        else:
            print(f"CA 服务器返回错误: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        print(f"请求 CA 服务器失败: {e}")
        return False


def request_new_certificate(common_name):
    """
    向 CA 请求新证书。

    参数:
    - common_name: 证书的通用名称 (Common Name)

    返回:
    - (cert_path, key_path): 新证书和私钥的路径
    """
    url = f"{CA_URL}/issue_certificate"
    data = {'common_name': common_name}

    if not os.path.exists(CA_CERT_PATH):
        print(f"CA 根证书不存在: {CA_CERT_PATH}")
        exit(1)

    try:
        response = requests.post(url, json=data, verify=False)  # 如果 CA 使用自签名证书，设置 verify=False
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


def ensure_valid_certificate(cert_path, key_path, common_name):
    """
    确保本地证书有效。如果无效或被吊销，则重新申请证书。

    参数:
    - cert_path: 本地证书路径
    - key_path: 本地私钥路径
    - common_name: 证书的通用名称 (Common Name)

    返回:
    - (cert_path, key_path): 返回证书和私钥路径
    """
    if not is_certificate_valid_and_revoked(cert_path, common_name):
        print(f"证书无效或被吊销，为 {common_name} 重新申请证书...")
        cert_path, key_path = request_new_certificate(common_name)
    else:
        print(f"证书有效: {common_name}")

    return cert_path, key_path


def initialize_certificate(common_name):
    """
    初始化证书（验证或申请新证书）。

    参数:
    - common_name: 证书的通用名称 (Common Name)

    返回:
    - (cert_path, key_path): 返回证书和私钥路径
    """
    cert_dir = os.path.join(os.getcwd(), 'certs')
    os.makedirs(cert_dir, exist_ok=True)  # 确保目录存在

    cert_path = os.path.join(cert_dir, f"{common_name}_cert.pem")
    key_path = os.path.join(cert_dir, f"{common_name}_key.pem")

    return ensure_valid_certificate(cert_path, key_path, common_name)
