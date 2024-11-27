# encoding=utf-8
__author__ = 'Zephyr369'

import ssl
import requests
from functools import wraps
from flask import request, abort, current_app
from cryptography import x509
from cryptography.hazmat.backends import default_backend


def verify_peer_certificate():
    """
    验证对方的证书是否有效的装饰器。

    参数：
    - ca_verify_url: CA 服务器的证书验证 API URL。
    - ca_cert_path: CA 根证书路径，用于验证 CA 服务器的 HTTPS 证书。

    返回：
    - 装饰器
    """
    ca_verify_url, ca_cert_path = "https://127.0.0.1:443/api/verify_certificate","../../certs/shop_application_cert.pem"
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # 从环境变量中获取对方的证书
            peer_cert = request.environ.get('SSL_CLIENT_CERT')
            if not peer_cert:
                current_app.logger.error("未提供对方的证书")
                abort(403)

            # 解析证书，获取 Common Name
            try:
                x509_cert = x509.load_pem_x509_certificate(peer_cert.encode('utf-8'), default_backend())
                common_name = x509_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
            except Exception as e:
                current_app.logger.error(f"解析对方证书失败: {e}")
                abort(403)

            # 调用 CA 验证接口
            try:
                response = requests.post(
                    ca_verify_url,
                    json={'common_name': common_name},
                    verify=ca_cert_path
                )
                response.raise_for_status()
                if response.json().get('revoked', True):
                    current_app.logger.error(f"证书已被吊销: {common_name}")
                    abort(403)
            except Exception as e:
                current_app.logger.error(f"验证证书失败: {e}")
                abort(403)

            return f(*args, **kwargs)

        return decorated_function

    return decorator
