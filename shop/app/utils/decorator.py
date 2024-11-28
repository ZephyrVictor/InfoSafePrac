# encoding=utf-8
__author__ = 'Zephyr369'

import os
import ssl
import socket
from functools import wraps
from flask import current_app, abort, request
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend


# 为了保证bank侧是可信的，写一个装饰器来装在要调用requests的函数上，确保bank是可信的,这是本项目中我认为最大的妥协，也是最不优雅的妥协
# 正常应该是通过CA来验证的，然后直接指定证书的路径。但是由于CA的证书是自签名的，所以无法验证，所以只能通过这种方式来验证

def verify_bank_certificate(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        bank_host = '127.0.0.1'
        bank_port = 5000
        ca_cert_path = "E:\\studying\\3\\上\\信息安全设计与实践\\app\\cert\\app\\ca_cert.pem"
        bank_cert_path = os.path.join(current_app.instance_path, 'certificates', 'bank_cert.pem')

        # Step 1: 从银行服务器获取证书
        try:
            context = ssl._create_unverified_context()  # 使用未验证的 SSL 上下文
            with socket.create_connection((bank_host, bank_port)) as sock:
                with context.wrap_socket(sock, server_hostname=bank_host) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
        except Exception as e:
            current_app.logger.error(f"无法连接到银行服务器获取证书: {e}")
            abort(500)

        # Step 2: 将 DER 格式转换为 PEM 格式并解析
        try:
            cert_pem = ssl.DER_cert_to_PEM_cert(der_cert)
            x509_cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
            common_name = x509_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        except Exception as e:
            current_app.logger.error(f"解析银行证书失败: {e}")
            abort(500)

        # Step 3: 验证银行证书是否被吊销
        ca_verify_url = 'https://127.0.0.1:443/api/verify_certificate'
        try:
            response = requests.post(
                ca_verify_url,
                json={'common_name': common_name},
                verify=False  # 通过自签名 CA 时设置为 False
            )
            response.raise_for_status()
            cert_status = response.json().get('revoked', True)

            if cert_status:
                current_app.logger.error(f"银行证书已被吊销: {common_name}")
                abort(403)
            else:
                # 证书未被吊销，记录日志并设置 verify=False
                current_app.logger.info(f"银行证书 {common_name} 验证通过，证书未被吊销，bank侧是可信的qaq")
                kwargs['verify'] = False  # 如果证书未被吊销，可以继续进行下一步操作

        except Exception as e:
            current_app.logger.error(f"验证银行证书失败: {e}")
            abort(500)

        # Step 4: 保存银行证书到本地
        try:
            os.makedirs(os.path.dirname(bank_cert_path), exist_ok=True)
            with open(bank_cert_path, 'w') as bank_cert_file:
                bank_cert_file.write(cert_pem)
            current_app.logger.info(f"银行证书已保存到: {bank_cert_path}")
        except Exception as e:
            current_app.logger.error(f"保存银行证书失败: {e}")
            abort(500)

        # Step 5: 将 CA 根证书与银行证书路径传递给被装饰函数
        kwargs['ca_cert_path'] = ca_cert_path
        kwargs['bank_cert_path'] = bank_cert_path
        return f(*args, **kwargs)

    return decorated_function
