# encoding=utf-8
__author__ = 'Zephyr369'

import ssl

from app import create_app

import os

from startup_certificate import ensure_valid_certificate

common_name = "bank_application"

cert_path, key_path = ensure_valid_certificate(common_name)

app = create_app()

if __name__ == '__main__':
    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        print(f"证书或私钥文件缺失: {cert_path}, {key_path}")
        exit(1)

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)  # 加载服务端证书和私钥
    context.load_verify_locations(cafile=cert_path)  # CA 根证书
    context.verify_mode = ssl.CERT_REQUIRED  # 要求客户端必须提供证书

    app.run(
        host='127.0.0.1',
        port=5000,
        threaded=True,
        debug=app.config['DEBUG'],
        ssl_context=(cert_path, key_path)
    )