# encoding=utf-8
__author__ = 'Zephyr369'
from app import create_app
import os

app = create_app()

if __name__ == '__main__':
    # 确保 SSL 证书文件存在
    cert_file = './app/ca_cert.pem'
    key_file = './app/ca_key.pem'

    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        print("SSL 证书或密钥文件不存在，请先生成它们。")
        exit(1)

    # 运行 Flask 应用，启用 HTTPS
    app.run(
        host='0.0.0.0',
        port=443,
        ssl_context=(cert_file, key_file),
        threaded=True,
        debug=True
    )
