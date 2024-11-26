# encoding=utf-8
__author__ = 'Zephyr369'


from app import create_app
from startup_certificate import initialize_certificate
import os

# 应用程序的 Common Name
common_name = "shop_application"

# 初始化证书
cert_path, key_path = initialize_certificate(common_name)

# 创建 Flask 应用
app = create_app()

# 运行 Flask 应用
if __name__ == '__main__':
    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        print(f"证书或私钥文件缺失: {cert_path}, {key_path}")
        exit(1)

    app.run(
        host='127.0.0.1',
        port=8888,
        threaded=True,
        debug=app.config['DEBUG'],
        ssl_context=(cert_path, key_path)
    )