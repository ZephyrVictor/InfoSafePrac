# encoding=utf-8
__author__ = 'Zephyr369'


from app import create_app

import os
from flask_wtf.csrf import CSRFProtect

from startup_certificate import ensure_valid_certificate


csrf = CSRFProtect()
# 创建 Flask 应用
app = create_app()

# 运行 Flask 应用
if __name__ == '__main__':
    common_name = "shop_application"

    # 初始化并验证证书
    cert_path, key_path = ensure_valid_certificate(common_name)

    # 验证完成后，确保证书文件存在（避免重复检查）
    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        print(f"证书或私钥文件缺失: {cert_path}, {key_path}")
        exit(1)

    # 启动 Flask 应用
    app.run(
        host='127.0.0.1',
        port=8888,
        threaded=True,
        debug=app.config['DEBUG'],
        ssl_context=(cert_path, key_path)
    )