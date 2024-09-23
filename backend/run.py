# encoding=utf-8
__author__ = 'Zephyr369'

from app import create_app

app = create_app()
# 访问localhost:5000/apidoc/可以查看文档
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, threaded= True, debug=app.config['DEBUG'])