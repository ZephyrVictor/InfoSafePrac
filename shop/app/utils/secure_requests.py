# encoding=utf-8
__author__ = 'Zephyr369'

import requests


def send_secure_request(url, data, client_cert, client_key, ca_cert):
    """
    向目标服务器发送带有客户端证书的 HTTPS 请求。

    参数：
    - url: 目标服务器的 URL。
    - data: 要发送的 JSON 数据。
    - client_cert: 客户端证书路径。
    - client_key: 客户端私钥路径。
    - ca_cert: CA 根证书路径。

    返回：
    - 响应 JSON 数据
    """
    response = requests.post(
        url,
        json=data,
        cert=(client_cert, client_key),
        verify=False  # CA服务器是自签名，不验证了
    )
    response.raise_for_status()
    return response.json()
