# encoding=utf-8
__author__ = 'Zephyr369'

import requests


def register_client_with_bank():
    bank_register_url = "https://127.0.0.1:5000/oauth/register_client"  # Bank 的注册接口
    shop_name = "shop_application"
    redirect_uris = ["https://127.0.0.1:8888/auth/bind_bank_card/callback"]  # Shop 的回调地址

    payload = {
        "client_name": shop_name,
        "redirect_uris": redirect_uris
    }

    try:
        response = requests.post(bank_register_url, json=payload, verify=False)
        if response.status_code == 201:
            data = response.json()
            print(f"Successfully registered with Bank.")
            print(f"Client ID: {data['client_id']}")
            print(f"Client Secret: {data['client_secret']}")
            return data['client_id'], data['client_secret']
        elif response.status_code == 200:
            data = response.json()
            print("Already registered:")
            print(f"Client ID: {data['client_id']}")
            print(f"Client Secret: {data['client_secret']}")
            return data['client_id'], data['client_secret']
        else:
            print(f"Failed to register: {response.json().get('error', 'Unknown error')}")
            return None, None
    except Exception as e:
        print(f"Error during registration: {e}")
        return None, None