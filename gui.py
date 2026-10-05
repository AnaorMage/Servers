import webview
from app import app

if __name__ == '__main__':
    webview.create_window(
        'Система учета и расчета мощностей IT-инфраструктуры',
        app,
        width=1280,
        height=800
    )
    webview.start()