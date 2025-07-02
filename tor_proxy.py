import requests
from stem import Signal
from stem.control import Controller

def get_tor_session():
    session = requests.session()
    session.proxies = {
        'http': 'socks5h://127.0.0.1:9050',
        'https': 'socks5h://127.0.0.1:9050'
    }
    return session

def renew_tor_identity():
    with Controller.from_port(port=9051) as controller:
        controller.authenticate(password="your_tor_password")
        controller.signal(Signal.NEWNYM)