import requests
import re
from bs4 import BeautifulSoup

class FingerprintScanner:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({

        })
        