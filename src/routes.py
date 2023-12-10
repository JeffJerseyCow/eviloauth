import logging
from flask import request, jsonify, render_template
from . import flask_app, redirect_uri_endpoint

@flask_app.route('/')
def home():
	endpoint = flask_app.config.get('ENDPOINT')
	client_id = flask_app.config.get('CLIENT_ID')
	scope = flask_app.config.get('SCOPE')
	response_type = flask_app.config.get('RESPONSE_TYPE')
	redirect_uri = flask_app.config.get('REDIRECT_URI')
	return render_template('index.html', endpoint=endpoint, client_id=client_id, scope=scope,
		response_type=response_type, redirect_uri=redirect_uri)

@flask_app.route('/callback', methods=['POST'])
def callback():
    try:
        data = request.json
        token = data.get('access_token')

        if not token:
            return jsonify({"status": "error", "message": "No token provided"}), 400

        token_id = store_token(token)
        logging.info(f'JWT received and stored token with ID {token_id}')

        return jsonify({"status": "success", "message": "Token received and stored", "id": token_id})

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return jsonify({"status": "error", "message": "An error occurred processing your request"}), 500

def store_token(token, filename='tokens.txt'):
    try:
        # Read the existing tokens and find the next ID
        with open(filename, 'r') as file:
            lines = file.readlines()
            last_id = int(lines[-1].split(',')[0]) if lines else 0
            next_id = last_id + 1
    except FileNotFoundError:
        # If the file doesn't exist, start with ID 1
        next_id = 1

    # Store the new token with the next ID
    with open(filename, 'a') as file:
        file.write(f"{next_id},{token}\n")

    return next_id

@flask_app.route(f'/{redirect_uri_endpoint}', methods=['GET'])
def redirect():
	return render_template('redirect.html')	
