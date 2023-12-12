import logging
from flask import request, jsonify, render_template
from . import flask_app
from .token_utilities import process_token, get_cache, opaque_token_count

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
    data = request.json
    token = data.get('access_token')

    if token:
        try:
            cache_data = process_token(token)
            print("Processed Token Data:", cache_data)
            return jsonify({"status": "success", "message": "Token received", "data": cache_data})
        except ValueError as e:
            logging.error('Cannot process_token %s', e)
            opaque_token = get_cache(f'opaque_{opaque_token_count}')
            print("Opaque Token:", opaque_token)
            return jsonify({"status": "error", "message": str(e)}), 400
    else:
        logging.error('Callback didn\'t receive access_token')
        return jsonify({"status": "error", "message": "No token provided"}), 400

redirect_uri_endpoint = flask_app.config.get('REDIRECT_URI_ENDPOINT')
@flask_app.route(f'/{redirect_uri_endpoint}', methods=['GET'])
def redirect():
	final_destination = flask_app.config.get('FINAL_DESTINATION')
	return render_template('redirect.html', final_destination=final_destination)	
