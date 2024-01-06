import logging
from flask import jsonify, render_template, request
from . import app, cache  # type: ignore
from .access_token import AccessToken


@app.route('/')
def home():
    endpoint = app.config.get('ENDPOINT')
    client_id = app.config.get('CLIENT_ID')
    scope = app.config.get('SCOPE')
    response_type = app.config.get('RESPONSE_TYPE')
    redirect_uri = app.config.get('REDIRECT_URI')
    return render_template('index.html', endpoint=endpoint, client_id=client_id, scope=scope,
                           response_type=response_type, redirect_uri=redirect_uri)


@app.route('/callback', methods=['POST'])
def callback():
    token = request.json.get('access_token')  # type: ignore

    if token:
        try:
            access_token = AccessToken(token)
            token_key = str(access_token)  # Unique string representation of the token
            cache.set(token_key, access_token)  # Store the token using its unique key

            logging.info("Processed Token Data: %s", access_token)
            return jsonify({'status': 'success', 'message': 'Token received', 'data': token_key})
        except ValueError as e:
            logging.error('Cannot process_token %s', e)
            return jsonify({'status': 'error', 'message': str(e)}), 400
    else:
        logging.error('Callback didn\'t receive access_token')
        return jsonify({'status': 'error', 'message': 'No token provided'}), 400

@app.route(f'/redirect', methods=['GET'])
def redirect():
    final_destination = app.config.get('FINAL_DESTINATION')
    return render_template('redirect.html', final_destination=final_destination)
