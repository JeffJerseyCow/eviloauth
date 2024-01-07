import logging
import requests
from . import app, cache
from .dispatcher import Dispatcher
from .access_token import AccessToken
from .refresh_token import RefreshToken
from flask import jsonify, render_template, request, redirect as flask_redirect


@app.route('/')
def home():
    return 'Eviloauth'


@app.route('/callback', methods=['POST'])
def callback():
    token_data = request.json.get('access_token')  # Retrieve the raw token data

    if token_data:
        try:
            # Convert token_data to an AccessToken object if it's a string
            if isinstance(token_data, str):
                access_token = AccessToken(token_data)
            else:
                logging.error("Invalid access token format")
                return jsonify({'status': 'error', 'message': 'Invalid token format'}), 400

            # Use Dispatcher's class method to get the token manager
            token_manager = Dispatcher.get_token_manager()

            if token_manager:
                token_key = token_manager.add(access_token)  # Pass the AccessToken object
                logging.info("Access Token: %s", str(access_token))
                return jsonify({'status': 'success', 'message': 'Token received', 'data': token_key})
            else:
                logging.error("Token manager not available")
                return jsonify({'status': 'error', 'message': 'Token manager not available'}), 500

        except ValueError as e:
            logging.error('Cannot process token %s', e)
            return jsonify({'status': 'error', 'message': str(e)}), 400
    else:
        logging.error('Callback did not receive access_token')
        return jsonify({'status': 'error', 'message': 'No token provided'}), 400

@app.route(f'/redirect', methods=['GET'])
def redirect():
    final_destination = app.config.get('FINAL_DESTINATION')
    return render_template('redirect.html', final_destination=final_destination)


@app.route(f'/hook', methods=['GET'])
def hook():
    access_token = request.json.get('access_token')
    token_manager = Dispatcher.get_token_manager()
    code = request.args.get('code')
    state = request.args.get('state')
    session_state = request.args.get('session_state')
    token_key = token_manager.add(access_token)

    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Origin': '*'
    }
    data = {
        'client_id': app.config.get('CLIENT_ID'),
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': app.config.get('REDIRECT_URI'),
        'code_verifier': app.config.get('CODE_VERIFIER'),
        'scope': app.config.get('SCOPE')
    }
    response = requests.post(app.config.get(
        'TOKEN_ENDPOINT'), headers=headers, data=data)

    token_type = response.json()["token_type"]
    scope = response.json()["scope"]
    expires_in = response.json()["expires_in"]
    ext_expires_in = response.json()["ext_expires_in"]
    access_token = response.json()["access_token"]
    refresh_token = response.json()["refresh_token"]

    access_token = AccessToken(access_token)
    access_tokens = cache.get('tokens')
    access_tokens.update({str(access_token): access_token})
    cache.set('tokens', access_tokens)
    logging.info("Access Token: %s", access_token)

    refresh_token = RefreshToken(refresh_token)
    # TODO: Store refresh token
    logging.info("Refresh Token: %s", refresh_token)

    return flask_redirect(app.config.get('FINAL_DESTINATION'))
