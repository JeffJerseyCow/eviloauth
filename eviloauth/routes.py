import logging
import requests
from . import app, cache
from .dispatcher import Dispatcher
from .access_token import AccessToken
from .refresh_token import RefreshToken
from eviloauth import app, cache
from eviloauth.general_token import GeneralToken
from flask import jsonify, render_template, request, redirect as flask_redirect


@app.route('/')
def home():
    return 'Eviloauth'


@app.route('/callback', methods=['POST'])
def callback():
    token_data = request.json.get('access_token')  # Retrieve the raw token data

    if token_data:
        try:
            general_token = GeneralToken(access_token=token_data)
            general_tokens = cache.get('tokens', {})  # Ensure there is a default empty dict
            general_tokens.update({str(general_token): general_token})
            cache.set('tokens', general_tokens)
            return jsonify({'status': 'success', 'message': 'Token received', 'data': str(general_token)})
        except Exception as e:  # Broad exception handling, consider specifying
            logging.error('Error processing token: %s', e)
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

    client_id = app.config.get('CLIENT_ID')
    redirect_uri = app.config.get('REDIRECT_URI')
    code_verifier = app.config.get('CODE_VERIFIER')
    scope = app.config.get('SCOPE')

    data = {
        'client_id': client_id,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': redirect_uri,
        'code_verifier': code_verifier,
        'scope': scope
    }
    response = requests.post(app.config.get(
        'TOKEN_ENDPOINT'), headers=headers, data=data)

    token_type = response.json()["token_type"]
    scope = response.json()["scope"]
    expires_in = response.json()["expires_in"]
    ext_expires_in = response.json()["ext_expires_in"]
    access_token = response.json()["access_token"]
    refresh_token = response.json()["refresh_token"]

    general_token = GeneralToken(access_token=access_token,
                                 refresh_token=refresh_token,
                                 client_id=client_id,
                                 code=code,
                                 redirect_uri=redirect_uri,
                                 code_verifier=code_verifier,
                                 scope=scope,
                                 token_endpoint=app.config.get(
                                     'TOKEN_ENDPOINT'),
                                 token_type=token_type,
                                 expires_in=expires_in,
                                 ext_expires_in=ext_expires_in)

    general_tokens = cache.get('tokens')
    general_tokens.update({str(general_token): general_token})
    cache.set('tokens', general_tokens)
    logging.info("Access Token: %s", access_token)
    logging.info("Refresh Token: %s", refresh_token)

    return flask_redirect(app.config.get('FINAL_DESTINATION'))
