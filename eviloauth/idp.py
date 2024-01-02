import string
import random
import logging
import requests
from . import get_idps, app
from prompt_toolkit import prompt
from .exceptions import EviloauthCommandException


class IDP():
    idps = get_idps()
    authz_endpoint = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize'
    token_endpoint = 'https://login.microsoftonline.com/common/oauth2/v2.0/token'

    def __init__(self, idp, redirect_server):

        if idp not in self.idps:
            raise EviloauthCommandException(
                f'IDP {idp} is not supported. Supported IDPs: {self.idps}')

        self.redirect_server = redirect_server
        self.idp = idp
        app.config['TOKEN_ENDPOINT'] = self.token_endpoint
        self.__idp_setup__()

    def __idp_setup__(self):
        self.client_id = prompt('Client ID: ')
        app.config['CLIENT_ID'] = self.client_id
        self.scope = prompt('Scope: ')
        app.config['SCOPE'] = self.scope
        self.final_destination = prompt('Final Destination: ')
        app.config['FINAL_DESTINATION'] = self.final_destination

        if self.idp == 'entra_implicit_flow':
            self.response_type = 'token'
            self.redirect_uri = f'https://{self.redirect_server}/redirect'

            app.config['REDIRECT_URI'] = self.redirect_uri
            app.config['RESPONSE_TYPE'] = self.response_type

            params = {
                'client_id': self.client_id,
                'scope': self.scope,
                'response_type': self.response_type,
                'redirect_uri': f'https://{self.redirect_server}/redirect'
            }
            uri = requests.Request('GET', self.authz_endpoint, params=params).prepare().url
            logging.info(uri)

        elif self.idp == 'entra_code_flow':
            self.response_type = 'code'
            self.redirect_uri = f'https://{self.redirect_server}/hook'
            self.state = self.__generate_state__()
            self.code_verifier = self.code_challenge = self.__generate_code_verifier__()
            self.code_challenge_method = 'plain'

            app.config['TOKEN_ENDPOINT'] = self.token_endpoint
            app.config['REDIRECT_URI'] = self.redirect_uri
            app.config['RESPONSE_TYPE'] = self.response_type
            app.config['STATE'] = self.state
            app.config['CODE_VERIFIER'] = self.code_verifier
            app.config['CODE_CHALLENGE'] = self.code_challenge
            app.config['CODE_CHALLENGE_METHOD'] = self.code_challenge_method

            params = {
                'client_id': self.client_id,
                'scope': self.scope,
                'response_type': self.response_type,
                'redirect_uri': self.redirect_uri,
                'state': self.state,
                'code_challenge': self.code_challenge,
                'code_challenge_method': self.code_challenge_method
            }
            uri = requests.Request('GET', self.authz_endpoint, params=params).prepare().url
            logging.info(uri)

    def __generate_state__(self):
        return ''.join([str(random.randint(0,9)) for _ in range(5)])

    def __generate_code_verifier__(self):
        allowed_chars = string.ascii_letters + string.digits + "-._~"
        return ''.join([random.choice(allowed_chars) for _ in range(48)])
