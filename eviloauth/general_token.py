import logging
import requests
from eviloauth.access_token import AccessToken
from eviloauth.refresh_token import RefreshToken
from eviloauth.exceptions import EviloauthInvalidTokenException


class GeneralToken:
    def __init__(self, **kwargs):

        self.kwargs = kwargs
        access_token = kwargs.get('access_token')
        refresh_token = kwargs.get('refresh_token')

        if access_token:
            self.access_token = AccessToken(access_token)
            self.token_id = f'GT-{self.access_token}'

        else:
            raise EviloauthInvalidTokenException("Access token is required")

        if refresh_token:
            self.refresh_token = RefreshToken(refresh_token)

    def __str__(self):
        return f"{self.token_id}"

    def __repr__(self):
        return self.__str__()

    def get_access_token(self):
        # TODO: FIX FOR TAGKING REFRESH TOKEN
        if self.refresh_token:
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Origin': '*'
            }

            data = {
                'client_id': self.kwargs.get('client_id'),
                'grant_type': 'refresh_token',
                'refresh_token': self.refresh_token.raw_token,
                'scope': self.kwargs.get('scope')
            }

            logging.info('Refreshing access token')
            response = requests.post(self.kwargs.get(
                'token_endpoint'), headers=headers, data=data)

            token_type = response.json()["token_type"]
            scope = response.json()["scope"]
            expires_in = response.json()["expires_in"]
            ext_expires_in = response.json()["ext_expires_in"]
            self.access_token = AccessToken(response.json()["access_token"])
            self.refresh_token = RefreshToken(response.json()["refresh_token"])

            return self.access_token

        else:
            return self.access_token

    def get_refresh_token(self):
        return self.refresh_token
