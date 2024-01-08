import logging
from datetime import datetime


class RefreshToken:
    def __init__(self, raw_refresh_token):
        self.raw_token = raw_refresh_token
        self.token_id = raw_refresh_token[-10:]
        self.time = datetime.now().strftime('%H:%M:%S')
        self.today = datetime.today().strftime('%d-%m-%Y')

    def __str__(self):
        return f'RT-{self.token_id}-{self.time}'

    def __repr__(self):
        return self.__str__()
