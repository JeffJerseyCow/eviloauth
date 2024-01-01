class EviloauthCommandException(Exception):

    def __init__(self, message="An error occurred in Eviloauth command execution"):
        super().__init__(message)

class EviloauthModuleException(Exception):

    def __init__(self, message="An error occurred in Eviloauth module execution"):
        super().__init__(message)
