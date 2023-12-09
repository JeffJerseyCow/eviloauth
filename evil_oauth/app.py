import requests
import argparse
import random
import string
from flask import Flask, request, jsonify, render_template
from . import __version__

app = Flask('oauth2-sec-test')

# Generate 10 alphanumeric for Response URI
chars = string.ascii_letters + string.digits
client_id = '77248f8f-96e8-436e-9dfa-8f8ed6e32add'
uri_string = 'JJ9jjdaWj7'
redirect_uri = f'https://127.0.0.1:5000/{uri_string}'

@app.route('/')
def home():
	return render_template('index.html', client_id=client_id, redirect_uri=redirect_uri)

@app.route('/callback', methods=['POST'])
def callback():
    data = request.json
    token = data.get('access_token')
    print("Received token:", token)
    return jsonify({"status": "success", "message": "Token received"})

@app.route(f'/{uri_string}', methods=['GET'])
def redirect():
	return render_template('redirect.html')	

def main():
	print('====================')
	print(f'evil-oauth {__version__}')
	print('====================')

	parser = argparse.ArgumentParser(prog='oauth2-sec-test')
	parser.add_argument('-c', '--client-id', required=True, help='OAuth2.0 Client ID')
	parser.add_argument('-r', '--response-type', default='token', 
		help='OAuth 2.0 Response Type [code (AuthZ Flow) | token (Implicit Flow)]')
	parser.add_argument('-s', '--scope', required=True, help='OAuth2.0 Scopes')
	parser.add_argument('-u', '--redirect-uri', default=uri_string, help='OAuth2.0 Response URI')
	parser.add_argument('-e', '--endpoint', required=True, help='OAuth2.0 Target URI Endpoint')
	args = parser.parse_args()

	authz_uri = ''.join([args.endpoint, '?', 
		'client_id=', args.client_id,
		'&'
		'scope=', args.scope,
		'&',
		'response_type=', args.response_type,
		'&',
		'redirect_uri=', redirect_uri])

	print(f'Client ID: {args.client_id}')
	print(f'Response Type: {args.response_type}')
	print(f'Scope: {args.scope}')
	print(f'Endpoint: {args.endpoint}')
	print(f'Authz URI: {authz_uri}')
	print(f'Callback on {redirect_uri}')
	client_id = args.client_id
	app.run(ssl_context=('adhoc'), debug=True)

if __name__ == '__main__':
	main()
