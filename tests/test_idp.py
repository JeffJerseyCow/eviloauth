import os
from eviloauth import cache
from eviloauth.idp import IDP
from dotenv import load_dotenv
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC


def start_flask():
    import threading
    from werkzeug.serving import make_server
    from eviloauth import app
    import eviloauth.routes
    flask_server = make_server('127.0.0.1', 5000, app, ssl_context='adhoc')
    t = threading.Thread(target=flask_server.serve_forever)
    t.start()
    return flask_server


def bypass_ssl(wait):

    advanced_button = wait.until(
        EC.visibility_of_element_located((By.ID, 'details-button')))
    advanced_button.click()

    proceed_link = wait.until(
        EC.visibility_of_element_located((By.ID, 'proceed-link')))
    proceed_link.click()


def test_entra_implicit_flow():
    load_dotenv()
    upn = os.getenv('UPN')
    password = os.getenv('PASSWORD')

    flask_server = start_flask()

    idp = IDP('entra_implicit_flow', '127.0.0.1:5000', client_id='77248f8f-96e8-436e-9dfa-8f8ed6e32add',
              scope='mail.read', final_destination='https://outlook.live.com/')

    driver = webdriver.Chrome()
    driver.get(idp.uri)

    wait = WebDriverWait(driver, 10)

    email_field = wait.until(
        EC.visibility_of_element_located((By.ID, "i0116")))
    email_field.send_keys(upn)
    email_field.send_keys(Keys.RETURN)

    password_field = wait.until(
        EC.visibility_of_element_located((By.ID, "i0118")))
    password_field.send_keys(password)
    password_field.send_keys(Keys.RETURN)

    stay_signed_in = wait.until(
        EC.visibility_of_element_located((By.ID, "idSIButton9")))
    stay_signed_in.click()
    driver.implicitly_wait(2)

    bypass_ssl(wait)

    wait.until(EC.title_contains('Outlook'))
    flask_server.shutdown()

    general_token = next(iter(cache.get('tokens').items()))[1]
    assert str(general_token.get_access_token())[0:5] == 'AT-O-'


def test_entra_code_flow():
    load_dotenv()
    upn = os.getenv('UPN')
    password = os.getenv('PASSWORD')

    flask_server = start_flask()

    idp = IDP('entra_code_flow', '127.0.0.1:5000', client_id='77248f8f-96e8-436e-9dfa-8f8ed6e32add',
              scope='mail.read', final_destination='https://outlook.live.com/')

    driver = webdriver.Chrome()
    driver.get(idp.uri)

    wait = WebDriverWait(driver, 10)

    email_field = wait.until(
        EC.visibility_of_element_located((By.ID, "i0116")))
    email_field.send_keys(upn)
    email_field.send_keys(Keys.RETURN)

    password_field = wait.until(
        EC.visibility_of_element_located((By.ID, "i0118")))
    password_field.send_keys(password)
    password_field.send_keys(Keys.RETURN)

    stay_signed_in = wait.until(
        EC.visibility_of_element_located((By.ID, "idSIButton9")))
    stay_signed_in.click()
    driver.implicitly_wait(2)

    bypass_ssl(wait)

    wait.until(EC.title_contains('Outlook'))
    flask_server.shutdown()

    general_token = next(iter(cache.get('tokens').items()))[1]
    assert str(general_token.get_access_token())[0:5] == 'AT-O-'


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        if sys.argv[1] == 'test_flask_start':
            test_flask_start()
            input()
