from selenium import webdriver
from selenium.webdriver.common.by import By
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


def test_flask_start():

    flask_server = start_flask()

    driver = webdriver.Chrome()
    driver.get('https://127.0.0.1:5000')

    wait = WebDriverWait(driver, 10)

    bypass_ssl(wait)

    body_text = wait.until(
        EC.visibility_of_element_located((By.TAG_NAME, 'body')))
    flask_server.shutdown()

    driver.implicitly_wait(2)

    assert body_text.text == 'Eviloauth'


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        if sys.argv[1] == 'test_flask_start':
            test_flask_start()
            input()
