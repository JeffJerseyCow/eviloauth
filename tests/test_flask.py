from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
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


def test_flask_start():

    flask_server = start_flask()

    options = Options()
    options.add_argument('--headless')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument('--ignore-certificate-errors')
    driver = webdriver.Chrome(options=options)

    driver.get('https://127.0.0.1:5000')

    wait = WebDriverWait(driver, 10)

    body_text = wait.until(
        EC.visibility_of_element_located((By.TAG_NAME, 'body')))
    flask_server.shutdown()

    driver.implicitly_wait(2)

    assert body_text.text == 'Eviloauth'
