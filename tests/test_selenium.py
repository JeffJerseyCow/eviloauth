import os
from dotenv import load_dotenv
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC


def test_selenium_import():
    options = Options()
    options.add_argument('--headless')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument('--ignore-certificate-errors')
    driver = webdriver.Chrome(options=options)

    driver.get('http://www.example.com')
    assert driver.title == 'Example Domain'


def test_dotenv_load():
    load_dotenv()

    assert os.getenv('UPN') == 'eviloauth-test@outlook.com'


def test_microsoft_login():

    load_dotenv()
    upn = os.getenv('UPN')
    password = os.getenv('PASSWORD')

    options = Options()
    options.add_argument('--headless')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument('--ignore-certificate-errors')
    driver = webdriver.Chrome(options=options)
    wait = WebDriverWait(driver, 10)

    uri = f'https://www.office.com/login'
    driver.get(uri)

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

    assert driver.title == 'Home | Microsoft 365'
