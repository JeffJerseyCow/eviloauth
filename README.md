<<<<<<< HEAD
# evil-oauth
evil-oauth is a series of red teaming, hacking and research tools for testing, and exploiting, OAuth2.0 implicit flows.
=======
# eviloauth
eviloauth is a series of red teaming, hacking and research tools for testing, and exploiting, OAuth2.0 implicit flows.
>>>>>>> 7992815 (Refactored)

Projects like evil-nginx are fantastic at exploiting the OIDC specific OAuth2.0 authentiation scope. However, hardware tokens and Windows Hello utilise the FIDO protocols WebAuthN and CTAP, preventing OIDC OAuth2.0 scope credential theft because FIDO binds the current browser URI location, to the tokens login signature. When the hardware/CTAP signature arrives at the IdP, the presented URI and authentication URI are diffrent, indicating a phishing attempt.

The last ditch effort of the would-be hacker is to understand and exploit OAuth2.0 authorization code flow, particularly the OAuth2.0 implicit flow in an effort to steal Bearer tokens. The implicit flow is different to the authorization code flow as it returns the access_token directly, not an authorization_code.

We effectively pretend that we're a Single Page Application (SPA), or mobile application and force the target user/browser into an implicit OAuth2.0 flow. Then trick them into granting us/the attacker authorization to read, or perfor, sensitive information/actions.

<<<<<<< HEAD
## Usage
Ensure you're in the 'evil_oauth' directory and execute the following command using your own client ID **-c**, the required scope **-s**, the relevant auhotization endpoint **-e** and redirect endpoint **-u**.

It's also possible to redirect the user a non-suspicious final destination, such as their mail box URI with the **-f** flag.

```shell
python3 -m evil-oauth.app -c '77248f8f-96e8-436e-9dfa-8f8ed6e32add' -s 'Mail.Read User.Read' -e https://login.microsoftonline.com/common/oauth2/v2.0/authorize -u redirect -v
```

=======
## Examples
Ensure you're in the 'eviloauth' directory.
```shell
pip install poetry
poetry install
poetry run eviloauth -c '77248f8f-96e8-436e-9dfa-8f8ed6e32add'  -s 'Mail.Read User.Read' -e https://login.microsoftonline.com/common/oauth2/v2.0/authorize -v -u redirect
```
>>>>>>> 7992815 (Refactored)
## Resources
Microsoft GraphAPI Scopes - https://learn.microsoft.com/en-us/graph/permissions-reference

Graph Permissions - https://graphpermissions.merill.net/permission
<<<<<<< HEAD

## Contribution
The majority of evil-oauth is developed using PEP 8 styled Python. Anyone can contribute by forking the project, creating a feature branch and then issuing a Pull Request (PR) to master.

After a successful review, the PR is merged. If a 'request for changes' is made, please enrue you address the comments across the entire code base.

### Code Quality
All Python ".py" files must undergo PEP 8 formatting prior to a PR. The simplest method is to utilise the **autopep8** command:
```shell
autopep8 -i ./feature_file.py
```
=======
>>>>>>> 7992815 (Refactored)
