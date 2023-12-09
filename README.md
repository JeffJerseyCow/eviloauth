# evil-oauth
evil-oauth is a series of red teaming, hacking and research tools for testing, and exploiting, OAuth2.0 implicit flows.

Projects like evil-nginx are fantastic at exploiting the OIDC specific OAuth2.0 authentiation scope. However, hardware tokens and Windows Hello utilise the FIDO protocols WebAuthN and CTAP, preventing OIDC OAuth2.0 scope credential theft because FIDO binds the current browser URI location, to the tokens login signature. When the hardware/CTAP signature arrives at the IdP, the presented URI and authentication URI are diffrent, indicating a phishing attempt.

The last ditch effort of the would-be hacker is to understand and exploit OAuth2.0 authorization code flow, particularly the OAuth2.0 implicit flow in an effort to steal Bearer tokens. The implicit flow is different to the authorization code flow as it returns the access_token directly, not an authorization_code.

We effectively pretend that we're a Single Page Application (SPA), or mobile application and force the target user/browser into an implicit OAuth2.0 flow. Then trick them into granting us/the attacker authorization to read, or perfor, sensitive information/actions.

## Examples
Ensure you're in the 'evil_oauth' directory.
```shell
python3 app.py -c '77248f8f-96e8-436e-9dfa-8f8ed6e32add'  -s Mail.Read -e https://login.microsoftonline.com/common/oauth2/v2.0/authorize

## Resources
Microsoft GraphAPI Scopes - https://learn.microsoft.com/en-us/graph/permissions-reference
