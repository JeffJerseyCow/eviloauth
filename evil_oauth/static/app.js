function initializeLogin(clientId, redirectUri) {
    document.getElementById('login').addEventListener('click', function() {
        const authUrl = `https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=${clientId}&response_type=token&redirect_uri=${redirectUri}&scope=Mail.Read`;

        window.location = authUrl;
    });
}
