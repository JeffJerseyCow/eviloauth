function initializeLogin(endpoint, clientId, scope, responseType, redirectUri) {
    document.getElementById('login').addEventListener('click', function() {
	const authzUri = `${endpoint}?client_id=${clientId}&scope=${scope}&response_type=${responseType}` +
			 `&redirect_uri=${redirectUri}`;
        window.location = authzUri;
    });
}
