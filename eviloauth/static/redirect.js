function initializeRedirect(finalDestination) {
    window.addEventListener('load', async function() {
        const hash = window.location.hash.substr(1);
        const params = new URLSearchParams(hash);
        const access_token = params.get('access_token');
	
        if (access_token) {
            try {
                const response = await fetch('/callback', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ access_token: access_token })
                });
                const responseData = await response.json();
            } catch (error) {
                console.error('Error:', error);
            }
        }

	  window.location = `${finalDestination}`;
    });
}
