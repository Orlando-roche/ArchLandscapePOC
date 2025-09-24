// Personal Google Cloud Project OAuth 2.0 Client ID
//   - Created in Google Cloud Console
//   - OAuth consent screen configured as External (not Internal)
const CLIENT_ID = "806987019551-2j02ce3t9b3e0io30coffth5u6c9uoc7.apps.googleusercontent.com";

let tokenClient;
let lastTokenResponse; // keep the token if you want to revoke

function gsiLoaded() {
	// Enable the button when the GIS library has loaded
	document.getElementById('login').disabled = false;

	// Lazy-init the token client on first click to ensure library is ready
	document.getElementById('login').addEventListener('click', () => {
		if (!tokenClient) {
			tokenClient = google.accounts.oauth2.initTokenClient({
				client_id: CLIENT_ID,
				scope: 'openid email profile', // request email
				callback: async (tokenResponse) => {
					if (tokenResponse.error) {
						showStatus(`Auth error: ${tokenResponse.error}`, true);
						return;
					}
					lastTokenResponse = tokenResponse;
					await showUserInfo(tokenResponse.access_token);
				},
				error_callback: (err) => {
					showStatus(`Popup error: ${err?.type || 'unknown'}`, true);
				}
			});
		}
		// Prompt on first time to ensure consent
		tokenClient.requestAccessToken({
			prompt: 'consent'
		});
	});

	document.getElementById('logout').addEventListener('click', () => {
		if (!lastTokenResponse?.access_token) return;
		google.accounts.oauth2.revoke(lastTokenResponse.access_token, () => {
			lastTokenResponse = null;
			document.getElementById('login').disabled = false;
			document.getElementById('logout').style.display = 'none';
			showStatus('Signed out.');
		});
	});
}

async function showUserInfo(accessToken) {
	// Fetch basic profile (incl. email) from the OIDC UserInfo endpoint
	// You can use either of these equivalent endpoints:
	//   https://openidconnect.googleapis.com/v1/userinfo
	//   https://www.googleapis.com/oauth2/v3/userinfo
	// We’ll use the official OIDC endpoint:
	const resp = await fetch('https://openidconnect.googleapis.com/v1/userinfo', {
		headers: {
			Authorization: `Bearer ${accessToken}`
		}
	});

	if (!resp.ok) {
		showStatus(`Failed to fetch profile (${resp.status})`, true);
		return;
	}

	const profile = await resp.json();
	document.getElementById('status').textContent = `✅ Authenticated as ${profile.email}`;
	document.getElementById('login').disabled = true;
	document.getElementById('logout').style.display = 'inline-block';
}

function showStatus(msg, isError = false) {
	const el = document.getElementById('status');
	el.textContent = msg;
	el.style.color = isError ? 'crimson' : 'inherit';
}