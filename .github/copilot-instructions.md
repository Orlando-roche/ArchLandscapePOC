# Copilot Instructions for ArchLandscapePOC

## Project Overview
ArchLandscapePOC is a static web application for automated architecture landscape generation. The main user flow is Google OAuth 2.0 authentication, followed by user info display. The app is deployed to GitHub Pages from the `/site` directory using a GitHub Actions workflow.

## Architecture & Key Files
- **Static Site**: All user-facing code is in `/site`.
  - `index.html`: Main entry point. Loads Google Identity Services (GIS) client and app JS.
  - `script.js`: Handles Google OAuth 2.0 login, token management, and user info retrieval. Uses a hardcoded `CLIENT_ID` for Google Cloud OAuth.
  - `styles.css`: Basic UI styling.
- **Deployment**: `.github/workflows/deploy-pages.yml` automates deployment to GitHub Pages on push to `main` or `master`. Only `/site` is published.
- **No Backend**: There is no server-side code; all logic is client-side.

## Developer Workflows
- **Local Development**: Edit files in `/site` and open `index.html` in a browser. No build step required.
- **Authentication**: Uses Google OAuth 2.0 via GIS client. The consent screen is set to External. The `CLIENT_ID` is project-specific and should be updated if the Google Cloud project changes.
- **Deployment**: Push changes to `main` or `master` to trigger GitHub Pages deployment. The workflow only uploads `/site`.
- **Testing**: No automated tests or test scripts are present. Manual browser testing is required.

## Project-Specific Patterns & Conventions
- **OAuth Flow**: The login button is disabled until the GIS library loads. Token client is lazily initialized on first click.
- **Status Updates**: Status messages are shown in the `#status` div. Error handling is surfaced to the user.
- **Logout**: Calls `google.accounts.oauth2.revoke` to invalidate the token.
- **No Frameworks**: Pure HTML/CSS/JS; no build tools, bundlers, or frameworks.
- **No Package Dependencies**: `package.json` exists but is unused; ignore for most workflows.

## Integration Points
- **Google Identity Services**: Integrated via CDN in `index.html`. The OAuth client ID is hardcoded in `script.js`.
- **GitHub Pages**: Deployment is automated; no manual steps required beyond pushing to the repo.

## Examples
- To update the OAuth client, change `CLIENT_ID` in `script.js`.
- To add UI elements, edit `index.html` and style in `styles.css`.
- To debug authentication, use browser dev tools and check status messages in the UI.

## Key References
- `/site/index.html`, `/site/script.js`, `/site/styles.css`
- `.github/workflows/deploy-pages.yml`

---
If any conventions or workflows are unclear, please ask for clarification or provide feedback to improve these instructions.
