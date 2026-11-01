# Roky's Market — Embed Studio

Discord OAuth2-protected dashboard to publish classic embeds and Components V2 messages via an existing bot.

## Deployment

1. Enable GitHub Pages → **GitHub Actions**.
2. Deploy the `backend/` FastAPI API to an HTTPS Python host. Do **not** host backend secrets on GitHub Pages.
3. Copy `backend/.env.example` into host environment variables. Configure Discord OAuth redirect to `https://YOUR-API-HOST/api/auth/callback`.
4. Edit `backend/allowed_users.txt` to add the Discord user IDs of permitted staff, one per line (`USERID: 123456789012345678`). By default no users are allowed until configured.
5. Set repository **Actions variable** `VITE_API_URL` to `https://YOUR-API-HOST`, then run Pages deploy.
6. Set `FRONTEND_URL=https://cozynxis.github.io/Roky-s-Market-Embeds-V2` and `COOKIE_SECURE=true` in API environment. `SESSION_SECRET` must be a secure random string of at least 32 chars.

The site is public but private content is guarded by the backend. Approved users sign in with Discord once, then their session cookie lasts seven days, unless they sign out. Adding or removing IDs changes backend access immediately. The bot token is never exposed to the browser.

**Security:** never commit `.env` or tokens. Hosting requires HTTPS and persistent backend storage for message history.