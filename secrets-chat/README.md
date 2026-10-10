# Secrets Chat

## Upload to GitHub
Upload the contents of this folder to the ROOT of the `secrets-chat-server` repository. The repository must show `server.js`, `package.json`, and the `public` folder at its top level.

## Render settings
- Runtime: Node
- Build command: `npm install`
- Start command: `npm start`
- Environment variables (set in Render, never commit real values): `MONGODB_URI`, `MONGODB_DB=secrets`, `SESSION_SECRET` (random, at least 32 characters), `NODE_ENV=production`.

## MongoDB Atlas
Use your Atlas connection string for `MONGODB_URI`; ensure the Atlas database user and Network Access settings permit the Render service to connect. Never put database credentials in frontend files or GitHub.

## Test
After deployment, open `/health` on the Render service URL. It should return `{"ok":true,"service":"secrets-chat-server"}`.

## Security note
This is a prototype, not an audited secure messenger. The existing frontend stores private encryption keys in browser localStorage and does not implement authenticated key verification or safe multi-device key recovery. Do not use it for high-risk conversations.
