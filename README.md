# BoardReady Class 10

Study tracker for CBSE Class 10 (2027 boards) with accounts and saved progress in MongoDB.

## Run it
1. Install Node 18+ and make a free MongoDB Atlas cluster (Database Access: add a user; Network Access: allow your IP, or 0.0.0.0/0 for hosting).
2. Copy `.env.example` to `.env` and fill in `MONGODB_URI` and a long random `JWT_SECRET`.
3. (Optional) Add `GOOGLE_CLIENT_ID` to enable "Continue with Google". See the section below.
4. `npm install` then `npm start`
5. Open http://localhost:3000 (do not open `public/index.html` directly, because accounts need the server).

## How it works
- `public/index.html` is the whole frontend. Progress is cached in the browser and synced to MongoDB 0.7 seconds after each tick when logged in.
- `POST /api/signup`, `POST /api/login`, `POST /api/auth/google`, `GET /api/me`, `PUT /api/progress`.
- Profile (login required): `PUT /api/profile` (name, school, board target %), `PUT /api/password` (change or set), `POST`/`DELETE /api/profile/google` (connect or disconnect Google), `DELETE /api/account`. Passwords are hashed with bcrypt; sessions use a 60-day JWT.
- Signing in on a new device loads the saved progress. If the account is empty, any progress already ticked on that device is uploaded.

## Google sign-in setup
1. Go to https://console.cloud.google.com/apis/credentials, create a project, and configure the OAuth consent screen (External).
2. Create credentials, **OAuth client ID**, type **Web application**.
3. Under **Authorized JavaScript origins** add `http://localhost:3000` and your deployed URL (for example `https://boardready.onrender.com`). No redirect URI is needed.
4. Copy the client ID into `GOOGLE_CLIENT_ID` in `.env` (and in your host's environment variables).
5. While the consent screen is in "Testing" mode, only emails listed under Test users can sign in. Click **Publish app** when you are ready for everyone.

Notes: the server verifies Google's ID token itself. If someone signs in with Google using an email that already has a password account, the accounts are linked and the old password is removed (email signup is not email-verified, so this stops anyone squatting on an address). The user can set a new password from the Account page. A Google-only account cannot disconnect Google until it has a password.

## Deploy (Render, Railway, etc.)
Create a Node web service from this folder, build command `npm install`, start command `npm start`, and add `MONGODB_URI`, `JWT_SECRET` and `GOOGLE_CLIENT_ID` as environment variables.

## Things to check each year
- Exam dates (`SCHED`) and PDF links (`SYL`) are near the top of the script in `public/index.html`.
