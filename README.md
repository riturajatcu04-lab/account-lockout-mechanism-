# Account Lockout Mechanism – Full-Stack Project

A local educational project using React (frontend), Python Flask (REST API/backend), and SQLite (database).

## Features

- User registration and login
- Password hashing with Werkzeug's password-hashing utilities
- Three consecutive failed password attempts trigger a 30-second account lockout
- Automatic lock expiry
- Login audit events stored in SQLite
- Admin dashboard for browsing registered users, recent audit events, and basic account statistics
- Flask-Limiter request limits
- Flask-WTF CSRF protection for state-changing requests
- Server-side session authentication

## Project structure

```text
account-lockout-fullstack/
├── backend/
│   ├── app.py
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   ├── index.html
│   ├── package.json
│   ├── vite.config.js
│   └── src/
│       ├── App.jsx
│       ├── api.js
│       ├── main.jsx
│       └── style.css
└── README.md
```

## Requirements

- Python 3.10 or newer
- Node.js 20 or newer (includes npm)
- VS Code (recommended)

## 1. Configure the backend

Open a terminal in the `backend` folder.

Windows PowerShell:

```powershell
py -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

If PowerShell blocks activation, use Command Prompt:

```cmd
venv\Scripts\activate.bat
```

Edit `backend/.env`. Set a long random `SECRET_KEY` and a strong `ADMIN_PASSWORD`.
Do not commit `.env` to Git or share it.

Start the backend:

```powershell
py app.py
```

The API runs at `http://127.0.0.1:5000`.

## 2. Start the frontend

Open a SECOND terminal in the `frontend` folder:

```powershell
npm install
npm run dev
```

Open the local address printed by Vite, normally `http://localhost:5173`.

The Vite development server proxies `/api` requests to Flask.

## 3. Test the application

1. Register a normal user with a password of at least 12 characters.
2. Log in successfully.
3. Log out.
4. Enter the correct username and an incorrect password three times.
5. Confirm that the backend returns a locked response for 30 seconds.
6. Try the correct password during the lockout: it must still be rejected.
7. Wait 30 seconds and log in with the correct password.
8. Log in as the administrator using the values configured in `.env`.
9. Open the admin dashboard to inspect audit events.

## API endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/health` | API health check |
| GET | `/api/csrf` | Obtain CSRF token |
| POST | `/api/register` | Create a user |
| POST | `/api/login` | Authenticate and apply lockout |
| GET | `/api/me` | Current session |
| POST | `/api/logout` | End session |
| GET | `/api/admin/summary` | Admin-only summary and recent audit events |
| GET | `/api/admin/users` | Admin-only list of account status and metadata (no password hashes) |

Registration is limited to 3 requests per minute per IP address.

## Important security notes

This is an educational local prototype, not a production identity service.

- Passwords are stored as password hashes, not plaintext.
- The Flask session uses an HTTP-only cookie and CSRF protection.
- Account lockout state is stored in SQLite.
- The built-in Flask development server and Flask-Limiter's in-memory storage are for local development. For multiple production workers/servers, configure a shared rate-limit store such as Redis and use a production WSGI server.
- Configure HTTPS and set `COOKIE_SECURE=1` when deployed behind HTTPS.
- The initial admin account is created from `.env` only if that username does not already exist. Changing the environment password later does not automatically change the existing admin password.
- The example does not implement email-based password recovery, MFA, or a complete enterprise audit pipeline.
- Account lockout can be abused to deny service to legitimate users. Production systems need carefully designed recovery, monitoring, and additional controls.
- Use only on systems you own or have explicit permission to test.

## Troubleshooting

- `ModuleNotFoundError`: activate the backend virtual environment and run `pip install -r requirements.txt`.
- `npm is not recognized`: install Node.js LTS, restart VS Code, then check `node -v` and `npm -v`.
- CSRF error: reload the frontend page so it fetches a fresh CSRF token.
- Admin dashboard unavailable: check the `ADMIN_USERNAME` and `ADMIN_PASSWORD` values in `.env`; restart Flask after changing `.env`.
