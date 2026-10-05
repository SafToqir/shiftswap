# ShiftSwap

![Tests](https://github.com/SafToqir/shiftswap/actions/workflows/tests.yml/badge.svg)

A web app for retail and hospitality staff to swap shifts. Post a shift you can't cover, and a colleague can claim it in one click.

I built this after four years working shifts at Tesco, where finding cover meant group chats and lost messages.

## Features

- Accounts with registration and login
- Post a shift with role, date, times and a note (overnight shifts handled)
- Browse and claim open shifts from colleagues
- "My shifts" page: see who is covering your shifts, remove unclaimed ones, or give back a shift you claimed

## Security

Built with the OWASP Top 10 in mind:

| Risk | How it's handled |
|---|---|
| Stolen passwords | Salted password hashing (`werkzeug`), minimum 10 characters |
| Brute-force login | Lockout after 5 failed attempts per IP for 10 minutes |
| Account enumeration | Same error message for wrong email and wrong password |
| CSRF | Every form and action button carries a CSRF token (`Flask-WTF`) |
| XSS | Jinja auto-escapes all user input; Content Security Policy blocks inline scripts |
| Clickjacking | `X-Frame-Options: DENY` |
| Broken access control | Server checks ownership before cancelling or releasing a shift (403 otherwise) |
| SQL injection | All queries go through the SQLAlchemy ORM, never string-built SQL |
| Race conditions | Claiming is a single conditional update, so two people can't claim the same shift |

## Tech

Python, Flask, SQLAlchemy (SQLite), Flask-Login, Flask-WTF, pytest, GitHub Actions

## Run it

```bash
pip install -r requirements.txt
python app.py
```

Then open http://127.0.0.1:5000

## Tests

```bash
pytest -v
```

17 tests cover registration, login, rate limiting, posting and claiming shifts, access control, CSRF, security headers and XSS escaping. They run automatically on every push via GitHub Actions.

## Project structure

```
app.py          routes, login, rate limiting, security headers
models.py       User and Shift database tables
forms.py        form fields and validation
templates/      HTML pages
static/         stylesheet
tests/          pytest tests
```
