from datetime import datetime, timedelta

import pytest

from app import create_app
from models import Shift, User, db


@pytest.fixture
def app():
    app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "WTF_CSRF_ENABLED": False,
    })
    yield app


@pytest.fixture
def client(app):
    return app.test_client()


def register(client, name="Sam", email="sam@example.com", password="correct-horse-1"):
    return client.post("/register", data={
        "name": name, "email": email, "password": password, "confirm": password,
    }, follow_redirects=True)


def login(client, email="sam@example.com", password="correct-horse-1"):
    return client.post("/login", data={"email": email, "password": password},
                       follow_redirects=True)


def logout(client):
    return client.post("/logout", follow_redirects=True)


def add_shift(app, owner_email, hours_from_now=24, claimed_by_email=None):
    with app.app_context():
        owner = User.query.filter_by(email=owner_email).first()
        start = datetime.now() + timedelta(hours=hours_from_now)
        shift = Shift(role="Checkouts", start=start, end=start + timedelta(hours=8),
                      posted_by_id=owner.id)
        if claimed_by_email:
            shift.claimed_by_id = User.query.filter_by(email=claimed_by_email).first().id
        db.session.add(shift)
        db.session.commit()
        return shift.id


# ---------- Auth ----------

def test_pages_require_login(client):
    response = client.get("/")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_register_stores_hashed_password(app, client):
    register(client)
    with app.app_context():
        user = User.query.filter_by(email="sam@example.com").first()
        assert user is not None
        assert user.password_hash != "correct-horse-1"
        assert user.check_password("correct-horse-1")


def test_duplicate_email_rejected(client):
    register(client)
    logout(client)
    response = register(client, name="Other")
    assert b"already exists" in response.data


def test_short_password_rejected(client):
    response = register(client, password="short")
    assert b"at least 10 characters" in response.data


def test_wrong_password_gives_generic_message(client):
    register(client)
    logout(client)
    response = login(client, password="wrong-password")
    assert b"Incorrect email or password" in response.data


def test_login_rate_limited_after_five_failures(client):
    register(client)
    logout(client)
    for _ in range(5):
        login(client, password="wrong-password")
    response = login(client)  # correct password, but locked out
    assert response.status_code == 429
    assert b"Too many failed attempts" in response.data


# ---------- Shifts ----------

def test_post_shift(app, client):
    register(client)
    tomorrow = (datetime.now() + timedelta(days=1)).date().isoformat()
    response = client.post("/shifts/new", data={
        "role": "Bakery", "day": tomorrow, "start_time": "09:00", "end_time": "17:00",
    }, follow_redirects=True)
    assert b"Shift posted" in response.data
    with app.app_context():
        assert Shift.query.count() == 1


def test_overnight_shift_ends_next_day(app, client):
    register(client)
    tomorrow = (datetime.now() + timedelta(days=1)).date().isoformat()
    client.post("/shifts/new", data={
        "role": "Night fill", "day": tomorrow, "start_time": "22:00", "end_time": "06:00",
    })
    with app.app_context():
        shift = Shift.query.first()
        assert shift.end - shift.start == timedelta(hours=8)


def test_cannot_post_shift_in_past(client):
    register(client)
    yesterday = (datetime.now() - timedelta(days=1)).date().isoformat()
    response = client.post("/shifts/new", data={
        "role": "Bakery", "day": yesterday, "start_time": "09:00", "end_time": "17:00",
    }, follow_redirects=True)
    assert b"in the past" in response.data


def test_claim_shift(app, client):
    register(client, name="Ali", email="ali@example.com")
    logout(client)
    register(client)
    shift_id = add_shift(app, "ali@example.com")

    response = client.post(f"/shifts/{shift_id}/claim", follow_redirects=True)
    assert b"Shift claimed" in response.data
    with app.app_context():
        assert db.session.get(Shift, shift_id).claimed_by.email == "sam@example.com"


def test_cannot_claim_own_shift(app, client):
    register(client)
    shift_id = add_shift(app, "sam@example.com")
    response = client.post(f"/shifts/{shift_id}/claim", follow_redirects=True)
    assert b"claim your own shift" in response.data


def test_cannot_claim_already_claimed_shift(app, client):
    register(client, name="Ali", email="ali@example.com")
    logout(client)
    register(client, name="Jo", email="jo@example.com")
    logout(client)
    register(client)
    shift_id = add_shift(app, "ali@example.com", claimed_by_email="jo@example.com")

    response = client.post(f"/shifts/{shift_id}/claim", follow_redirects=True)
    assert b"already claimed" in response.data
    with app.app_context():
        assert db.session.get(Shift, shift_id).claimed_by.email == "jo@example.com"


def test_cannot_cancel_someone_elses_shift(app, client):
    register(client, name="Ali", email="ali@example.com")
    logout(client)
    register(client)
    shift_id = add_shift(app, "ali@example.com")

    response = client.post(f"/shifts/{shift_id}/cancel")
    assert response.status_code == 403
    with app.app_context():
        assert db.session.get(Shift, shift_id) is not None


def test_release_claimed_shift(app, client):
    register(client, name="Ali", email="ali@example.com")
    logout(client)
    register(client)
    shift_id = add_shift(app, "ali@example.com", claimed_by_email="sam@example.com")

    client.post(f"/shifts/{shift_id}/release")
    with app.app_context():
        assert db.session.get(Shift, shift_id).claimed_by_id is None


# ---------- Security ----------

def test_csrf_token_required():
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:"})
    response = app.test_client().post("/login", data={
        "email": "sam@example.com", "password": "anything",
    })
    assert response.status_code == 400


def test_security_headers(client):
    response = client.get("/login")
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]


def test_html_in_input_is_escaped(app, client):
    register(client, name="<script>alert(1)</script>", email="ali@example.com")
    logout(client)
    register(client)
    add_shift(app, "ali@example.com")
    response = client.get("/")
    assert b"<script>alert(1)</script>" not in response.data
    assert b"&lt;script&gt;" in response.data
