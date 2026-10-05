import os
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta

from flask import Flask, abort, flash, redirect, render_template, request, url_for
from flask_login import (LoginManager, current_user, login_required, login_user,
                         logout_user)
from flask_wtf.csrf import CSRFProtect

from forms import LoginForm, RegisterForm, ShiftForm
from models import Shift, User, db

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 10 * 60


def create_app(config=None):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY", "dev-only-change-me"),
        SQLALCHEMY_DATABASE_URI=os.environ.get("DATABASE_URL", "sqlite:///shiftswap.db"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )
    if config:
        app.config.update(config)

    db.init_app(app)
    CSRFProtect(app)

    login_manager = LoginManager(app)
    login_manager.login_view = "login"
    login_manager.login_message_category = "info"

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    # Failed login timestamps per IP address, for rate limiting
    failed_logins = defaultdict(deque)

    def too_many_attempts(ip):
        attempts = failed_logins[ip]
        while attempts and attempts[0] < time.time() - LOCKOUT_SECONDS:
            attempts.popleft()
        return len(attempts) >= MAX_LOGIN_ATTEMPTS

    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        return response

    # ---------- Auth ----------

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if current_user.is_authenticated:
            return redirect(url_for("index"))
        form = RegisterForm()
        if form.validate_on_submit():
            email = form.email.data.lower().strip()
            if User.query.filter_by(email=email).first():
                flash("An account with that email already exists.", "error")
            else:
                user = User(name=form.name.data.strip(), email=email)
                user.set_password(form.password.data)
                db.session.add(user)
                db.session.commit()
                login_user(user)
                flash(f"Welcome, {user.name}!", "success")
                return redirect(url_for("index"))
        return render_template("register.html", form=form)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for("index"))
        form = LoginForm()
        ip = request.remote_addr or "unknown"
        if form.validate_on_submit():
            if too_many_attempts(ip):
                flash("Too many failed attempts. Try again in 10 minutes.", "error")
                return render_template("login.html", form=form), 429
            user = User.query.filter_by(email=form.email.data.lower().strip()).first()
            if user and user.check_password(form.password.data):
                failed_logins.pop(ip, None)
                login_user(user)
                return redirect(url_for("index"))
            failed_logins[ip].append(time.time())
            # Same message either way, so attackers can't tell which emails exist
            flash("Incorrect email or password.", "error")
        return render_template("login.html", form=form)

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        logout_user()
        flash("You've been logged out.", "info")
        return redirect(url_for("login"))

    # ---------- Shifts ----------

    @app.route("/")
    @login_required
    def index():
        open_shifts = (Shift.query
                       .filter(Shift.claimed_by_id.is_(None),
                               Shift.start > datetime.now(),
                               Shift.posted_by_id != current_user.id)
                       .order_by(Shift.start)
                       .all())
        return render_template("index.html", shifts=open_shifts)

    @app.route("/shifts/new", methods=["GET", "POST"])
    @login_required
    def new_shift():
        form = ShiftForm()
        if form.validate_on_submit():
            start = datetime.combine(form.day.data, form.start_time.data)
            end = datetime.combine(form.day.data, form.end_time.data)
            if end <= start:  # overnight shift, finishes the next day
                end += timedelta(days=1)
            if start <= datetime.now():
                flash("That shift has already started.", "error")
            else:
                shift = Shift(role=form.role.data.strip(), start=start, end=end,
                              note=(form.note.data or "").strip(),
                              posted_by_id=current_user.id)
                db.session.add(shift)
                db.session.commit()
                flash("Shift posted.", "success")
                return redirect(url_for("my_shifts"))
        return render_template("new_shift.html", form=form)

    @app.route("/shifts/<int:shift_id>/claim", methods=["POST"])
    @login_required
    def claim_shift(shift_id):
        shift = db.get_or_404(Shift, shift_id)
        if shift.posted_by_id == current_user.id:
            flash("You can't claim your own shift.", "error")
        elif shift.is_past:
            flash("That shift has already started.", "error")
        else:
            # Only claim if nobody else got there first (avoids a race condition)
            updated = (Shift.query
                       .filter_by(id=shift.id, claimed_by_id=None)
                       .update({"claimed_by_id": current_user.id}))
            db.session.commit()
            if updated:
                flash("Shift claimed. It's yours.", "success")
                return redirect(url_for("my_shifts"))
            flash("Someone else has already claimed that shift.", "error")
        return redirect(url_for("index"))

    @app.route("/shifts/<int:shift_id>/cancel", methods=["POST"])
    @login_required
    def cancel_shift(shift_id):
        shift = db.get_or_404(Shift, shift_id)
        if shift.posted_by_id != current_user.id:
            abort(403)
        if shift.is_claimed:
            flash("That shift has been claimed, so it can't be cancelled.", "error")
        else:
            db.session.delete(shift)
            db.session.commit()
            flash("Shift removed.", "info")
        return redirect(url_for("my_shifts"))

    @app.route("/shifts/<int:shift_id>/release", methods=["POST"])
    @login_required
    def release_shift(shift_id):
        shift = db.get_or_404(Shift, shift_id)
        if shift.claimed_by_id != current_user.id:
            abort(403)
        if shift.is_past:
            flash("That shift has already started.", "error")
        else:
            shift.claimed_by_id = None
            db.session.commit()
            flash("You've given the shift back. It's open again.", "info")
        return redirect(url_for("my_shifts"))

    @app.route("/my-shifts")
    @login_required
    def my_shifts():
        posted = (Shift.query.filter_by(posted_by_id=current_user.id)
                  .order_by(Shift.start).all())
        claimed = (Shift.query.filter_by(claimed_by_id=current_user.id)
                   .order_by(Shift.start).all())
        return render_template("my_shifts.html", posted=posted, claimed=claimed)

    @app.errorhandler(403)
    def forbidden(_):
        return render_template("error.html", code=403,
                               message="You don't have permission to do that."), 403

    @app.errorhandler(404)
    def not_found(_):
        return render_template("error.html", code=404,
                               message="That page doesn't exist."), 404

    with app.app_context():
        db.create_all()

    return app


if __name__ == "__main__":
    create_app().run(debug=True)
