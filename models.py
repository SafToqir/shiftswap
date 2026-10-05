from datetime import datetime

from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

db = SQLAlchemy()


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

    def set_password(self, password):
        # Store a salted hash, never the password itself
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Shift(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    role = db.Column(db.String(80), nullable=False)
    start = db.Column(db.DateTime, nullable=False)
    end = db.Column(db.DateTime, nullable=False)
    note = db.Column(db.String(300), default="")
    created_at = db.Column(db.DateTime, default=datetime.now)

    posted_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    claimed_by_id = db.Column(db.Integer, db.ForeignKey("user.id"))

    posted_by = db.relationship("User", foreign_keys=[posted_by_id])
    claimed_by = db.relationship("User", foreign_keys=[claimed_by_id])

    @property
    def is_claimed(self):
        return self.claimed_by_id is not None

    @property
    def is_past(self):
        return self.start <= datetime.now()

    @property
    def hours(self):
        return round((self.end - self.start).total_seconds() / 3600, 1)
