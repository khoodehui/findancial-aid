from datetime import datetime
from app import db, login_manager, app
from flask_login import UserMixin
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    favourites = db.Column(db.Text())
    unread_announcements = db.Column(db.Text())
    mailing_list = db.Column(db.Boolean())
    not_interested = db.Column(db.Text())

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf_8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"


class Plan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text(), unique=True, nullable=False)
    req_short = db.Column(db.Text(), nullable=False)
    req_full = db.Column(db.Text(), nullable=False)
    benefits_short = db.Column(db.Text(), nullable=False)
    benefits_full = db.Column(db.Text(), nullable=False)
    application = db.Column(db.Text(), nullable=False)
    website = db.Column(db.String(250), nullable=False)
    # PLAN KEYWORDS
    # kw1 = General Aid
    # kw2 = Disability Aid
    # kw3 = Elderly Aid
    # kw4 = Childcare
    # kw5 = Healthcare
    kw1 = db.Column(db.Boolean(), nullable=False)
    kw2 = db.Column(db.Boolean(), nullable=False)
    kw3 = db.Column(db.Boolean(), nullable=False)
    kw4 = db.Column(db.Boolean(), nullable=False)
    kw5 = db.Column(db.Boolean(), nullable=False)

    def __repr__(self):
        return f"Plan Name: {self.name}"


class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.Text(), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.now)
    content = db.Column(db.Text(), nullable=False)

    def __repr__(self):
        return f"Announcement('{self.title}', '{self.date_posted}')"
