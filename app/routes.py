from threading import Thread
from flask import render_template, flash, url_for, redirect, request, session
from flask_login import login_user, login_required, current_user, logout_user
from flask_mail import Message
from app import app, db, bcrypt, mail
from app.forms import LoginForm, RegistrationForm, InsertPlanForm, SearchPlanForm, RequestResetForm, ResetPasswordForm, \
    SendMailForm
from app.models import User, Plan, Announcement
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from sqlalchemy import or_
from sqlalchemy.testing import in_
from flask_paginate import Pagination, get_page_parameter


@app.route('/')
def start():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    return render_template('start2.html', title="Get Started")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('home'))
        else:
            flash('Incorrect email or password.', 'danger')
    return render_template('login.html', title='Log In', form=form)


def send_reset_email(user):
    token = user.get_reset_token()
    title = 'Password Reset Request'
    recipients = [user.email]
    msg_body = f'''To reset your password, click on the following link:
{url_for('reset_token', token=token, _external=True)}

If you did not make this request, please ignore this email. No changes will be made to your account.
'''
    thr = Thread(target=send_async_email, args=[title, recipients, msg_body, ""])
    thr.start()


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('invalid_action'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        return render_template('reset_password_token_sent.html', title="Reset Password", email=form.email.data)
    return render_template('reset_password.html', title="Reset Password", form=form)


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('invalid_action'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('Invalid or expired token. Please try again.', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash('Password has been reset.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password_token_valid.html', title='Reset Password', form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        session['username'] = form.username.data
        session['email'] = form.email.data
        session['password'] = hashed_password
        session['receive_email'] = form.receive_email.data
        return redirect(url_for('confirm'))
    return render_template('register.html', title='Sign Up', form=form)


def send_confirmation_email(expires_sec=1800):
    s = Serializer(app.config['SECRET_KEY'], expires_sec)
    token = s.dumps({'user_email': session.get('email')}).decode('utf_8')
    msg_body = f'''Click on this link to confirm your Email:
{url_for('confirmed', token=token, _external=True)}
    '''
    title = 'Confirm Your Email'
    recipients = [session.get('email')]
    thr = Thread(target=send_async_email, args=[title, recipients, msg_body, ""])
    thr.start()


def send_async_email(title, recipients, msg_body="", msg_html=""):
    with app.app_context():
        msg = Message(title, sender='noreply@demo.com', recipients=recipients)
        msg.body = msg_body
        msg.html = msg_html
        mail.send(msg)


def verify_confirmation_token(token):
    s = Serializer(app.config['SECRET_KEY'])
    try:
        email = s.loads(token)['user_email']
    except:
        return False
    return email == session.get('email')


@app.route('/signup/confirm')
def confirm():
    send_confirmation_email()
    return render_template('confirm_email_token_sent.html', title='Sign Up')


@app.route('/signup/confirm/<token>')
def confirmed(token):
    if verify_confirmation_token(token):
        user = User(username=session.get('username'), email=session.get('email'), password=session.get('password'),
                    favourites="", unread_announcements="", mailing_list=session.get('receive_email'))
        db.session.add(user)
        db.session.commit()
        session.pop('username')
        session.pop('email')
        session.pop('password')
        session.pop('receive_email')
        login_user(user)
        return render_template('confirm_email_success.html', title='Sign Up')
    else:
        try:
            session.pop('username')
            session.pop('email')
            session.pop('password')
            session.pop('receive_email')
            return render_template('confirm_email_token_error.html', title='Sign Up')
        except:
            return redirect(url_for('invalid_action'))


@app.route('/home')
@login_required
def home():
    unread_announcements_count = len(current_user.unread_announcements.split(",")) - 1
    return render_template('home2.html', title='Home', unread_count=unread_announcements_count)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('start'))


def get_fav_id():
    fav_id_str = current_user.favourites.split(",")
    fav_id_int = []

    for id in fav_id_str:
        if id == "":
            continue
        else:
            fav_id_int.append(int(id))
    return fav_id_int


@app.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    form = SearchPlanForm()
    results = []
    query_kw = []
    if form.validate_on_submit():
        all_kw = [Plan.kw1, Plan.kw2, Plan.kw3, Plan.kw4, Plan.kw5, Plan.kw6]
        keywords = [form.kw1.data, form.kw2.data, form.kw3.data, form.kw4.data, form.kw5.data, form.kw6.data]
        for i in range(6):
            if keywords[i]:
                query_kw.append(all_kw[i])
        results = db.session.query(Plan).filter(or_(*query_kw, None)).all()
    return render_template('search.html', title="Search Plans", form=form, results=results, fav_id=get_fav_id())


@app.route('/plan/<string:plan_name>')
@login_required
def view_plan(plan_name):
    plan = Plan.query.filter_by(name=plan_name).first_or_404()
    return render_template('view_plan.html', title=plan.name, plan=plan)


@app.route('/account')
def account():
    return render_template('account.html', title="Account")


@app.route('/favourites')
@login_required
def favourites():
    fav_id = get_fav_id()
    favourited_plans = db.session.query(Plan).filter(Plan.id.in_(fav_id)).all()
    return render_template('favourites.html', title="Favourites", plans=favourited_plans)


@app.route('/error')
def invalid_action():
    return render_template('invalid_action.html', title='Error')


@app.route('/background_process_favourite/<string:plan_id>')
@login_required
def background_process_favourite(plan_id):
    favourites = current_user.favourites
    if plan_id not in favourites.split(","):
        current_user.favourites = favourites + "," + plan_id
        db.session.commit()
    return ""


@app.route('/background_process_remove_favourite/<string:plan_id>')
@login_required
def background_process_remove_favourite(plan_id):
    new_favourites = current_user.favourites.replace("," + plan_id, "")
    current_user.favourites = new_favourites
    db.session.commit()
    return ""


@app.route('/addplan', methods=['GET', 'POST'])
@login_required
def addplan():
    form = InsertPlanForm()
    if form.validate_on_submit():
        plan = Plan(name=form.name.data, req_short=form.req_short.data, req_full=form.req_full.data,
                    benefits_short=form.benefits_short.data, benefits_full=form.benefits_full.data,
                    application=form.application.data, website=form.website.data, kw1=form.kw1.data, kw2=form.kw2.data,
                    kw3=form.kw3.data, kw4=form.kw4.data, kw5=form.kw5.data, kw6=form.kw6.data)
        db.session.add(plan)
        db.session.commit()
        flash('Plan added successfully.')
        return redirect(url_for('addplan'))
    else:
        return render_template('insertplan.html', form=form)


def get_unread_announcements_id():
    ua_id_str = current_user.unread_announcements.split(",")
    ua_id_int = []

    for id in ua_id_str:
        if id == "":
            continue
        else:
            ua_id_int.append(int(id))
    return ua_id_int


@app.route('/post_announcement', methods=['GET', 'POST'])
@login_required
def post_announcement():
    form = SendMailForm()
    if form.validate_on_submit():
        announcement = Announcement(title=form.title.data, content=form.content.data)
        db.session.add(announcement)

        for user in User.query.all():
            user.unread_announcements = user.unread_announcements + "," + str(announcement.id)

        db.session.commit()
        raw_email_data = db.session.query(User.email).filter(User.mailing_list).all()
        msg_html = form.content.data
        title = form.title.data
        recipients = [item[0] for item in raw_email_data]
        thr = Thread(target=send_async_email, args=[title, recipients, "", msg_html])
        thr.start()
        flash("Announcement posted and emails notifications sent.", "success")
        return redirect(url_for('post_announcement'))
    return render_template('post_announcement.html', form=form)


@app.route('/announcements')
def announcements():
    unread_id = get_unread_announcements_id()
    unread = db.session.query(Announcement).filter(Announcement.id.in_(unread_id)).order_by(Announcement.date_posted.desc()).all()
    read = db.session.query(Announcement).filter(~Announcement.id.in_(unread_id)).order_by(Announcement.date_posted.desc()).all()
    unread.extend(read)
    announcements = unread
    page = request.args.get(get_page_parameter(), type=int, default=1)
    per_page = 8
    offset = (page - 1) * per_page
    if len(announcements) > per_page:
        announcements_offset = announcements[offset: offset + per_page]
    else:
        announcements_offset = announcements
    pagination = Pagination(page=page,
                            total=len(announcements),
                            record_name='users',
                            per_page=per_page,
                            css_framework='bootstrap4',
                            alignment='center')
    return render_template('announcements.html', title='Announcements', announcements=announcements_offset,
                           pagination=pagination, unread=unread_id)


@app.route('/background_process_read_announcement/<string:announcement_id>')
@login_required
def background_process_read_announcement(announcement_id):
    current_user.unread_announcements = current_user.unread_announcements.replace("," + announcement_id, "")
    db.session.commit()
    return ""
