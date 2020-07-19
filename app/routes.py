from threading import Thread
from flask import render_template, flash, url_for, redirect, request, session
from flask_login import login_user, login_required, current_user, logout_user
from flask_mail import Message
from app import app, db, bcrypt, mail
from app.forms import LoginForm, RegistrationForm, InsertPlanForm, SearchPlanForm, RequestResetForm, ResetPasswordForm
from app.models import User, Plan
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer


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
    msg = Message('Password Reset Request', sender='noreply@demo.com', recipients=[user.email])
    msg.body = f'''To reset your password, click on the following link:
{url_for('reset_token', token=token, _external=True)}

If you did not make this request, please ignore this email. No changes will be made to your account.
'''
    thr = Thread(target=send_async_email, args=[msg])
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
        return redirect(url_for('confirm'))
    return render_template('register.html', title='Sign Up', form=form)


def send_confirmation_email(expires_sec=1800):
    s = Serializer(app.config['SECRET_KEY'], expires_sec)
    token = s.dumps({'user_email': session.get('email')}).decode('utf_8')
    msg = Message('Confirm Your Email', sender='noreply@demo.com', recipients=[session.get('email')])
    msg.body = f'''Click on this link to confirm your Email:
{url_for('confirmed', token=token, _external=True)}
    '''
    thr = Thread(target=send_async_email, args=[msg])
    thr.start()


def send_async_email(msg):
    with app.app_context():
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
                    favourites="")
        db.session.add(user)
        db.session.commit()
        session.pop('username')
        session.pop('email')
        session.pop('password')
        login_user(user)
        return render_template('confirm_email_success.html', title='Sign Up')
    else:
        try:
            session.pop('username')
            session.pop('email')
            session.pop('password')
            return "Invalid or Expired Token."
        except:
            return redirect(url_for('invalid_action'))


@app.route('/home')
@login_required
def home():
    return render_template('home2.html', title='Home')


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('start'))


def getFavId():
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
    if form.validate_on_submit():
        keywords = [form.kw1.data, form.kw2.data, form.kw3.data, form.kw4.data, form.kw5.data, form.kw6.data]
        for i in range(6):
            if keywords[i]:
                query = "Plan.query.filter_by(kw" + str(i + 1) + "=True).all()"
                plans = eval(query)
                results.extend(plans)
                results = list(dict.fromkeys(results))
    return render_template('search.html', title="Search Plans", form=form, results=results, fav_id=getFavId())


@app.route('/plan/<string:plan_name>')
@login_required
def view_plan(plan_name):
    plan = Plan.query.filter_by(name=plan_name).first_or_404()
    return render_template('view_plan.html', title=plan.name, plan=plan)


@app.route('/account')
def account():
    return render_template('account.html', title="Account")


@app.route('/account/favourites')
@login_required
def favourites():
    favourited_id = current_user.favourites.split(",")
    favourited_plans = []
    for plan_id in favourited_id:
        if plan_id == "":
            continue
        else:
            plan = Plan.query.get(int(plan_id))
            favourited_plans.append(plan)
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


@app.route('/start2')
def start2():
    return render_template('start2.html', title='Home')
