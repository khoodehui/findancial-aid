from flask import render_template, flash, url_for, redirect, request
from flask_login import login_user, login_required, current_user, logout_user
from app import app, db, bcrypt
from app.forms import LoginForm, RegistrationForm, InsertPlanForm, SearchPlanForm
from app.models import User, Plan


@app.route('/')
def start():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    return render_template('start.html', title="Get Started")


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


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password, favourites="")
        db.session.add(user)
        db.session.commit()
        flash('Account created. You are now able to login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Sign Up', form=form)


@app.route('/home')
@login_required
def home():
    return render_template('home.html', title='Home')


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('start'))


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
    return render_template('search.html', title="Search Plans", form=form, results=results)


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
    print(new_favourites)
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

