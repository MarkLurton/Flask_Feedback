"""Flask Feedback Exercise"""

from flask import Flask, render_template, redirect, session, flash
from flask_debugtoolbar import DebugToolbarExtension
from models import connect_db, db, User, Feedback
from forms import RegisterForm, LoginForm, FeedbackForm
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql:///flask_feedback_db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = True
app.config["SECRET_KEY"] = "abc123"
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False


connect_db(app)

toolbar = DebugToolbarExtension(app)

@app.route('/')
def home_page():
    """Render home page"""
    return redirect('/register')

@app.route('/register', methods=['GET', 'POST'])
def register_user():
    """Register user"""
    if session.get('user_username', False):
        return redirect(f'/users/{session["user_username"]}')
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        email = form.email.data
        first_name = form.first_name.data
        last_name = form.last_name.data
        new_user = User.register(username, password, email, first_name, last_name)

        db.session.add(new_user)
        try:
            db.session.commit()
        except IntegrityError:
            form.username.errors.append('Username taken.  Please pick another')
            return render_template('register.html', form=form)
        session['user_username'] = new_user.username
        flash('Welcome! Successfully Created Your Account!', "success")
        return redirect(f'/users/{new_user.username}')

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login_user():
    """Login user"""
    if session.get('user_username', False):
        return redirect(f'/users/{session["user_username"]}')

    form = LoginForm()

    if form.validate_on_submit():
        name = form.username.data
        pwd = form.password.data

        # authenticate will return a user or False
        user = User.authenticate(name, pwd)

        if user:
            session["user_username"] = user.username  # keep logged in
            return redirect(f"/users/{user.username}")

        else:
            form.username.errors = ["Incorrect username/password"]

    return render_template('login.html', form=form)

@app.route('/users/<username>')
def show_secret(username):
    """Show secret"""

    if "user_username" not in session:
        flash('You must log in to access this page.', 'danger')
        return redirect('/login')

    user = User.query.get_or_404(username)
    all_feedback = user.feedback
    return render_template('user_info.html', user=user, feedback=all_feedback)

@app.route('/logout')
def logout_user():
    """Logout user"""
    session.pop('user_username')
    flash('Successfully logged out. See you soon!', 'info')

    return redirect('/login')

@app.route('/users/<username>/delete', methods=['POST'])
def delete_user(username):
    """Delete user"""
    if username != session.get('user_username', None):
        flash('You do not have permission to do this!', 'danger')
        return redirect(f'/users/{username}')
    else:
        user = User.query.get_or_404(username)

        db.session.delete(user)
        db.session.commit()

        session.pop('user_username')
        flash("You have successfully deleted your account. We hope we'll see you again!", "info")

        return redirect('/login')

@app.route('/users/<username>/feedback/add', methods=['GET', 'POST'])
def add_feedback(username):
    """Add feedback"""
    if username != session.get('user_username', None):
        flash('You do not have permission to do this!', 'danger')
        return redirect(f'/users/{username}')
    else:
        form = FeedbackForm()

        if form.validate_on_submit():
            if username != session.get('user_username', None):
                flash('You do not have permission to do this!', 'danger')
                return redirect(f'/users/{username}')

            title = form.title.data
            content = form.content.data

            fb = Feedback(username=username, title=title, content=content)

            db.session.add(fb)
            db.session.commit()

            flash('Feedback successfully added!', 'success')

            return redirect(f'/users/{username}')

            

        return render_template('feedback.html', form=form)

@app.route('/feedback/<feedback_id>/update', methods=['POST', 'GET'])
def update_feedback(feedback_id):
    """Update feedback"""
    fb = Feedback.query.get_or_404(feedback_id)

    if fb.username != session.get('user_username', None):
        flash('You do not have permission to do this!', 'danger')
        return redirect(f'/users/{fb.username}')
    else:
        form = FeedbackForm(obj=fb)

        if form.validate_on_submit():
            if fb.username != session.get('user_username', None):
                flash('You do not have permission to do this!', 'danger')
                return redirect(f'/users/{fb.username}')

            fb.title = form.title.data
            fb.content = form.content.data

            db.session.add(fb)
            db.session.commit()

            flash('Feedback successfully updated!', 'success')

            return redirect(f'/users/{fb.username}')
        
        return render_template('update.html', form=form)

@app.route('/feedback/<feedback_id>/delete', methods=['POST'])
def delete_feedback(feedback_id):
    """Update feedback"""
    fb = Feedback.query.get_or_404(feedback_id)

    if fb.username != session.get('user_username', None):
        flash('You do not have permission to do this!', 'danger')
        return redirect(f'/users/{fb.username}')
    else:
        db.session.delete(fb)
        db.session.commit()

        flash('Feedback successfully deleted!', 'success')

        return redirect(f'/users/{fb.username}')
