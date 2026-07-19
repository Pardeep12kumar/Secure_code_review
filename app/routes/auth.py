from flask import (
    Blueprint,
    render_template,
    redirect,
    url_for,
    flash,
    request
)

from flask_login import (
    login_user,
    logout_user,
    login_required,
    current_user
)

from app.forms.login_form import LoginForm
from app.forms.register_form import RegisterForm

from app import db, bcrypt

from models.user import User

auth = Blueprint(
    "auth",
    __name__,
    url_prefix="/auth"
)


@auth.route("/register", methods=["GET", "POST"])
def register():

    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    form = RegisterForm()

    print("Request Method:", request.method)

    if request.method == "POST":
        print("Form Data:", request.form)
        print("Validation:", form.validate())
        print("Errors:", form.errors)

    if form.validate_on_submit():

        print("Registration Successful")

        username = form.username.data.strip()
        email = form.email.data.strip().lower()

        user = User.query.filter_by(
            username=username
        ).first()

        if user:
            flash(
                "Username already exists.",
                "danger"
            )
            return render_template(
                "register.html",
                form=form
            )

        email_user = User.query.filter_by(
            email=email
        ).first()

        if email_user:
            flash(
                "Email already registered.",
                "danger"
            )
            return render_template(
                "register.html",
                form=form
            )

        hashed_password = bcrypt.generate_password_hash(
            form.password.data
        ).decode("utf-8")

        new_user = User(
            username=username,
            email=email,
            password=hashed_password
        )

        db.session.add(new_user)
        db.session.commit()

        flash(
            "Registration successful. Please login.",
            "success"
        )

        return redirect(
            url_for("auth.login")
        )

    return render_template(
        "register.html",
        form=form
    )


@auth.route("/login", methods=["GET", "POST"])
def login():

    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    form = LoginForm()

    if form.validate_on_submit():

        user = User.query.filter_by(
            email=form.email.data.lower().strip()
        ).first()

        if user and bcrypt.check_password_hash(
            user.password,
            form.password.data
        ):

            login_user(
                user,
                remember=form.remember.data
            )

            flash(
                "Welcome back!",
                "success"
            )

            return redirect(
                url_for("main.dashboard")
            )

        flash(
            "Invalid email or password.",
            "danger"
        )

    return render_template(
        "login.html",
        form=form
    )


@auth.route("/logout")
@login_required
def logout():

    logout_user()

    flash(
        "You have been logged out.",
        "info"
    )

    return redirect(
        url_for("auth.login")
    )
