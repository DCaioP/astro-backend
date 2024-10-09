from app.models import User
from app import db
from functools import wraps
from app.forms import LoginForm
from flask import render_template, request, redirect, url_for, flash, abort
from flask_mail import Mail, Message
from flask_login import login_required, logout_user, current_user, login_user, login_manager
from flask_jwt_extended import create_access_token
from werkzeug.security import generate_password_hash, check_password_hash


def business_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.account_type != 'business':
            abort(403)
        return f(*args, **kwargs)

    return decorated_function


def personal_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.account_type != 'personal':
            abort(403)
        return f(*args, **kwargs)

    return decorated_function


def init_app(app):
    mail = Mail(app)

    @app.route("/")
    def principal():
        return render_template("index/index.html")

    @app.route("/job")
    def emprego():
        return render_template("index/job.html")

    @app.route("/employee")
    def funcionario():
        return render_template("index/employee.html")

    @app.route("/job_details")
    def detalhes_funcionario():
        return render_template("index/job_details.html")

    @app.route("/about")
    def sobre():
        return render_template("index/about.html")

    @app.route("/contact")
    def contato():
        return render_template("index/contact.html")

    @app.route("/home_business")
    @login_required
    @business_required
    def home_business():
        return render_template("home_business/home.html")

    @app.route("/home_personal")
    @login_required
    @personal_required
    def home_personal():
        return render_template("home_personal/home.html")

    @app.route("/signin", methods=["GET", "POST"])
    def signin():

        if request.method == "POST":
            name_user = request.form["name"]
            email_user = request.form["email"]
            user = User()
            user.name = request.form["name"]
            user.account_type = request.form["account_type"]
            user.email = request.form["email"]
            db.session.add(user)
            db.session.commit()
            token = create_access_token(identity=user.email)
            user.token = token
            db.session.commit()

            msg = Message(
                subject="Bem vindo(a) ao Job Finder",
                sender=app.config["MAIL_DEFAULT_SENDER"],
                recipients=[email_user],
                html=render_template("email/email.html", nome_user=name_user, email_user=email_user, email_send=User.query.filter_by(email=email_user).first())
            )
            mail.send(msg)

            return redirect(url_for("login"))
        return render_template("index/signin_v2.html")

    @app.route("/register_password/<int:user_id>", methods=["GET", "POST"])
    def registro(user_id):
        reg = User.query.filter_by(user_id=user_id).first()
        if request.method == "POST":
            password = request.form["password"]
            password_repeat = request.form["password_repeat"]
            if password == password_repeat:
                cripto_password = generate_password_hash(password)
                reg.query.filter_by(user_id=user_id).update({"password": cripto_password})
                db.session.commit()
                flash("Senha criado com sucesso!")
                return redirect("../login")
            else:
                flash("Os dois campos de password devem ser iguais!")

        return render_template("email/register.html", reg=reg)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        form = LoginForm()

        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()

            if not user:
                flash("Email do usuário incorreto, por favor verifique!")
                return redirect(url_for("login"))

            elif not check_password_hash(user.password, form.password.data):
                flash("Senha de usuário incorreta, por favor verifique")
                return redirect(url_for("login"))

            login_user(user)
            if user.account_type == 'business':
                return redirect(url_for("home_business"))
            elif user.account_type == 'personal':
                return redirect(url_for("home_personal"))
            else:
                flash("Tipo de conta não reconhecido")
                return redirect(url_for("login"))

        return render_template("index/login.html", form=form)

    @app.route("/register_job", methods=["GET", "POST"])
    @login_required
    @business_required
    def register_job():
        if request.method == "POST":
            user = User()
            user.email = request.form["email"]
            user.nome = request.form["nome"]
            user.senha = generate_password_hash(request.form["senha"])
            db.session.add(user)
            db.session.commit()

            flash("Usuario criado com sucesso!")
            return redirect(url_for("cad_user"))
        return render_template("cad_user.html")

    @app.route("/logout")
    @login_required
    def logout():
        logout_user()
        return redirect(url_for("principal"))