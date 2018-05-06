import sys
import argparse
from flask import Flask, render_template, request, flash, \
                    redirect, Response, url_for, abort
from urllib.parse import urlparse, urljoin
from flask_login import LoginManager, UserMixin, current_user, \
                            AnonymousUserMixin, login_required, \
                            login_user, logout_user
from flask_wtf import FlaskForm
from wtforms import Form, StringField, PasswordField, \
                        SubmitField, validators
from flask_sqlalchemy import SQLAlchemy
import bcrypt

app = Flask(__name__)
app.secret_key = "update_me"

# flask-login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# setup flask sqlalchemy
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
db = SQLAlchemy(app)


class Anonymous(AnonymousUserMixin):
    
    def __init__(self):
        self.username = 'Guest'
login_manager.anonymous_user = Anonymous


class User(UserMixin):

    def __init__(self, id):
        user_data = DBUser.query.filter_by(id=id).first()
        self.id = id
        self.name = user_data.username
        self.email = user_data.email
        
    
    def __repr__(self):
        return "%d/%s/%s" % (self.id, self.name, self.email)



# setup the database model
class Posts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'),
        nullable=False)
    user = db.relationship('DBUser',
        backref=db.backref('posts', lazy=True))


# the user table structure 
class DBUser(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), unique=False, nullable=False)

    def __repr__(self):
        return "<DBUser %r>" % self.username


# create the database
def init_db():
    db.create_all()
    user_dict = {
        "admin" : DBUser(username="admin", email="admin@example.com", password=bcrypt.hashpw(b"abc123", bcrypt.gensalt())),
        "guest" : DBUser(username="guest", email="guest@example.com", password=bcrypt.hashpw(b"password", bcrypt.gensalt()))}
    for key, user in user_dict.items():
        print("%s added to the database."% user.username)
        db.session.add(user)
    db.session.commit()


# the flask wtf login form setup and validation
class LoginForm(Form):
    username = StringField("Username", validators=[validators.DataRequired()])
    password = PasswordField("Password", validators=[validators.DataRequired()])
    submit = SubmitField("Login")


class RegistForm(Form):
    username = StringField("Username", validators=[validators.DataRequired()
        ])
    email = StringField("Email", validators=[
        validators.DataRequired(), 
        validators.Email()
        ])
    password = PasswordField("Password", validators=[validators.DataRequired(), 
        validators.EqualTo("vpassword", message="Passwords don't match")
        ])
    vpassword = PasswordField("Verify Password", validators=[
        validators.DataRequired()
        ])
    submit = SubmitField("Register")


class PostForm(Form):
    content = StringField("Post Content", validators=[validators.DataRequired()])
    submit = SubmitField("Submit")


# snippet to check if the url is safe
# http://flask.pocoo.org/snippets/62/
def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ("http", "https") and \
           ref_url.netloc == test_url.netloc


@app.route("/", methods=["GET", "POST"])
def home():
    form = PostForm(request.form)
    if request.method == "POST"  and form.validate():
        #post_user = DBUser(username=current_user.name)
        post = Posts(content=form.content.data, user_id=current_user.id)
        db.session.add(post)
        db.session.commit()

    posts = Posts.query.all()

    return render_template("home.html", form=form, posts=posts)


@app.route("/profile", methods=["GET", "POST"])
def profile():
    return "coming soon"

# register here
@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if current_user.is_anonymous:
        form = RegistForm(request.form)
        if request.method == "POST" and form.validate():
            try:
                user = DBUser(username=form.username.data, 
                    email=form.email.data, 
                    password=bcrypt.hashpw(form.password.data.encode("utf-8"), bcrypt.gensalt()))
                db.session.add(user)
                db.session.commit()
                return redirect(url_for("login"))
            except:
                # need to improve this error handling
                error = "Username or email already in use."
        return render_template("register.html", form=form, error=error)
    else:
        return redirect(url_for("home"))


# login here
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if current_user.is_anonymous:
        form = LoginForm(request.form)
        if request.method == "POST" and form.validate():
            username = form.username.data
            password = form.password.data.encode("utf-8")
            user_data = DBUser.query.filter_by(username=username).first()
            if user_data and bcrypt.checkpw(password, user_data.password):
                user = User(user_data.id)
                login_user(user)
                flash("You were successfully logged in")
                next = request.args.get("next")
                if not is_safe_url(next):
                    return abort(400)

                return redirect(next or url_for("home"))
            else:
                error = "Login failed"
        return render_template("login.html", form=form, error=error)
    else:
        return "Already logged in."


# log the user out
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))


# handle failed login
@app.errorhandler(401)
def page_not_found(e):
    return "Login failed"


# callback to reload the user object        
@login_manager.user_loader
def load_user(userid):
    return User(userid)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Social network feed example in flask.")
    parser.add_argument("-s", "--setup", dest="dbsetup", action="store_true",
                    help="This creates and sets up the base database.")
    parser.add_argument("-r", "--run", dest="run",  action="store_true",
                    help="Start and run the server.")
    parser.add_argument("-d", "--debug", dest="debug",  action="store_true",
                    help="Start the app in debug mode.")
    parser.add_argument("-l", "--listen", dest="host", default="127.0.0.1",
                    help="Where should the server listen. \
                          Defaults to 127.0.0.1.")
    parser.add_argument("-p", "--port", dest="port", default=5000,
                    help="Which port should the server listen on. \
                          Defaults to 5000.")
    # if no args were supplied print help and exit
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit()
    # we have args...let"s do things
    args = parser.parse_args()
    if args.dbsetup and args.run:
        print("Setup and run arguments can't be used at the same time.")
        sys.exit(1)
    if args.dbsetup:
        init_db()
    if args.run:
        app.run(debug=args.debug, host=args.host, port=args.port)