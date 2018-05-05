import sys
import argparse
from flask import Flask, render_template, request
from flask_wtf import FlaskForm
from wtforms import Form, StringField, PasswordField, \
                        SubmitField, validators
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS

app = Flask(__name__)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
db = SQLAlchemy(app)

CORS(app)


# setup the database model
class Posts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text, nullable=False)
    content = db.Column(db.Text, nullable=False)


# create the database
def init_db():
    db.create_all()


# create the form
class PostForm(Form):
    name = StringField("Name", validators=[validators.DataRequired()])
    content = StringField("Post Content", validators=[validators.DataRequired()])
    submit = SubmitField("Submit")

@app.route("/", methods=["GET", "POST"])
def index():
    form = PostForm(request.form)
    if request.method == "POST"  and form.validate():
        post = Posts(name=form.name.data,
                    content=form.content.data)
        db.session.add(post)
        db.session.commit()

    posts = Posts.query.all()

    return render_template("index.html", form=form, posts=posts)

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