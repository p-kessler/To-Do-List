from flask import Blueprint, render_template, request, flash, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_required, current_user


# create views blueprint so I can use these routes in the create_app route
views = Blueprint("views", __name__)


@views.route("/")
@login_required
def home():
    return render_template("home.html")

@views.route("/history")
def history():
    return render_template("history.html")