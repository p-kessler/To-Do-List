from flask import Blueprint, render_template, request, flash, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_required, current_user
from .models import Task
from app import db


# create views blueprint so I can use these routes in the create_app route
views = Blueprint("views", __name__)


@views.route("/", methods=["GET", "POST"])
@login_required
def home():
    if request.method == "POST":
        task = request.form.get("task")
        if len(task) < 1:
            flash("Task is too short!", category="error")
        else:
            new_task = Task(task=task, user_id=current_user.id)
            db.session.add(new_task)
            db.session.commit()
           

    return render_template("home.html", user=current_user)

@views.route("/history")
def history():
    return render_template("history.html")