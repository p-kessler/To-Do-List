from flask import Blueprint, render_template, request, flash, redirect, url_for
import re
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from app import db
from sqlalchemy.exc import SQLAlchemyError
from flask_login import login_user, login_required, logout_user, current_user


# create auth blueprint so can be used in __init__
auth = Blueprint("auth", __name__)



@auth.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        if not email or not password:
            flash("Please complete all fields.", category="error")
            return render_template("login.html", email=email)
        
        user = User.query.filter_by(email=email).first()

        if user:
            if check_password_hash(user.password, password):
                login_user(user, remember=True)
                return redirect(url_for("views.home"))
            else:
                flash("Incorrect password", category="error")
        else:
            flash("No account with this email address", category="error")
    return render_template("login.html", user=current_user)

@auth.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))


@auth.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":
        # Assign variables with data submitted
        email = request.form.get("email")
        first_name = request.form.get("first_name")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")


        # Check for empty fields
        if not all([email, first_name, password, confirmation]):
            flash("Please complete all fields", category="error")
            return render_template("register.html", email=email, first_name=first_name)
        
        # Check if email already exisits in database
        existing_user = User.query.filter_by(email=email).first()

        if existing_user:
            flash("Email already taken", category="error")
            return render_template("register.html", email=email, first_name=first_name)
        
        # Check if password match and password is at least 7 characters
        if password != confirmation:
            flash("Password do not match.", category="error")
            return render_template("register.html", email=email, first_name=first_name)
        elif len(password) < 7:
            flash("Password must be at least 7 characters", category="error")
            return render_template("register.html", email=email, first_name=first_name)
        
        # Validate email format
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash("Please enter a valid email address.", category="error")
            return render_template("register.html", email=email, first_name=first_name)
        else:

            #try adding user to db
            try:
                # Hash entered password
                hashed_password = generate_password_hash(password)

                # Create new user 
                new_user = User(email=email, first_name=first_name, password=hashed_password)
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user, remember=True)
                flash("Account created successfully!", category="success")
                # return redirect
                
                return redirect(url_for("views.home"))

            except SQLAlchemyError as e:
                db.session.rollback()
                flash(f"Error creating account: {str(e)}", category="error")
                return render_template("register.html", email=email, first_name=first_name)
                

            
    return render_template("register.html", user=current_user)