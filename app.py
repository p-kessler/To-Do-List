from flask_login import LoginManager, login_required
from flask_sqlalchemy import SQLAlchemy
from os import path
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask import Flask, flash, redirect, render_template, request, session, url_for, jsonify
from models import db, Users, Tasks
import secrets
import re
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.security import generate_password_hash, check_password_hash
import json

app = Flask(__name__)
app.config["SECRET_KEY"] = secrets.token_hex(16)

# Configure database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db.init_app(app)

# Configure login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(id):
    return db.session.get(Users, int(id))





@app.route("/")
def index():
    return render_template("index.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))



# Route for registering an account
@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    else:

        if request.method == "POST":
            # Assign variables with data submitted
            email = request.form.get("email")
            first_name = request.form.get("first_name")
            password = request.form.get("password")
            confirmation = request.form.get("confirmation")


            # Check for empty fields
            if not all([email, first_name, password, confirmation]):
                flash("Please complete all fields.", category="error")
                return render_template("register.html", email=email, first_name=first_name)

            # Check if email already exisits in database
            existing_user = Users.query.filter_by(email=email).first()

            if existing_user:
                flash("Email already taken.", category="error")
                return render_template("register.html", email=email, first_name=first_name)

            # Check if password match and password is at least 7 characters
            if password != confirmation:
                flash("Passwords do not match.", category="error")
                return render_template("register.html", email=email, first_name=first_name)
            elif len(password) < 7:
                flash("Password must be at least 7 characters.", category="error")
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
                    new_user = Users(email=email, first_name=first_name, password=hashed_password)
                    db.session.add(new_user)
                    db.session.commit()
                    login_user(new_user, remember=True)
                    flash("Account created successfully!", category="success")
                    # return redirect

                    return redirect(url_for("home"))

                except SQLAlchemyError as e:
                    db.session.rollback()
                    flash(f"Error creating account: {str(e)}", category="error")
                    return render_template("register.html", email=email, first_name=first_name)



        return render_template("register.html", user=current_user)


# Route for logging in to account
@app.route("/login", methods=["GET", "POST"])
def login():

    if current_user.is_authenticated:
        return redirect(url_for("home"))
    else:

        # Forget any user_id
        session.clear()
        if request.method == "POST":
            email = request.form.get("email")
            password = request.form.get("password")

            if not email or not password:
                flash("Please complete all fields.", category="error")
                return render_template("login.html", email=email)

            user = Users.query.filter_by(email=email).first()

            if user:
                if check_password_hash(user.password, password):
                    login_user(user, remember=True)
                    return redirect(url_for("home"))
                else:
                    flash("Incorrect password", category="error")
            else:
                flash("No account with this email address", category="error")
        return render_template("login.html", user=current_user)




# Route for home page
@app.route("/home", methods=["GET", "POST"])
@login_required
def home():
    if request.method == "POST":
        task = request.form.get("task")
        
        if len(task) < 1:
            flash("Task is too short!", category="error")
        else:
            try:
                new_task = Tasks(task=task, user_id=current_user.id)
                db.session.add(new_task)
                db.session.commit()

                # Redirect so when page is refreshed it doesn't duplicate task
                return redirect(url_for("home"))
            except SQLAlchemyError as e:
                db.session.rollback()
                flash(f"Error adding task: {str(e)}", category="error")
                return render_template("home.html", task=task)


    
    return render_template("home.html")

@app.route("/account", methods=["GET", "POST"])
def account():
    return render_template("account.html")

# Makes user accessible in all templates
@app.context_processor
def inject_user():
    return dict(user=current_user)

@app.route("/delete-task", methods=["DELETE"])
def delete_task():
    data = request.get_json()
    task_id = data['id']
    task = Tasks.query.get(task_id)
    if task:
        db.session.delete(task)
        db.session.commit()

    return jsonify({'success': True})

@app.route("/mark-complete", methods=["PUT"])
def mark_complete():
    data = request.get_json()
    task_id = data['id']
    task = Tasks.query.get(task_id)

    if task:
        task.status = "complete"
        db.session.commit()
    
    return jsonify({'success': True})


if __name__ == "__main__":
    # Create database
    with app.app_context():
        db.create_all()
    app.run(debug=True)







    # task = json.loads(request.data)
    # task_id = task["task_id"]
    # task = Tasks.query.get(task_id)

    # if task:
    #     if task.user_id == current_user.id:
    #         db.session.delete(task)
    #         db.session.commit()
    #         return  jsonify({})