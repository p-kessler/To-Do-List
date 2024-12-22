from flask_login import LoginManager, login_required
from flask_sqlalchemy import SQLAlchemy
from os import path
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask import Flask, flash, redirect, render_template, request, session, url_for, jsonify
from models import db, Users, Tasks
import secrets
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.security import generate_password_hash, check_password_hash

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





# Landing page
@app.route("/")
def index():
    return render_template("index.html")

# Log user out
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))



# Registering for an account
@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    else:

        if request.method == "POST":
            # Assign variables with data submitted

            # Convert email to lowercase to avoid case sensitivity
            email = request.form.get("email").lower()
            first_name = request.form.get("first_name").capitalize()
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

            else:
                #try adding user to db
                try:
                    # Hash entered password
                    hashed_password = generate_password_hash(password)

                    # Create new user and log them in
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


# Logging in
@app.route("/login", methods=["GET", "POST"])
def login():

    # if user is already logged in it redirects them to their home page
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

            # If user exists then log them in
            if user:
                if check_password_hash(user.password, password):
                    login_user(user, remember=True)
                    return redirect(url_for("home"))
                else:
                    flash("Incorrect password.", category="error")
                    return render_template("login.html", email=email)
            else:
                flash("There is no account with this email address.", category="error")
                return render_template("login.html", email=email)
            
        return render_template("login.html", user=current_user)


# Home page
@app.route("/home", methods=["GET", "POST"])
@login_required
def home():
    if request.method == "POST":
        task = request.form.get("task")
        
        if len(task) < 1:
            flash("Task is too short!", category="error")
            return render_template("home.html")
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

# Account page
@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    return render_template("account.html")

# Makes user accessible in all templates
@app.context_processor
def inject_user():
    return dict(user=current_user)

# Delete Task
@app.route("/delete-task", methods=["DELETE"])
def delete_task():
    data = request.get_json()
    task_id = data['id']
    task = Tasks.query.get(task_id)
    if task:
        try:
            db.session.delete(task)
            db.session.commit()
        except SQLAlchemyError as e:
            db.session.rollback()
            flash(f"Error deleting task: {str(e)}", category="error")
            return render_template("home.html")            


    return jsonify({'success': True})

# Marks task complete
@app.route("/mark-complete", methods=["PUT"])
def mark_complete():
    data = request.get_json()
    task_id = data['id']
    task = Tasks.query.get(task_id)

    if task:
        try:
            task.status = "complete"
            db.session.commit()
        except SQLAlchemyError as e:
            db.session.rollback()
            flash(f"Error marking task complete: {str(e)}", category="error")
            return render_template("home.html")      
    
    return jsonify({'success': True})

# Change password
@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":

        # Assign variables with data submitted
        email = request.form.get("email")
        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")
        confirmation = request.form.get("confirmation")
        # Check for empty fields
        if not all([email, current_password, new_password, confirmation]):
            flash("Please complete all fields.", category="error")
            return render_template("change-password.html", email=email)
        
        # Check if new password match
        if not new_password == confirmation:
            flash("New password do not match.", category="error")
            return render_template("change-password.html", email=email)
        
        user = Users.query.filter_by(email=email).first()

        # Change users password
        if user and user.email == email:
            if check_password_hash(user.password, current_password):
                try:
                    user.password = generate_password_hash(new_password)
                    db.session.commit()
                    flash("Password changed successfully", category="success")
                    return redirect(url_for("account"))
                except SQLAlchemyError as e:
                    db.session.rollback()
                    flash(f"Error changing password: {str(e)}", category="error")
                    return render_template("change-password.html", email=email)   
            else:
                flash("Incorrect password", category="error")
                render_template("change-password.html", email=email)
        else:
                flash("No account with this email address", category="error")
                render_template("change-password.html", email=email)


    return render_template("change-password.html")

# Delete account
@app.route("/delete-account", methods=["GET", "POST"])
@login_required
def delete_account():
    if request.method == "POST":

        # Assign variables with data submitted
        email = request.form.get("email")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Check for empty fields
        if not all([email, password, confirmation]):
            flash("Please complete all fields.", category="error")
            return render_template("delete-account.html", email=email)
        
        # Check if new password match
        if not password == confirmation:
            flash("Passwords do not match.", category="error")
            return render_template("delete-account.html", email=email)
        
        user = Users.query.filter_by(email=email).first()

        if user:
            if check_password_hash(user.password, password):
                # Delete users account and redirect to landing page
                try:
                    db.session.delete(user)
                    db.session.commit()
                    logout_user()
                    flash("Account successfully deleted.", category="success")
                    return redirect(url_for("index"))
                except SQLAlchemyError as e:
                    db.session.rollback()
                    flash(f"Error deleting account: {str(e)}", category="error")
                    return render_template("delete-account.html", email=email) 
            else:
                flash("Incorrect password", category="error")
                render_template("delete-account.html", email=email)
        else:
                flash("No account with this email address", category="error")
                render_template("delete-account.html", email=email)

    return render_template("delete-account.html")


if __name__ == "__main__":
    # Create database
    with app.app_context():
        db.create_all()
    app.run(debug=True)


