from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO, emit
import os
from datetime import datetime
from flask_migrate import Migrate
import csv
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Enable Cross-Origin Resource Sharing (CORS)

# Setup SocketIO for real-time communication
socketio = SocketIO(app)

# Configure SQLite database path
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SECRET_KEY'] = 'DLP_secret_key'  # Secret key for session management
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'dlp.db')  # SQLite DB URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable modification tracking for performance

# Initialize SQLAlchemy for database handling
db = SQLAlchemy(app)

# Setup Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Redirect to login page if user isn't authenticated

# Setup Flask-Migrate for database migrations
migrate = Migrate(app, db)

# Violation model represents a violation record in the system
class Violation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(80), nullable=False)  # User associated with the violation
    violation = db.Column(db.String(200), nullable=False)  # Description of the violation
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)  # Timestamp of violation
    url = db.Column(db.String(200), nullable=True)  # URL involved in the violation
    method = db.Column(db.String(10), nullable=True)  # HTTP method (GET, POST, etc.)

    def __repr__(self):
        return f"<Violation {self.violation}>"

# User class for mock users; integrates with Flask-Login
class User(UserMixin):
    def __init__(self, username, role):
        self.id = username  # User ID
        self.role = role  # User role (e.g., admin, user)

# Function to load users from a CSV file for authentication
def load_users_from_csv():
    users = {}
    try:
        with open('users.csv', mode='r') as file:  # Open the CSV file
            csv_reader = csv.DictReader(file)
            for row in csv_reader:
                # Store each user with their username, password, and role
                users[row['username']] = {'password': row['password'], 'role': row['role']}
    except FileNotFoundError:
        print("Error: users.csv not found.")
    return users

# Flask-Login user loader, loads user by username
@login_manager.user_loader
def load_user(username):
    users = load_users_from_csv()  # Load users from CSV
    if username in users:
        user = User(username, users[username]['role'])
        return user
    return None

# Login route to handle user authentication
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Load users from CSV
        users = load_users_from_csv()
        
        # Check if username and password match
        if username in users and users[username]['password'] == password:
            user = User(username, users[username]['role'])
            login_user(user)  # Log the user in
            flash('Login successful', 'success')
            return redirect(url_for('dashboard'))  # Redirect to dashboard after login
        else:
            flash('Invalid credentials', 'danger')  # Show error for invalid credentials
    return render_template('login.html')

# Logout route to handle user logouts
@app.route('/logout')
@login_required  # Only allow access to logged-in users
def logout():
    logout_user()  # Log the user out
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

# Dashboard route (restricted to admin users only)
@app.route('/dashboard')
@login_required
def dashboard():
    # Check if the current user is an admin
    if current_user.role != 'admin':
        flash('You do not have access to this page.', 'danger')
        return redirect(url_for('login'))  # Redirect if not authorized
    return render_template('dashboard.html')

# Route to fetch violations data with filters (supports filtering by user, violation, url, method, and date range)
@app.route('/violations_data')
def violations_data():
    user_filter = request.args.get('user')  # Filter by user
    violation_filter = request.args.get('violation')  # Filter by violation
    url_filter = request.args.get('url')  # Filter by URL
    method_filter = request.args.get('method')  # Filter by HTTP method
    start_date = request.args.get('start_date')  # Start date filter
    end_date = request.args.get('end_date')  # End date filter

    query = Violation.query  # Base query for violations

    # Apply filters based on user input
    if user_filter:
        query = query.filter(Violation.user.ilike(f'%{user_filter}%'))  # Case-insensitive user filter
    if violation_filter:
        query = query.filter(Violation.violation.ilike(f'%{violation_filter}%'))  # Violation filter
    if url_filter:
        query = query.filter(Violation.url.ilike(f'%{url_filter}%'))  # URL filter
    if method_filter:
        query = query.filter(Violation.method.ilike(f'%{method_filter}%'))  # HTTP method filter
    if start_date and end_date:
        # Convert strings to date objects and filter by date range
        start_date_obj = datetime.strptime(start_date, '%Y-%m-%d')
        end_date_obj = datetime.strptime(end_date, '%Y-%m-%d')
        query = query.filter(Violation.timestamp.between(start_date_obj, end_date_obj))

    violations = query.all()  # Execute query and get all matching records

    # Convert violations to a list of dictionaries (including URL and method)
    data = [{
        "id": v.id,
        "user": v.user,
        "violation": v.violation,
        "timestamp": v.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        "url": v.url,
        "method": v.method
    } for v in violations]
    
    return jsonify(data)  # Return data as JSON

# Route to log a new violation and notify all connected clients via WebSocket
@app.route('/log_violation', methods=['POST'])
def log_violation():
    data = request.json
    user = data.get('user')
    violation = data.get('violation')

    # Create and save a new violation in the database
    new_violation = Violation(user=user, violation=violation)
    db.session.add(new_violation)
    db.session.commit()

    # Emit real-time update to all connected clients using WebSocket
    violations = Violation.query.all()
    data = [{"id": v.id, "user": v.user, "violation": v.violation, "timestamp": v.timestamp.strftime('%Y-%m-%d %H:%M:%S')} for v in violations]
    socketio.emit('violation_update', data)  # Send data to all clients

    return jsonify({"message": "Violation logged", "user": user}), 201

# Route to display the violation response page
@app.route('/violation_page')
def violation_page():
    return render_template('violation_response.html')  # Render the violation page

# Main entry point for the application
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create database tables if they don't exist
    socketio.run(app, debug=True)  # Run the app with SocketIO and debug mode enabled
