# DATAProX - Data Loss Prevention (DLP) System

## Project Overview

**DATAProX** is a Data Loss Prevention (DLP) system designed to monitor and block the transmission of sensitive data and malicious files within HTTP requests. It works by identifying sensitive patterns (e.g., emails, credit card numbers) and known malicious file hashes in web traffic, logging violations, and preventing the transmission of these requests.

## Features

- **Real-Time HTTP Traffic Monitoring**: Inspects HTTP requests and checks for sensitive data patterns or malicious files.
- **Violation Logging**: Logs violations of sensitive data detection or malicious file uploads into a centralized server using Flask.
- **WebSocket Updates**: Real-time violation updates are pushed to the dashboard using WebSocket for a live feed of violations.
- **File Upload Monitoring**: Analyzes uploaded files and blocks them if they match known malicious hashes.
- **Admin Dashboard**: A web-based admin dashboard that allows administrators to view and filter violations in real-time.
- **User Authentication**: Provides a login system for administrators, allowing only authorized users to access the dashboard.

## Installation and Setup

### Prerequisites
- **Python 3.x**
- **Flask**
- **Flask-SocketIO**
- **SQLite** (or another database of your choice)
- **mitmproxy**

### Steps to Install

1. **Clone the Repository**:
  ``` git clone https://github.com/muhammadumar-usman/DATAProX.git```
   ```cd DATAProX```

2.	Install Dependencies:
o	Install the required Python packages:
```pip install -r requirements.txt```

3.	Database Setup:
o	Initialize the SQLite database:
```flask db init```
```flask db migrate```
```flask db upgrade```

4.	Run the Flask App:
o	Start the Flask server:
```flask run```

5.	Start mitmproxy:
o	Start mitmproxy to monitor traffic:
```mitmproxy --mode transparent --script your_script.py```

### File Structure
```
DATAProX/
│
├── app.py                 # Main Flask application file
├── dlp.db                 # SQLite database file (auto-generated)
├── requirements.txt       # Python dependencies
├── templates/             # HTML files for Flask
│   ├── login.html         # Admin login page
│   ├── dashboard.html     # Dashboard for viewing violations
│   └── violation_response.html  # Violation response page
├── static/                # Static assets (CSS, JS, images)
│   └── logo.png           # Logo image
├── users.csv              # CSV file containing user credentials
├── patterns.txt           # Patterns file for sensitive data detection
└── known_hashes.txt       # List of known malicious file hashes
```

### Usage
1.	Login:
o	Open the web app by navigating to http://localhost:5000/login.
o	Use the admin credentials from the users.csv file to log in.
2.	View Violations:
o	After login, access the dashboard to see real-time violations.
o	Violations can be filtered by user, URL, method, or time range.
3.	Monitor Traffic:
o	Use mitmproxy to intercept traffic and send requests to the Flask backend.

### Contributing
Contributions are welcome! Please open an issue or submit a pull request for any enhancements or bug fixes.

