from mitmproxy import http
import hashlib
import requests
import re

# Function to load sensitive data patterns and their categories from the external file
def load_patterns(file_path):
    try:
        with open(file_path, 'r') as f:
            patterns = []
            # Read each line from the file
            for line in f:
                if line.strip() and not line.startswith('#'):  # Ignore empty lines and comments
                    parts = line.split(',')  # Split each line by comma (pattern, category)
                    if len(parts) == 2:
                        pattern = parts[0].strip()  # Extract regex pattern
                        category = parts[1].strip()  # Extract category like "Email", "Credit Card"
                        patterns.append((pattern, category))  # Add tuple to the list
            return patterns  # Return the list of patterns
    except FileNotFoundError:
        print(f"Error: The file {file_path} was not found.")
        return []

# Function to load known file hashes from an external file
def load_known_hashes(file_path):
    try:
        with open(file_path, 'r') as f:
            # Return a list of known hashes (one hash per line)
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: The file {file_path} was not found.")
        return []

# Function to calculate the hash (e.g., SHA-256) of a file
def calculate_file_hash(file_data):
    sha256 = hashlib.sha256()  # Create a new SHA-256 hash object
    sha256.update(file_data)  # Update it with the file data
    return sha256.hexdigest()  # Return the hexadecimal digest of the hash

def request(flow: http.HTTPFlow) -> None:
    # Load sensitive data patterns (regex and category) from the external file
    sensitive_data_patterns = load_patterns('patterns.txt')

    # Load known file hashes (pre-determined list of malicious file hashes)
    known_hashes = load_known_hashes('known_hashes.txt')

    # Check if the request contains a file upload (identified by "multipart/form-data" in headers)
    if "multipart/form-data" in flow.request.headers.get("Content-Type", ""):
        multipart_data = flow.request.multipart_form  # Parse the multipart form data

        # Iterate through each file in the multipart form data
        for key, file_info in multipart_data.items():
            # If the form data is a file (not a regular form field)
            if isinstance(file_info, bytes):
                file_data = file_info  # Get the file data as bytes
                file_hash = calculate_file_hash(file_data)  # Calculate the SHA-256 hash of the file

                # Check if the file hash matches any known malicious hashes
                if file_hash in known_hashes:
                    # Block the request if a malicious file is detected
                    flow.response = http.Response.make(
                        403,  # HTTP status code for Forbidden
                        b"<html><body><h1>Request Blocked</h1><p>A known malicious file was detected and the request was blocked.</p></body></html>",  # Custom HTML response
                        {"Content-Type": "text/html"}  # Response headers
                    )
                    flow.intercept()  # Stop further processing of the request
                    print(f"File with hash {file_hash} blocked")  # Log the blocked file hash
                    return  # Stop processing the rest of the request

    # Check the request body for sensitive data patterns (e.g., emails, credit card numbers)
    request_text = flow.request.get_text()  # Get the request body as plain text
    for pattern, category in sensitive_data_patterns:
        if re.search(pattern, request_text):  # Search for the pattern in the request body
            try:
                # Log the detected violation to the Flask backend
                violation_data = {
                    "user": "user1",  # Replace with actual user dynamically if possible
                    "violation": f"Sensitive Data Detected: {category}",  # Include the detected category
                    "url": flow.request.pretty_url,  # The URL of the request
                    "method": flow.request.method,  # HTTP method (GET, POST, etc.)
                    "timestamp": flow.request.timestamp_start  # Timestamp when the request started
                }

                # Send the violation data to the Flask server
                response = requests.post('http://localhost:5000/log_violation', json=violation_data)
                
                if response.status_code == 201:
                    print("Violation logged successfully!")
                else:
                    print(f"Failed to log violation. Status code: {response.status_code}")

                # Block the request after logging the violation
                flow.response = http.Response.make(
                    403,  # HTTP status code for Forbidden
                    b"<html><body><h1>Request Blocked</h1><p>Sensitive data was detected and the request was blocked.</p></body></html>",  # Custom HTML response
                    {"Content-Type": "text/html"}
                )
                flow.intercept()  # Stop further processing
                return  # Stop further execution

            except requests.exceptions.RequestException as e:
                print(f"Error logging violation: {e}")  # Log any error encountered while sending the violation
