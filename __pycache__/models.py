from app import db
from datetime import datetime

# Violation class representing a record of violations in the database
class Violation(db.Model):
    # Unique ID for each violation record, used as primary key
    id = db.Column(db.Integer, primary_key=True)

    # Username or user ID associated with the violation
    user = db.Column(db.String(80), nullable=False)

    # Description of the violation (e.g., "Sensitive data detected")
    violation = db.Column(db.String(200), nullable=False)

    # Timestamp of when the violation occurred, automatically set to the current time
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    # URL where the violation was detected (optional, can be null)
    url = db.Column(db.String(200), nullable=True)

    # HTTP method used in the request that caused the violation (GET, POST, etc.)
    method = db.Column(db.String(10), nullable=True)

    # Special method to represent the object when it's printed or logged
    # Useful for debugging or logging purposes
    def __repr__(self):
        return f"<Violation {self.violation}>"
