import sys
import time
from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel, QLineEdit, QPushButton, QMessageBox, QWidget, \
    QVBoxLayout, QCheckBox, QGroupBox, QPlainTextEdit
from PyQt5.QtCore import Qt
from flask import request, session
import sqlite3
import re
from datetime import datetime
import web_security_utils
import urllib.parse
global conn

def validate_input(query):
    # Input validation and sanitization logic
    # Example: Check if the query contains any potentially malicious characters or patterns
    if re.search(r"[;'\"]", query):
        return False
    else:
        return True


def get_current_user():
    # Replace with your implementation to get the current user
    # You can retrieve the current user based on your application's authentication mechanism
    # For simplicity, we'll return a dummy user object
    class User:
        def has_permission(self, _):
            return True  # Simulating the user having the permission

    return User()


class WebApplicationFirewall(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Web Application Firewall")
        self.setGeometry(200, 200, 500, 400)

        self.central_widget = QWidget(self)
        self.setCentralWidget(self.central_widget)

        self.layout = QVBoxLayout(self.central_widget)

        self.query_label = QLabel("SQL Query:", self.central_widget)
        self.layout.addWidget(self.query_label)

        self.entry = QLineEdit(self.central_widget)
        self.layout.addWidget(self.entry)

        self.detect_button = QPushButton("Detect SQL Injection", self.central_widget)
        self.detect_button.clicked.connect(self.detect_sql_injection)
        self.layout.addWidget(self.detect_button)

        self.payload_label = QLabel("Payload:")
        self.layout.addWidget(self.payload_label)
        self.payload_input = QLineEdit()
        self.layout.addWidget(self.payload_input)
        self.url_label = QLabel("URL:")
        self.layout.addWidget(self.url_label)
        self.url_input = QLineEdit()
        self.layout.addWidget(self.url_input)
        self.user_agent_label = QLabel("User Agent:")
        self.layout.addWidget(self.user_agent_label)
        self.user_agent_input = QLineEdit()
        self.layout.addWidget(self.user_agent_input)

        self.predict_button = QPushButton("Predict")
        self.layout.addWidget(self.predict_button)
        self.predict_button.clicked.connect(self.on_predict)

        # self.result_text = QTextEdit(self.central_widget)
        # self.layout.addWidget(self.result_text)

        # Set background color for the GUI
        self.setStyleSheet("background-color: lightgray;")

        self.security_group_box = QGroupBox("Security Settings", self.central_widget)
        self.security_layout = QVBoxLayout(self.security_group_box)

        self.access_control_checkbox = QCheckBox("Enforce Access Control", self.security_group_box)
        self.access_control_checkbox.stateChanged.connect(self.on_checkbox_state_changed)
        self.security_layout.addWidget(self.access_control_checkbox)


        self.rate_limiting_checkbox = QCheckBox("Enable Rate Limiting", self.security_group_box)
        self.rate_limiting_checkbox.stateChanged.connect(self.on_second_checkbox_state_changed)
        self.security_layout.addWidget(self.rate_limiting_checkbox)

        self.layout.addWidget(self.security_group_box)

        self.setLayout(self.layout)
        self.log_text = QPlainTextEdit(self.central_widget)  # A multiline text box for displaying logs
        self.layout.addWidget(self.log_text)

        self.log_entry_button = QPushButton("Submit Log Entry", self.central_widget)
        self.log_entry_button.clicked.connect(self.log_entry_to_database)
        self.layout.addWidget(self.log_entry_button)

        # Create a database connection for logging
        self.log_conn = sqlite3.connect("log.db")
        self.log_cursor = self.log_conn.cursor()

    def on_predict(self):
        payload = self.payload_input.text()
        url = self.url_input.text()
        user_agent = self.user_agent_input.text()

        # Validate input for payload, URL, and user agent
        if not self.validate_input(payload) or not self.validate_url(url) or not self.validate_user_agent(user_agent):
            self.show_error("Invalid Input", "Invalid input provided.")
            return

        result = web_security_utils.extract_features_and_predict(payload, url, user_agent)

        if result is not None:
            if result == 0:
                QMessageBox.information(self, "Result", "Your payload is safe (200 OK)")
            else:
                QMessageBox.warning(self, "Result", "Your payload is malicious (403 error)")

    @staticmethod
    def validate_input(input_str):
        # Input validation and sanitization logic for payload, URL, and user agent
        # Example: Check if the input contains any potentially malicious characters or patterns
        if re.search(r"[;'\"]", input_str):
            return False
        return True

    @staticmethod
    def validate_url(url_str):
        # Validate the URL format
        try:
            # Use urllib.parse to parse and validate the URL
            urllib.parse.urlparse(url_str)
            return True
        except Exception:
            return False

    @staticmethod
    def validate_user_agent(user_agent_str):
        # Input validation and sanitization logic for user agent
        # Example: Check if the user agent contains any potentially malicious characters or patterns
        if re.search(r"[;'\"]", user_agent_str):
            return False
        return True

    def on_checkbox_state_changed(self, state):
        current_user = get_current_user()  # Replace with your implementation to get the current user
        if state == Qt.Checked:
            self.enforce_access_control(current_user)
        else:
            self.show_info("Access Revoked", "Access revoked to the resource.")

    def on_second_checkbox_state_changed(self, state):
        if state == Qt.Checked:
            self.perform_rate_limiting()
        else:
            self.show_info("Rate Limiting Disabled", "Rate limiting has been disabled.")

    def enforce_access_control(self, current_user):
        # Access control enforcement logic
        # Example: Check if the user making the request has the necessary permissions
        if not current_user.has_permission("access_resource"):
            # Deny access and return an appropriate response
            self.show_warning("Access Denied", "You do not have permission to access this resource.")
        else:
            # Proceed with further processing
            self.show_info("Access Granted", "Access granted to the resource.")

    @staticmethod
    def log_entry_to_database(self, entry):
        self.log_text.appendPlainText(entry)

        log_entry = self.log_text.toPlainText()  # Retrieve the log entry from the log_text widget

        if log_entry:
            # Insert the log entry into the database
            timestamp = int(time.time())
            self.log_cursor.execute("INSERT INTO log (timestamp, entry) VALUES (?, ?)", (timestamp, entry))
            self.log_conn.commit()

        conn.commit()
        conn.close()

    def closeEvent(self, event):
        # Close the database connection when the application is closed
        self.log_conn.close()
        event.accept()

    @staticmethod
    def send_notification_to_monitoring_system(message):
        # Send a notification to the monitoring system or administrators
        # Your notification logic here
        print("Sending notification:", message)

    def log_and_monitor(self):
        # Logging and monitoring logic
        # Example: Log request details and monitor application activities
        log_entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "method": request.method,
            "path": request.path,
            "user_agent": request.user_agent.string,
            "headers": dict(request.headers),
            "client_ip": request.remote_addr,
            "query_params": dict(request.args),
            "session_id": session.get('session_id'),
            "user_id": session.get('user_id')
            # Include any other relevant information
        }

        self.log_entry_to_database(self, log_entry)
        self.send_notification_to_monitoring_system(log_entry)




    def detect_sql_injection(self):
        query = self.entry.text().strip()

        # Security measures
        # Whitelist criteria
        # Whitelist criteria
        whitelist_criteria = [
            r"^[a-zA-Z0-9]{1,20}$",  # Alphanumeric strings of up to 20 characters
            r"(?i)select \* from users where username='[a-zA-Z]+' and password='[a-zA-Z]+'",  # Specific query pattern
            r"(?i)select \* from [a-zA-Z_]+",  # Allow SELECT queries from specific tables
            r"^[a-z0-9]{1,20}$",  # Lowercase alphanumeric strings of up to 20 characters
            r"(?i)select \* from users where username='[a-z]+' and password='[a-z]+'",
            # Specific query pattern with lowercase
            r"(?i)select \* from [a-z_]+",  # Allow SELECT queries from specific tables with lowercase
            # Add more whitelist criteria here
        ]

        # Check if the query matches any whitelist criteria
        is_whitelisted = any(re.match(pattern, query) for pattern in whitelist_criteria)

        # Query is not in the whitelist
        if not is_whitelisted:
            self.show_warning("Potential SQL Injection (Whitelist Check)", "Potential SQL injection detected!")
            return

        # Input length restriction: Check the length of the input query
        max_input_length = 100
        if len(query) > max_input_length:
            self.show_warning("Potential SQL Injection (Input Length Restriction)",
                              "Potential SQL injection detected due to input length.")
            return

        # Rule-based detection patterns
        detection_rules = [
            "DROP TABLE",
            "UNION SELECT",
            "DELETE FROM",
            "UPDATE SET",
            "INSERT INTO",
            "SLEEP\\(\\d+\\)",  # Time-based attack pattern
            "ALTER TABLE",
            "GRANT",
            # Add more detection rules here
        ]

        # Rule-based detection
        for rule in detection_rules:
            if rule in query:
                self.show_warning("Potential SQL Injection (Rule-Based)",
                                  f"Potential SQL injection detected!\nDetected pattern: {rule}")
                return

        try:
            # Create a database connection
            conn = sqlite3.connect("database.db")

            # Use parameterized queries with placeholders
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (query, "dummy_password"))
            result = cursor.fetchall()

            if result:
                self.show_info("Safe Query", "Query is safe.")
            else:
                self.show_warning("Potential SQL Injection (Parameterized Query)", "Potential SQL injection detected!")

        except Exception as e:
            self.show_error("Error", str(e))

        finally:

            if conn:
                conn.close()

        # Feature extraction for the query
        query_features = web_security_utils.vectorizer.transform([query])

        # Predict the label using the trained classifier
        prediction = web_security_utils.classifier.predict(query_features)[0]

        # Check if the query is flagged as a potential SQL injection
        if prediction == 1:
            self.show_warning("Potential SQL Injection (Machine Learning)", "Potential SQL injection detected!")
        else:
            self.show_info("Safe Query", "Query is safe.")



    @staticmethod
    def get_ip_address():
        # Replace with your implementation to get the IP address
        # You can retrieve the IP address from the request object or any other mechanism
        # For simplicity, we'll return a dummy IP address
        return "4.227.201.97"

    def perform_rate_limiting(self):
        # Rate limiting logic
        # Example: Limit the number of requests per second from an IP address
        ip_address = self.get_ip_address()
        if web_security_utils.is_rate_limit_exceeded(self):
            self.show_warning("Rate Limit Exceeded", "Rate limit exceeded from IP address: " + ip_address)
        else:
            self.show_info("Rate Limit Passed", "Rate limit passed for IP address: " + ip_address)

    # Other methods and UI components
    # ...

    def show_warning(self, title, message):
        QMessageBox.warning(self, title, message)

    def show_info(self, title, message):
        QMessageBox.information(self, title, message)

    def show_error(self, title, message):
        QMessageBox.critical(self, title, message)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")  # Set the application style to Fusion for consistent look and feel
    window = WebApplicationFirewall()
    window.show()
    sys.exit(app.exec_())
