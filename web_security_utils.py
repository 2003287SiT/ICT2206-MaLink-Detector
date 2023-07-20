import pandas as pd
import numpy as np
import string
import random
import time
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import sqlite3
from sklearn.feature_extraction.text import TfidfVectorizer

# Load the data
data = pd.read_csv("data.csv", index_col="index")

# Selecting dependent and independent variables
Y = data['is_malicious']
X = data.iloc[:, 3:]

# Modeling data with Random Forest Classifier
random_forest_classifier = RandomForestClassifier()
random_forest_classifier.fit(X, Y)

# Define SQL and JavaScript keywords data
sql_keywords = pd.read_csv('SQLKeywords.txt', index_col=False)
js_keywords = pd.read_csv("JavascriptKeywords.txt", index_col=False)

RATE_LIMIT_THRESHOLD = 100  # Maximum allowed requests per minute
RATE_LIMIT_DURATION = 60  # Time window in seconds for rate limiting

# Training data for SQL injection detection
# Load training data from .txt file
training_data = []
with open('training_data.txt', 'r') as file:
    for line in file:
        query, label = line.strip().split('\t')
        training_data.append((query, int(label)))

# Preparing the training data
queries = [data[0] for data in training_data]
labels = [data[1] for data in training_data]

# Split the data into training and validation sets
X_train, X_val, y_train, y_val = train_test_split(queries, labels, test_size=0.2, random_state=42)

# Feature extraction using TF-IDF
vectorizer = TfidfVectorizer()
X_train_features = vectorizer.fit_transform(X_train)
X_val_features = vectorizer.transform(X_val)

# Train the classifier
classifier = RandomForestClassifier()
classifier.fit(X_train_features, y_train)


def extract_features_and_predict(payload, url, user_agent):
    try:
        features = {}
        payload = str(payload)
        features['payload_length'] = len(payload)
        features['non_printable_chars'] = len([1 for letter in payload if letter not in string.printable])
        features['punctuation_chars'] = len([1 for letter in payload if letter in string.punctuation])
        features['min_payload_byte'] = min(bytearray(payload, 'utf-8'))
        features['max_payload_byte'] = max(bytearray(payload, 'utf-8'))
        features['mean_payload_byte'] = np.mean(bytearray(payload, 'utf-8'))
        features['distinct_payload_byte'] = len(set(bytearray(payload, 'utf-8')))
        features['sql_keywords_found'] = len(
            [1 for keyword in sql_keywords['Keyword'] if str(keyword).lower() in payload.lower()])
        features['js_keywords_found'] = len(
            [1 for keyword in js_keywords['Keyword'] if str(keyword).lower() in payload.lower()])

        # New features for URL analysis
        url_features = str(url)
        features['url_length'] = len(url_features)
        features['num_query_params'] = url_features.count('&') + 1
        features['encoded_url'] = 1 if "%" in url_features else 0

        # New features for User Agent analysis
        user_agent_features = str(user_agent)
        features['user_agent_length'] = len(user_agent_features)
        features['user_agent_random_value'] = random.random()  # Adding a random feature just for demonstration

        payload_df = pd.DataFrame(features, index=[0])
        result = random_forest_classifier.predict(payload_df)
        return result[0]

    except Exception as e:
        # Handle any exception that might occur during feature extraction or prediction
        print("An error occurred:", e)
        return None

def is_rate_limit_exceeded(self):
    # Check if the rate limit for the given IP address is exceeded
    current_time = int(time.time())
    conn = sqlite3.connect("rate_limit.db")  # Database for storing rate limit information

    # Check if there is a record for the IP address in the database
    cursor = conn.cursor()
    cursor.execute("SELECT timestamp, request_count FROM rate_limit WHERE ip_address = ?",
                   (self,))
    result = cursor.fetchone()

    if result:
        # If a record exists, check if the time window has elapsed
        timestamp, request_count = result
        if current_time - timestamp <= RATE_LIMIT_DURATION:
            # Time window has not elapsed, check if the request count exceeds the threshold
            if request_count >= RATE_LIMIT_THRESHOLD:
                conn.close()
                return True
            else:
                # Update the request count in the database
                cursor.execute("UPDATE rate_limit SET request_count = ? WHERE ip_address = ?",
                               (request_count + 1, self))
        else:
            # Time window has elapsed, reset the request count
            cursor.execute("UPDATE rate_limit SET timestamp = ?, request_count = 1 WHERE ip_address = ?",
                           (current_time, self))
    else:
        # If no record exists, insert a new record with the initial request count
        cursor.execute("INSERT INTO rate_limit (ip_address, timestamp, request_count) VALUES (?, ?, 1)",
                       (self, current_time))

    conn.commit()
    conn.close()
    return False





