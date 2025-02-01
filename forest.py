import zipfile
import os
import gzip
import requests
import sqlite3
import shutil
import argparse
import re
import json
from urllib.parse import urlparse

import chatgpt

# Global set to store sensitive values detected across sessions
sensitive_values = set()

# Global set to track unique keys extracted from request URLs
unique_keys_from_urls = set()

def create_database(db_name):
    # Create or connect to the SQLite database
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    # Create the table to store request and response data with sensitivity flag
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            method TEXT,
            protocol TEXT,
            host TEXT,
            url TEXT,
            request_headers TEXT,
            request_body TEXT,
            response_status INTEGER,
            response_headers TEXT,
            response_body TEXT,
            is_sensitive INTEGER DEFAULT 0  -- 0 = Not sensitive, 1 = Sensitive
        )
    ''')

    # Create the credentials table to store sensitive values
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER,
            sensitive_value TEXT,
            FOREIGN KEY (session_id) REFERENCES sessions (id)
        )
    ''')

    # Create the keywords table to dynamically update user-related keywords
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_keywords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            keyword TEXT UNIQUE
        )
    ''')

    # Create the target domains table to dynamically load domains
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS target_domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE
        )
    ''')

    # Insert default keywords if the table is empty
    cursor.execute('''
        INSERT OR IGNORE INTO user_keywords (keyword) VALUES
        ('user'), ('profile'), ('file'), ('drive'), ('chat'), ('message'), ('owner')
    ''')

    # Insert default OneDrive-related domains
    cursor.execute('''
        INSERT OR IGNORE INTO target_domains (domain) VALUES
        ('graph.microsoft.com'), ('live.com'), ('sharepoint.com')
    ''')

    conn.commit()
    return conn

def fetch_user_data_keywords(conn):
    """Fetch the list of user-related keywords from the database."""
    cursor = conn.cursor()
    cursor.execute('SELECT keyword FROM user_keywords')
    return [row[0].lower() for row in cursor.fetchall()]

def fetch_target_domains(conn):
    """Fetch the list of target domains from the database."""
    cursor = conn.cursor()
    cursor.execute('SELECT domain FROM target_domains')
    return [row[0].lower() for row in cursor.fetchall()]

def extract_sensitive_values(response):
    """Extract sensitive values from response headers and body."""
    sensitive_candidates = set()

    # From response headers
    for key, value in response.headers.items():
        if len(value) > 10:  # Arbitrary length to filter meaningful values
            sensitive_candidates.add(value)

    # From response body (split into tokens for extraction)
    for token in response.text.split():
        if len(token) > 10:  # Token length threshold for sensitive values
            sensitive_candidates.add(token)

    return sensitive_candidates

def contains_sensitive_value(headers, body):
    """Check if headers or body contain any of the previously extracted sensitive values."""
    combined_text = " ".join(headers.values()) + " " + body
    for sensitive_value in sensitive_values:
        if sensitive_value in combined_text:
            print(f"Sensitive value detected in request: {sensitive_value}")
            return True
    return False

def is_user_data(response_text, user_keywords):
    """Determine if the response contains user-related data based on keywords or JSON structure."""
    # Check for keywords in the plain text response
    if any(keyword in response_text.lower() for keyword in user_keywords):
        return True

    # If JSON, try to find relevant keys
    try:
        data = json.loads(response_text)
        if isinstance(data, dict):
            # Check if any keys match known user-related fields
            if any(key.lower() in user_keywords for key in data.keys()):
                return True
    except json.JSONDecodeError:
        pass  # If not JSON, skip this check

    return False

def extract_keys_from_url(url):
    """Extract all potential unique keys (IDs) from a given URL, with flexible length and patterns."""
    key_pattern = re.compile(r"[a-zA-Z0-9_-]{5,}")  # ID-like patterns (5+ characters)
    return set(key_pattern.findall(url))

def keys_used_in_response(response_text):
    """Check if any previously extracted unique keys are used in the response text."""
    for key in unique_keys_from_urls:
        if key in response_text:
            print(f"Found matching key in response: {key}")
            return True, key
    return False, None

def extract_saz_and_make_requests(saz_file, db_conn):
    valid_content_types = {"text/plain", "application/json", "text/html", "text/xml"}
    temp_dir = "extracted_saz"
    os.makedirs(temp_dir, exist_ok=True)

    # Fetch the latest user-related keywords and target domains from the database
    user_keywords = fetch_user_data_keywords(db_conn)
    target_domains = fetch_target_domains(db_conn)

    try:
        with zipfile.ZipFile(saz_file, 'r') as saz_zip:
            saz_zip.extractall(temp_dir)

        raw_dir = os.path.join(temp_dir, 'raw')
        session_files = [os.path.join(raw_dir, f) for f in os.listdir(raw_dir) if f.endswith('_c.txt')]

        for client_file in session_files:
            session_id = os.path.basename(client_file).split('_')[0]
            print(f"Processing session: {session_id}")

            request_lines, body = read_client_file(client_file)
            method, protocol, host, url, headers, body = parse_request(request_lines, body)

            if session_id == "177":
                print("dd")
            if target_domains and not is_relevant_request(host, url, headers, target_domains):
                print(f"Skipping session {session_id} - Not relevant to target domains")
                continue

            # Extract keys from the URL and store them globally
            extracted_keys = extract_keys_from_url(url)
            unique_keys_from_urls.update(extracted_keys)

            # Check if this request contains previously extracted sensitive values
            is_sensitive = 1 if contains_sensitive_value(headers, body) else 0

            response = send_request(method, protocol + host + url, headers, body)

            if response and is_valid_response(response, valid_content_types):
                # Check if any previously extracted keys are used in the current response
                key_found, matching_key = keys_used_in_response(response.text)
                if key_found:
                    print(f"Linking key {matching_key} to future requests if needed.")

                # Check if the response contains user-related data
                if is_user_data(response.text, user_keywords):
                    print("User-related data found in response.")
                    is_sensitive = 1  # Mark this session as sensitive

                # Extract sensitive values from the response and update the global list
                extracted_values = extract_sensitive_values(response)
                sensitive_values.update(extracted_values)

                # Store the session and sensitive values in the database
                session_id_db = store_session_in_db(db_conn, method, protocol, host, url, headers, body, response, is_sensitive)
                store_sensitive_values(db_conn, session_id_db, extracted_values)
                print(f"Response for {protocol + host + url} - Status: {response.status_code}\n")
            else:
                print(f"Skipping session {session_id} - Invalid response content or length")
    finally:
        shutil.rmtree(temp_dir)

def is_valid_response(response, valid_content_types):
    content_length = int(response.headers.get("Content-Length", 0))
    content_type = response.headers.get("Content-Type", "").split(";")[0].strip().lower()

    if content_length == 0:
        return False
    if content_type not in valid_content_types:
        return False
    return True

def is_relevant_request(host, url, headers, target_domains):
    """Check if the request is relevant based on host, URL, or headers."""
    combined_text = f"{host} {url} {' '.join(headers.values())}".lower()

    # Check for target domains in the combined text
    return any(domain.lower() in combined_text for domain in target_domains)

def read_client_file(client_file):
    """Read the request file in binary mode and decode parts correctly."""
    with open(client_file, 'rb') as f:
        raw_data = f.read()

    # Find the end of headers (headers end with \r\n\r\n)
    header_end_index = raw_data.find(b"\r\n\r\n")
    if header_end_index == -1:
        raise ValueError("Invalid request format: headers not found")

    # Split the raw data into header part and body part
    header_part = raw_data[:header_end_index].decode('utf-8', errors='replace')
    body_part = raw_data[header_end_index + 4:]  # Body starts after \r\n\r\n

    request_lines = header_part.split("\r\n")

    # Parse headers
    headers = {}
    for line in request_lines[1:]:
        if ':' in line:
            key, value = line.split(':', 1)
            headers[key.strip()] = value.strip()

    # Check if the body is gzip-compressed
    if "Content-Encoding" in headers and headers["Content-Encoding"].lower() == "gzip":
        try:
            print("Detected gzip-compressed body, decompressing...")
            body = gzip.decompress(body_part).decode('utf-8', errors='replace')
        except Exception as e:
            print(f"Failed to decompress gzip body: {e}")
            body = ""  # If decompression fails, treat body as empty
    else:
        # If not compressed, decode as plain text
        body = body_part.decode('utf-8', errors='replace')

    return request_lines, body

def parse_request(request_lines, body):
    """Parse the HTTP request into method, protocol, host, URL, headers, and body."""
    
    # Split the first line into HTTP method, URL, and protocol
    method, raw_url, _ = request_lines[0].strip().split(' ', 2)

    # Initialize headers as an empty dictionary
    headers = {}
    for line in request_lines[1:]:
        if ':' in line:
            key, value = line.split(':', 1)
            headers[key.strip()] = value.strip()

    # Check if the URL is absolute or relative
    parsed_url = urlparse(raw_url)
    if parsed_url.netloc:  # Absolute URL
        protocol = f"{parsed_url.scheme}://"
        host = parsed_url.netloc
        url = parsed_url.path + ("?" + parsed_url.query if parsed_url.query else "")
    else:  # Relative URL
        protocol = "https://" if headers.get("Host", "").startswith("https") else "http://"
        host = headers.get("Host", "")
        url = raw_url

    return method, protocol, host, url, headers, body

def send_request(method, full_url, headers, body):
    """Send the HTTP request using Python requests."""
    try:
        if method == "GET":
            return requests.get(full_url, headers=headers, allow_redirects=False)
        elif method == "POST":
            return requests.post(full_url, headers=headers, data=body)
        else:
            print(f"Skipping unsupported or unnecessary HTTP method: {method}")
            return None
    except Exception as e:
        print(f"Error sending request to {full_url}: {e}")
        return None

def store_session_in_db(conn, method, protocol, host, url, request_headers, request_body, response, is_sensitive):
    """Store the request and response data into the SQLite database."""
    cursor = conn.cursor()

    # Serialize headers and body as strings
    request_headers_str = '\n'.join([f"{k}: {v}" for k, v in request_headers.items()])
    response_headers_str = '\n'.join([f"{k}: {v}" for k, v in response.headers.items()])
    response_body_str = response.text

    # Insert data into the database with sensitivity flag
    cursor.execute('''
        INSERT INTO sessions (method, protocol, host, url, request_headers, request_body, response_status, response_headers, response_body, is_sensitive)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (method, protocol, host, url, request_headers_str, request_body, response.status_code, response_headers_str, response_body_str, is_sensitive))

    conn.commit()
    return cursor.lastrowid  # Return the session ID for linking sensitive values

def store_sensitive_values(conn, session_id, sensitive_values):
    """Store extracted sensitive values in the credentials table."""
    cursor = conn.cursor()
    for value in sensitive_values:
        cursor.execute('''
            INSERT INTO credentials (session_id, sensitive_value)
            VALUES (?, ?)
        ''', (session_id, value))
    conn.commit()

def query_sensitive_sessions(db_name):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    print("\n📋 Sensitive sessions:")
    cursor.execute('''
        SELECT sessions.id, method, host, url, request_headers, sensitive_value
        FROM sessions
        JOIN credentials ON sessions.id = credentials.session_id
    ''')

    rows = cursor.fetchall()
    for row in rows:
        print(f"Session ID: {row[0]}, Method: {row[1]}, Host: {row[2]}, URL: {row[3]}\nHeaders:\n{row[4]}\nSensitive Value: {row[5]}\n")
    
    conn.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process sensitive sessions and optionally generate OpenAPI specs.")
    parser.add_argument("saz_file", help="Path to the SAZ file")
    parser.add_argument("db_name", help="Name of the SQLite database (e.g., requests.db)")
    parser.add_argument("--generate_openapi", action="store_true", help="Generate OpenAPI specifications for sensitive sessions")
    parser.add_argument("--output_dir", default="openapi_specs", help="Directory to save the OpenAPI specs (default: ./openapi_specs)")

    args = parser.parse_args()

    # Create or connect to the SQLite database
    conn = create_database(args.db_name)
    extract_saz_and_make_requests(args.saz_file, conn)

    if args.generate_openapi:
        os.makedirs(args.output_dir, exist_ok=True)
        chatgpt.process_sensitive_sessions_and_generate_openapi(args.db_name, args.output_dir)

    conn.close()
