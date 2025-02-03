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

from openai_api_analyzer import filter_sensitive_responses
from generate_api_spec import generate_api_spec

def create_database(db_name):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    # Create tables
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            method TEXT,
            protocol TEXT,
            host TEXT,
            url TEXT,
            request_body TEXT,
            response_status INTEGER,
            response_body TEXT,
            is_sensitive INTEGER DEFAULT 0
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS headers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER,
            host TEXT,
            key TEXT,
            value TEXT,
            FOREIGN KEY (session_id) REFERENCES sessions (id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS response_headers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER,
            host TEXT,
            key TEXT,
            value TEXT,
            FOREIGN KEY (session_id) REFERENCES sessions (id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cookies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER,
            host TEXT,
            key TEXT,
            value TEXT,
            FOREIGN KEY (session_id) REFERENCES sessions (id)
        )
    ''')

    conn.commit()
    return conn

def load_keywords_from_file(file_path):
    """Load keywords from a text file and return them as a list."""
    if not os.path.isfile(file_path):
        print(f"Warning: Keywords file '{file_path}' not found. Using an empty list.")
        return []
    with open(file_path, 'r') as f:
        return [line.strip().lower() for line in f if line.strip()]

def load_target_domains_from_file(file_path):
    """Load target domains from a text file and return them as a list."""
    if not os.path.isfile(file_path):
        print(f"Warning: Target domains file '{file_path}' not found. Using an empty list.")
        return []
    with open(file_path, 'r') as f:
        return [line.strip().lower() for line in f if line.strip()]

def read_response_file(response_file):
    """Read the response file (_s.txt) and return status, headers, and body."""
    if not os.path.exists(response_file):
        return 0, "", ""

    with open(response_file, 'rb') as f:
        raw_data = f.read()

    # Find the end of headers (headers end with \r\n\r\n)
    header_end_index = raw_data.find(b"\r\n\r\n")
    if header_end_index == -1:
        raise ValueError("Invalid response format: headers not found")

    # Split headers and body
    header_part = raw_data[:header_end_index].decode('utf-8', errors='replace')
    body_part = raw_data[header_end_index + 4:]  # Body starts after \r\n\r\n

    # Parse status line (e.g., HTTP/1.1 200 OK)
    status_line = header_part.split("\n")[0].strip()
    status_code = int(status_line.split(' ')[1])

    # Parse headers into a dictionary
    headers = {}
    for line in header_part.split("\n")[1:]:
        if ':' in line:
            key, value = line.split(':', 1)
            headers[key.strip().lower()] = value.strip()

    # Handle gzip-compressed responses
    if 'content-encoding' in headers and headers['content-encoding'].lower() == 'gzip':
        try:
            print(f"Decompressing gzip response for {response_file}...")
            body = gzip.decompress(body_part).decode('utf-8', errors='replace')
        except Exception as e:
            print(f"Failed to decompress gzip response: {e}")
            body = ""
    else:
        body = body_part.decode('utf-8', errors='replace')

    return status_code, headers, body

def store_key_value_pairs(conn, table_name, session_id, host, key, value):
    """Store (session_id, host, key, value) pairs in the specified table, avoiding duplicates based on (host, key, value)."""
    cursor = conn.cursor()

    # Check for duplicates based on (host, key, value) only
    cursor.execute(f'''
        SELECT 1 FROM {table_name} 
        WHERE host = ? AND key = ? AND value = ?
    ''', (host, key, value))

    # Insert the (session_id, host, key, value) only if no duplicates exist
    if not cursor.fetchone():
        cursor.execute(f'''
            INSERT INTO {table_name} (session_id, host, key, value)
            VALUES (?, ?, ?, ?)
        ''', (session_id, host, key, value))

    conn.commit()

def store_headers(conn, session_id, host, headers):
    for key, value in headers.items():
        store_key_value_pairs(conn, "headers", session_id, host, key, value)

def store_response_headers(conn, session_id, host, response_headers):
    for key, value in response_headers.items():
        store_key_value_pairs(conn, "response_headers", session_id, host, key, value)

def store_cookies(conn, session_id, host, headers):
    headers_lower = {k.lower(): v for k, v in headers.items()}
    
    if 'cookie' in headers_lower:
        cookies = headers_lower['cookie'].split('; ')
        for cookie in cookies:
            if '=' in cookie:
                key, value = cookie.split('=', 1)
                store_key_value_pairs(conn, "cookies", session_id, host, key.strip().lower(), value.strip())

def is_user_data(response_text, user_keywords):
    # Regex patterns for sensitive data detection (email, phone, credit card)
    sensitive_patterns = [
        r'[\w\.-]+@[\w\.-]+',  # Email pattern
        r'\b\d{10,11}\b',      # Phone number (10-11 digits)
        r'\b\d{16}\b'          # Credit card number (16 digits)
    ]

    # Detect sensitive data using regex
    for pattern in sensitive_patterns:
        if re.search(pattern, response_text):
            print(f"Sensitive data detected using regex: {pattern}")
            return True

    # Detect based on keywords
    if user_keywords and any(keyword in response_text.lower() for keyword in user_keywords):
        return True

    # Detect based on JSON structure
    try:
        data = json.loads(response_text)
        if user_keywords and isinstance(data, dict) and any(key.lower() in user_keywords for key in data.keys()):
            return True
    except json.JSONDecodeError:
        pass

    return not user_keywords  # If no keywords, consider all responses as candidates

def extract_saz_and_store(saz_file, db_conn, user_keywords, target_domains):
    temp_dir = "extracted_saz"
    os.makedirs(temp_dir, exist_ok=True)

    try:
        with zipfile.ZipFile(saz_file, 'r') as saz_zip:
            saz_zip.extractall(temp_dir)

        raw_dir = os.path.join(temp_dir, 'raw')
        session_files = [os.path.join(raw_dir, f) for f in os.listdir(raw_dir) if f.endswith('_c.txt')]

        for client_file in session_files:
            session_id = os.path.basename(client_file).split('_')[0]
            response_file = os.path.join(raw_dir, f"{session_id}_s.txt")

            print(f"Processing session: {session_id}")

            # Read the request and response files
            request_lines, body = read_client_file(client_file)
            response_status, response_headers, response_body = read_response_file(response_file)

            method, protocol, host, url, headers, body = parse_request(request_lines, body)

            # Check if the request is relevant to the target domains
            if target_domains and not is_relevant_request(host, url, headers, target_domains):
                print(f"Skipping session {session_id} - Not relevant to target domains")
                continue

            # Check if the response is valid based on headers, content type, and sensitive keywords
            if not is_valid_response(response_headers, response_body):
                print(f"Skipping session {session_id} - Invalid response")
                continue

            # Check if the response contains user-related data based on local keywords
            if not is_user_data(response_body, user_keywords):
                continue  # Skip if no user-related data is found locally

            # Check if the response contains sensitive data using ChatGPT
            if not filter_sensitive_responses(protocol + host + url, response_body):
                continue  # Skip if ChatGPT finds no sensitive data

            # Store session data
            session_id = store_session_in_db(db_conn, session_id, method, protocol, host, url, body, response_status, response_body)

            # Store request headers, response headers, and cookies in the database
            store_headers(db_conn, session_id, host, headers)
            store_response_headers(db_conn, session_id, host, response_headers)
            store_cookies(db_conn, session_id, host, headers)

            print(f"Stored session {session_id} - Response status: {response_status}")

    finally:
        shutil.rmtree(temp_dir)

def is_valid_response(response_headers, response_body):
    valid_content_types = {"text/plain", "application/json", "text/html", "text/xml"}
    sensitive_header_keys = ["location", "access_token", "refresh_token", "authorization"]

    # Check sensitive keys in response headers
    for key, value in response_headers.items():
        if any(sensitive_key in key.lower() for sensitive_key in sensitive_header_keys):
            print(f"Sensitive key detected in response headers: {key} -> {value}")
            return True

    # Extract Content-Type from response headers
    content_type = response_headers.get("content-type", "").split(";")[0].strip().lower()

    # Content-Length check
    content_length = len(response_body)

    # Validate Content-Type and minimum body length
    if content_type not in valid_content_types and content_length < 10:
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

#TODO: 보내야 하는 경우가 있으려나? 필수 파라미터 체크용
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
    
def store_session_in_db(conn, session_id, method, protocol, host, url, request_body, response_status, response_body):
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO sessions (id, method, protocol, host, url, request_body, response_status, response_body)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (session_id, method, protocol, host, url, request_body, response_status, response_body))
    
    conn.commit()
    return session_id


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process sensitive sessions and optionally generate OpenAPI specs.")
    parser.add_argument("saz_file", help="Path to the SAZ file")
    
    # Set default database name
    parser.add_argument("-o", "--db_name", default="results.db", help="Name of the SQLite database (default: results.db)")
    
    # Default values added for keyword and domain files
    parser.add_argument("--user_keywords_file", default="user_data_dict.txt", help="Path to the user keywords text file (default: user_data_dict.txt)")
    parser.add_argument("--target_domains_file", default="target_domains_dict.txt", help="Path to the target domains text file (default: target_domains_dict.txt)")

    parser.add_argument("--generate_open_api_spec", action="store_true", help="Generate OpenAPI specifications after processing the SAZ file")
    
    args = parser.parse_args()

    # Validate the SAZ file path
    try:
        if not os.path.isfile(args.saz_file):
            raise FileNotFoundError(f"The provided path is not a file: {args.saz_file}")
    except FileNotFoundError as e:
        print(e)
        exit(1)
    # Load user keywords and target domains from files
    user_keywords = load_keywords_from_file(args.user_keywords_file)
    target_domains = load_target_domains_from_file(args.target_domains_file)

    # Create or connect to the SQLite database
    conn = create_database(args.db_name)

    # Process the SAZ file
    extract_saz_and_store(args.saz_file, conn, user_keywords, target_domains)

    if args.generate_open_api_spec:
        generate_api_spec(conn)

    conn.close()

