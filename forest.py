import zipfile
import logging
import os
import gzip
import sqlite3
import shutil
import datetime
import argparse
import re
import json
from tqdm import tqdm
from urllib.parse import urlparse, parse_qs

from loggers import setup_logger
from db_schema import create_database
from openai_api_analyzer import filter_sensitive_responses
from test_required_paramters import test_required_parameters
from generate_api_spec import generate_api_spec

logger = setup_logger(__name__)

def get_run_id_hour():
    now = datetime.datetime.now()
    truncated = now.replace(minute=0, second=0, microsecond=0)
    return truncated.strftime("run_%Y%m%d_%H00")

def load_keywords_from_file(file_path):
    """Load keywords from a text file and return them as a list."""
    if not os.path.isfile(file_path):
        logger.warning(f"Warning: Keywords file '{file_path}' not found. Using an empty list.")
        return []
    with open(file_path, 'r') as f:
        return [line.strip().lower() for line in f if line.strip()]

def load_target_domains_from_file(file_path):
    """Load target domains from a text file and return them as a list."""
    if not os.path.isfile(file_path):
        logger.warning(f"Warning: Target domains file '{file_path}' not found. Using an empty list.")
        return []
    with open(file_path, 'r') as f:
        return [line.strip().lower() for line in f if line.strip()]

def read_response_file(response_file):
    """Read the response file (_s.txt) and return status, headers, and body."""
    if not os.path.exists(response_file):
        return 0, "", ""

    with open(response_file, 'rb') as f:
        raw_data = f.read()

    if len(raw_data.strip()) == 0:
        logger.debug(f"[SKIP] Empty response file: {response_file}")
        return 0, {}, ""
    
    # Find the end of headers (headers end with \r\n\r\n)
    header_end_index = raw_data.find(b"\r\n\r\n")
    if header_end_index == -1:
        logger.debug(f"[SKIP] Invalid response format (no headers): {response_file}")
        return 0, {}, ""

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
    
     # Check for chunked transfer encoding
    if 'transfer-encoding' in headers and 'chunked' in headers['transfer-encoding'].lower():
        try:
            body_part = decode_chunked_data(body_part)
        except Exception as e:
            print(f"[WARNING] Failed to decode chunked data: {e}")

    # Check for gzip encoding
    if 'content-encoding' in headers and 'gzip' in headers['content-encoding'].lower():
        try:
            body_part = gzip.decompress(body_part)
        except Exception as e:
            logger.warning(f"[WARNING] Failed to decompress gzip data: {e}")
            body_part = b""

    # Decode the final body bytes to UTF-8 string
    body = body_part.decode('utf-8', errors='replace')

    return status_code, headers, body

def decode_chunked_data(raw_data):
    """Decodes raw data using Chunked Transfer Encoding."""
    decoded = b""
    idx = 0
    length = len(raw_data)

    while True:
        # Find the chunk-size line ending
        line_end = raw_data.find(b"\r\n", idx)
        if line_end == -1:
            # Invalid chunked format or incomplete data
            break

        # Extract the chunk-size in hex form (e.g. "2fd")
        chunk_size_hex = raw_data[idx:line_end].decode("utf-8").strip()
        idx = line_end + 2  # move past '\r\n'

        if not chunk_size_hex:
            # If chunk_size_hex is empty, there's a format problem
            break

        try:
            # Convert the chunk size from hex to an integer
            chunk_size = int(chunk_size_hex, 16)
        except ValueError:
            # If conversion fails, it's not valid chunked data
            break

        if chunk_size == 0:
            # A size of 0 indicates the final chunk (end of data)
            break

        # Extract the chunk data
        chunk_data = raw_data[idx:idx + chunk_size]
        decoded += chunk_data
        idx += chunk_size

        # Skip the trailing '\r\n' after each chunk
        if idx + 2 <= length and raw_data[idx:idx + 2] == b"\r\n":
            idx += 2

    return decoded

def store_headers(conn, run_id, host, path, headers_dict):
    """
    Insert (run_id, host, path, key, value) for request headers
    """
    cursor = conn.cursor()
    for k, v in headers_dict.items():
        try:
            cursor.execute('''
                INSERT INTO headers (run_id, host, path, key, value)
                VALUES (?, ?, ?, ?, ?)
            ''', (run_id, host, path, k, v))
        except sqlite3.IntegrityError:
            pass
    conn.commit()

def store_response_headers(conn, run_id, host, path, resp_headers_dict):
    cursor = conn.cursor()
    for k, v in resp_headers_dict.items():
        try:
            cursor.execute('''
                INSERT INTO response_headers (run_id, host, path, key, value)
                VALUES (?, ?, ?, ?, ?)
            ''', (run_id, host, path, k, v))
        except sqlite3.IntegrityError:
            pass
    conn.commit()

def store_cookies(conn, run_id, host, path, headers_dict):
    """
    If 'Cookie' in headers, split by ';' and store as (run_id, host, path, key, value).
    """
    cursor = conn.cursor()
    lower_dict = {k.lower(): v for k, v in headers_dict.items()}
    if 'cookie' not in lower_dict:
        return

    cookie_str = lower_dict['cookie']
    cookie_pairs = cookie_str.split(';')
    for pair in cookie_pairs:
        pair = pair.strip()
        if '=' in pair:
            ckey, cval = pair.split('=', 1)
            ckey = ckey.strip()
            cval = cval.strip()
            try:
                cursor.execute('''
                    INSERT INTO cookies (run_id, host, path, key, value)
                    VALUES (?, ?, ?, ?, ?)
                ''', (run_id, host, path, ckey, cval))
            except sqlite3.IntegrityError:
                pass
    conn.commit()

def extract_get_params_from_url(path, query):
    """
    Given path and query separately, parse the query string to get param dict.
    """
    params = {}
    if query:
        q_dict = parse_qs(query)
        for k, v_list in q_dict.items():
            if v_list:
                params[k] = v_list[0]
    return params

def store_request_params(conn, run_id, host, path, query):
    """
    Parse query into param_name, param_value and store in request_params
    as (run_id, host, path, param_name, param_value).
    """
    params_dict = extract_get_params_from_url(path, query)
    if not params_dict:
        return

    cursor = conn.cursor()
    for p_name, p_value in params_dict.items():
        try:
            cursor.execute('''
                INSERT INTO request_params (run_id, host, path, param_name, param_value)
                VALUES (?, ?, ?, ?, ?)
            ''', (run_id, host, path, p_name, p_value))
        except sqlite3.IntegrityError:
            pass
    conn.commit()

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
            logger.info(f"Sensitive data detected using regex: {pattern}")
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

def extract_saz_and_store(saz_file, db_conn, user_keywords, target_domains, run_id=None):
    temp_dir = "extracted_saz"
    os.makedirs(temp_dir, exist_ok=True)

    if not run_id:
        run_id = get_run_id_hour()

    try:
        with zipfile.ZipFile(saz_file, 'r') as saz_zip:
            saz_zip.extractall(temp_dir)

        raw_dir = os.path.join(temp_dir, 'raw')
        session_files = [os.path.join(raw_dir, f) for f in os.listdir(raw_dir) if f.endswith('_c.txt')]

        for client_file in tqdm(session_files, desc="Processing sessions", unit="session"):
            session_id = os.path.basename(client_file).split('_')[0]
            response_file = os.path.join(raw_dir, f"{session_id}_s.txt")

            # Read the request and response files
            request_lines, request_body = read_client_file(client_file)
            response_status, resp_headers, response_body = read_response_file(response_file)

            method, protocol, host, path, query, req_headers = parse_request(request_lines)

            # Check if the request is relevant to the target domains
            if target_domains and not is_relevant_request(host, path, query, req_headers, target_domains):
                continue

            # Check if the response is valid based on headers, content type, and sensitive keywords
            if not is_valid_response(resp_headers, response_body):
                continue

            # Check if the response contains user-related data based on local keywords
            if not is_user_data(response_body, user_keywords):
                continue  # Skip if no user-related data is found locally

            full_path_query = path + ("?" + query if query else "")
            # Check if the response contains sensitive data using ChatGPT
            if not filter_sensitive_responses(protocol + host + full_path_query, response_body):
                continue  # Skip if ChatGPT finds no sensitive data

            # Store session data
            session_pk = store_session_in_db(db_conn, run_id, session_id, method, protocol, host, path, query, req_headers, request_body, response_status, resp_headers, response_body)

            # Store request headers, response headers, and cookies in the database
            store_request_params(db_conn, run_id, host, path, query)
            store_headers(db_conn, run_id, host, path, req_headers)
            store_response_headers(db_conn, run_id, host, path, resp_headers)
            store_cookies(db_conn, run_id, host, path, req_headers)

            logger.info(f"Stored session {session_id} - Response status: {response_status}")

    finally:
        shutil.rmtree(temp_dir)

def is_valid_response(response_headers, response_body):
    """
    Consider a response valid if:
      - The Content-Type is either application/json or text/xml
      - The response body length is not zero
    """
    valid_content_types = {"application/json", "text/xml"}

    # Extract Content-Type from response headers (case-insensitive)
    content_type = response_headers.get("content-type", "").split(";")[0].strip().lower()

    # Check if content type is JSON or XML
    if content_type not in valid_content_types:
        return False

    # Check if body is non-empty
    content_length = len(response_body)
    if content_length == 0:
        return False

    return True

def is_relevant_request(host, path, query, headers, target_domains):
    """Check if the request is relevant based on host, URL, or headers."""
    combined_text = f"{host} {path} {query} {' '.join(headers.values())}".lower()
    return any(domain.lower() in combined_text for domain in target_domains)

def read_client_file(client_file):
    """Read the request file in binary mode and decode parts correctly."""
    with open(client_file, 'rb') as f:
        raw_data = f.read()

    if len(raw_data.strip()) == 0:
        logger.debug(f"[SKIP] Empty request file: {client_file}")
        return {}, ""
    
    # Find the end of headers (headers end with \r\n\r\n)
    header_end_index = raw_data.find(b"\r\n\r\n")
    if header_end_index == -1:
        logger.debug(f"[SKIP] Invalid request format (no headers): {client_file}")
        return {}, ""

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
            body = gzip.decompress(body_part).decode('utf-8', errors='replace')
        except Exception as e:
            logger.error(f"Failed to decompress gzip body: {e}")
            body = ""  # If decompression fails, treat body as empty
    else:
        # If not compressed, decode as plain text
        body = body_part.decode('utf-8', errors='replace')

    return request_lines, body

def parse_request(request_lines):
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
    parsed = urlparse(raw_url)
    if parsed.netloc:
        protocol = f"{parsed.scheme}://"
        host = parsed.netloc
        path = parsed.path
        query = parsed.query
    else:
        host = headers.get("Host", "")
        protocol = "https://" if host.startswith("https") else "http://"
        p = urlparse(raw_url)
        path = p.path
        query = p.query

    return method, protocol, host, path, query, headers

def store_session_in_db(conn, run_id, session_id, method, protocol, host, path, query, request_headers, request_body, response_status, response_headers, response_body):
    """
    Insert into sessions table (run_id, session_id, method, protocol, host, path, query, ...)
    Returns pk.
    """
    cursor = conn.cursor()

    request_headers_json = json.dumps(request_headers or {}, ensure_ascii=False)
    response_headers_json = json.dumps(response_headers or {}, ensure_ascii=False)

    cursor.execute('''
        INSERT INTO sessions (
            run_id, session_id, method, protocol,
            host, path, query, request_headers, request_body, 
            response_status, response_headers, response_body
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        run_id, session_id, method, protocol,
        host, path, query, request_headers_json, request_body,
        response_status, response_headers_json, response_body
    ))
    conn.commit()
    return cursor.lastrowid

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process sensitive sessions and optionally generate OpenAPI specs.")
    parser.add_argument("saz_file", help="Path to the SAZ file")
    
    # Set default database name
    parser.add_argument("-o", "--db_name", default="results.db", help="Name of the SQLite database (default: results.db)")
    
    # Default values added for keyword and domain files
    parser.add_argument("--user_keywords_file", default="user_data_dict.txt", help="Path to the user keywords text file (default: user_data_dict.txt)")
    parser.add_argument("--target_domains_file", default="target_domains_dict.txt", help="Path to the target domains text file (default: target_domains_dict.txt)")

    parser.add_argument("--test_required_parameters", action="store_true", help="Test if headers/cookies are required by removing them one by one and sending requests")
    parser.add_argument("--run_id", default=None, help="Specific run_id to filter. Use 'all' for all run_id, or omit to use latest.")
    parser.add_argument("--generate_open_api_spec", action="store_true", help="Generate OpenAPI specifications after processing the SAZ file")
    
    parser.add_argument("--verbose", action="store_true", help="Enable verbose (DEBUG) logging")
    
    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logger = setup_logger(__name__, level=log_level)

    # Validate the SAZ file path
    try:
        if not os.path.isfile(args.saz_file):
            raise FileNotFoundError(f"The provided path is not a file: {args.saz_file}")
    except FileNotFoundError as e:
        logger.error(e)
        exit(1)
    # Load user keywords and target domains from files
    user_keywords = load_keywords_from_file(args.user_keywords_file)
    target_domains = load_target_domains_from_file(args.target_domains_file)

    # Create or connect to the SQLite database
    conn = create_database(args.db_name)

    # Process the SAZ file
    extract_saz_and_store(args.saz_file, conn, user_keywords, target_domains)

    if args.test_required_parameters:
        test_required_parameters(conn)
        
    if args.generate_open_api_spec:
        generate_api_spec(conn)

    conn.close()

