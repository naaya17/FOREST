import requests
import time

def test_required_parameters(db_conn, run_id=None, delay=1):
    """
    1) Fetch (pk, run_id, method, protocol, host, path, query, request_body) from 'sessions' table.
    2) For each session:
       - Retrieve headers/cookies from (run_id, host, path).
       - Build the final URL using protocol, host, path, and query.
       - Perform a baseline request (including request_body if not GET).
       - Remove each header/cookie one by one and re-send the request (body stays the same).
       - If the response becomes an error (>=400) while baseline was <400, mark is_required=1 in DB.
    3) Add a delay (seconds) before each request to reduce potential server ban.
    """
    cursor = db_conn.cursor()

    # A) Determine run_id logic
    if run_id is None:
        run_id = get_latest_run_id(db_conn)
        if run_id is None:
            print("No run_id found. Exiting test.")
            return
        print(f"[INFO] Using latest run_id for testing: {run_id}")
        session_filter_sql = "WHERE run_id = ?"
        session_filter_params = (run_id,)
    elif run_id.lower() == "all":
        print("[INFO] Testing ALL run_id sessions.")
        session_filter_sql = ""
        session_filter_params = ()
    else:
        print(f"[INFO] Testing specific run_id: {run_id}")
        session_filter_sql = "WHERE run_id = ?"
        session_filter_params = (run_id,)

    # B) Retrieve session data: (pk, run_id, method, protocol, host, path, query, request_body)
    cursor.execute(f"""
        SELECT pk, run_id, method, protocol, host, path, query, request_body
        FROM sessions
        {session_filter_sql}
        ORDER BY pk
    """, session_filter_params)
    sessions = cursor.fetchall()

    for pk, actual_run_id, method, protocol, host, path, query, req_body_str in sessions:
        # 1) Retrieve headers/cookies
        hdrs = get_headers_for_session(db_conn, actual_run_id, host, path)
        ccks = get_cookies_for_session(db_conn, actual_run_id, host, path)

        # 2) Build final URL
        full_url = build_full_url(protocol, host, path, query)

        # 3) Baseline request (include body if not GET)
        baseline_status = send_test_request(method, full_url, hdrs, ccks, req_body_str, delay=delay)
        print(f"\n[BASELINE] pk={pk}, method={method}, url={full_url}, status={baseline_status}")

        # 4) Test each header by removing it
        for hkey in list(hdrs.keys()):
            modified_hdrs = {k: v for k, v in hdrs.items() if k != hkey}
            test_status = send_test_request(method, full_url, modified_hdrs, ccks, req_body_str, delay=delay)
            is_error = (baseline_status < 400) and (test_status >= 400)
            if is_error:
                print(f"[REQUIRED] Header {hkey} is REQUIRED (baseline={baseline_status}, no-header={test_status})")
                update_header_is_required(db_conn, actual_run_id, host, path, hkey, 1)
            else:
                print(f"[OPTIONAL] Header {hkey} is NOT required (status {test_status})")


        # 5) Test each cookie by removing it
        for ckey in list(ccks.keys()):
            modified_ck = {k: v for k, v in ccks.items() if k != ckey}
            test_status = send_test_request(method, full_url, hdrs, modified_ck, req_body_str, delay=delay)
            is_error = (baseline_status < 400) and (test_status >= 400)
            if is_error:
                print(f"[REQUIRED] Cookie {ckey} is REQUIRED (baseline={baseline_status}, no-cookie={test_status})")
                update_cookie_is_required(db_conn, actual_run_id, host, path, ckey, 1)
            else:
                print(f"[OPTIONAL] Cookie {ckey} is NOT required (status {test_status})")




def build_full_url(protocol, host, path, query):
    """
    Combine protocol, host, path, and optional query into a full URL.
    Example:
      protocol = "https://"
      host = "example.com"
      path = "/api/v1/user"
      query = "page=2"
    => "https://example.com/api/v1/user?page=2"
    """
    full_url = f"{protocol}{host}{path}"
    if query:
        full_url += f"?{query}"
    return full_url

def send_test_request(method, full_url, headers_dict, cookies_dict, request_body=None, delay=1):
    """
    Sends a request with a small delay to avoid potential bans.
    If method is not GET, we send 'request_body' as data=... (raw).
    Returns the status code.
    """
    time.sleep(delay)
    try:
        if method.upper() == "GET":
            resp = requests.get(full_url, headers=headers_dict, cookies=cookies_dict)
        else:
            # For simplicity, treat everything else as POST with body
            resp = requests.post(full_url, headers=headers_dict, cookies=cookies_dict, data=request_body)
        return resp.status_code
    except Exception as e:
        print(f"[ERROR] Request failed: {e}")
        return 0

def get_latest_run_id(db_conn):
    """
    Returns the most recent run_id from the sessions table in descending order.
    """
    c = db_conn.cursor()
    c.execute("SELECT run_id FROM sessions ORDER BY run_id DESC LIMIT 1")
    row = c.fetchone()
    if row:
        return row[0]
    return None

def get_headers_for_session(db_conn, run_id, host, path):
    """
    Retrieves {header_key: header_value} from 'headers' table for (run_id, host, path).
    If run_id == 'all', ignore run_id in the query.
    """
    c = db_conn.cursor()
    if run_id.lower() == "all":
        c.execute("""
            SELECT key, value
            FROM headers
            WHERE host = ? AND path = ?
        """, (host, path))
    else:
        c.execute("""
            SELECT key, value
            FROM headers
            WHERE run_id = ? AND host = ? AND path = ?
        """, (run_id, host, path))
    rows = c.fetchall()
    return {k: v for k, v in rows}

def get_cookies_for_session(db_conn, run_id, host, path):
    """
    Retrieves {cookie_key: cookie_value} from 'cookies' table for (run_id, host, path).
    If run_id == 'all', ignore run_id in the query.
    """
    c = db_conn.cursor()
    if run_id.lower() == "all":
        c.execute("""
            SELECT key, value
            FROM cookies
            WHERE host = ? AND path = ?
        """, (host, path))
    else:
        c.execute("""
            SELECT key, value
            FROM cookies
            WHERE run_id = ? AND host = ? AND path = ?
        """, (run_id, host, path))
    rows = c.fetchall()
    return {k: v for k, v in rows}

def update_header_is_required(db_conn, run_id, host, path, hkey, is_req):
    """
    Updates the 'headers' table, setting is_required = is_req for the specified record.
    """
    c = db_conn.cursor()
    print(f"[DEBUG] Trying to update header: run_id={run_id}, host={host}, path={path}, key={hkey}, is_required={is_req}")
    
    c.execute("""
        UPDATE headers
        SET is_required = ?
        WHERE run_id = ? AND host = ? AND path = ? AND key = ?
    """, (is_req, run_id, host, path, hkey))
    
    db_conn.commit()
    
    print(f"[DEBUG] Update result: {c.rowcount} row(s) affected")


def update_cookie_is_required(db_conn, run_id, host, path, ckey, is_req):
    """
    Updates the 'cookies' table, setting is_required = is_req for the specified record.
    """
    c = db_conn.cursor()
    print(f"[DEBUG] Trying to update cookie: run_id={run_id}, host={host}, path={path}, key={ckey}, is_required={is_req}")
    
    c.execute("""
        UPDATE cookies
        SET is_required = ?
        WHERE run_id = ? AND host = ? AND path = ? AND key = ?
    """, (is_req, run_id, host, path, ckey))
    
    db_conn.commit()
    
    print(f"[DEBUG] Update result: {c.rowcount} row(s) affected")

