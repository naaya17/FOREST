import logging
import requests
import time
import shlex
from tqdm import tqdm 
import requests, time, shlex
from loggers import setup_logger

from requests_toolbelt.utils import dump

logger = setup_logger(__name__)

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

    logger.info("")

    # A) Determine run_id logic
    if run_id is None:
        run_id = get_latest_run_id(db_conn)
        if run_id is None:
            logger.error("No run_id found. Exiting test.")
            return
        logger.info(f"Using latest run_id for testing: {run_id}")
        session_filter_sql = "WHERE run_id = ?"
        session_filter_params = (run_id,)
    elif run_id.lower() == "all":
        logger.info("Testing ALL run_id sessions.")
        session_filter_sql = ""
        session_filter_params = ()
    else:
        logger.info(f"Testing specific run_id: {run_id}")
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

    for pk, actual_run_id, method, protocol, host, path, query, req_body_str in tqdm(sessions, desc="Testing parameters", unit="session"):
        # 1) Retrieve headers/cookies
        hdrs = get_headers_for_session(db_conn, actual_run_id, host, path)
        ccks = get_cookies_for_session(db_conn, actual_run_id, host, path)

        # 2) Build final URL
        full_url = build_full_url(protocol, host, path, query)

        # 3) Baseline request (include body if not GET)
        logger.info(f"[BASELINE] pk={pk}, method={method}, url={full_url}")
        baseline_status, baseline_body = send_test_request(method, full_url, hdrs, ccks, req_body_str, delay=delay)
        logger.info(f"[BASELINE] status={baseline_status}")
        
        # A) skip if baseline is invalid
        if is_actual_error(baseline_status, baseline_body):
            logger.warning(f"[SKIP] pk={pk}: Baseline request failed or returned error (status={baseline_status}). Skipping.")
            continue

        
        if method.upper() != "GET" and req_body_str:
            bodyless_status, bodyless_body = send_test_request(
                method, full_url, hdrs, ccks, request_body=None, delay=delay
            )
            body_is_required = (
                is_actual_error(bodyless_status, bodyless_body) and 
                not is_actual_error(baseline_status, baseline_body)
            )
            if body_is_required:
                logger.info(f"[REQUIRED] Request body is REQUIRED (baseline={baseline_status}, no-body={bodyless_status})")
            else:
                logger.info(f"[OPTIONAL] Request body is NOT required (status {bodyless_status})")

            update_body_is_required(db_conn, actual_run_id, host, path, body_is_required)

        # 4) Test each header by removing it
        for hkey in list(hdrs.keys()):
            modified_hdrs = {k: v for k, v in hdrs.items() if k != hkey}
            test_status, test_body = send_test_request(method, full_url, modified_hdrs, ccks, req_body_str, delay=delay)
            is_error = is_actual_error(test_status, test_body) and not is_actual_error(baseline_status, baseline_body)
            if is_error:
                logger.info(f"[REQUIRED] Header {hkey} is REQUIRED (baseline={baseline_status}, no-header={test_status})")
                update_header_is_required(db_conn, actual_run_id, host, path, hkey, 1)
            else:
                logger.info(f"[OPTIONAL] Header {hkey} is NOT required (status {test_status})")


        # 5) Test each cookie by removing it
        for ckey in list(ccks.keys()):
            modified_ck = {k: v for k, v in ccks.items() if k != ckey}
            test_status, test_body = send_test_request(method, full_url, hdrs, modified_ck, req_body_str, delay=delay)
            is_error = is_actual_error(test_status, test_body) and not is_actual_error(baseline_status, baseline_body)
            logger.debug(f"[DEBUG] Modified cookies after removing {ckey}: {modified_ck}")
            if is_error:
                logger.info(f"[REQUIRED] Cookie {ckey} is REQUIRED (baseline={baseline_status}, no-cookie={test_status})")
                update_cookie_is_required(db_conn, actual_run_id, host, path, ckey, 1)
            else:
                logger.info(f"[OPTIONAL] Cookie {ckey} is NOT required (status {test_status})")
                logger.debug(f"[DEBUG] Response body after removing {ckey}: {test_body}")
        
        logger.info("")

def is_actual_error(status_code, body):
    """
    Determines whether the response is logically an error,
    even if HTTP status code is 200.
    Looks inside the body for status_code=401 or similar.
    """
    if status_code == 0:
        return True  # 요청 실패
    if status_code >= 400:
        return True
    if isinstance(body, dict):
        return body.get("status_code", 200) >= 400
    return False



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
    time.sleep(delay)

    headers = headers_dict.copy() if headers_dict else {}
    headers.update({
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Expires": "0",
        "User-Agent": "curl/7.88.1"
    })
    headers = {k: v for k, v in headers.items() if k.lower() != "cookie"}

    # curl 문자열 만들기
    curl_parts = [f"curl -X {method.upper()}"]
    for k, v in headers.items():
        curl_parts.append(f"-H {shlex.quote(f'{k}: {v}')}")
    if cookies_dict:
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies_dict.items())
        curl_parts.append(f"--cookie {shlex.quote(cookie_str)}")
    if method.upper() != "GET" and request_body:
        curl_parts.append(f"--data {shlex.quote(request_body)}")
    curl_parts.append(shlex.quote(full_url))
    curl_command = " ".join(curl_parts)
    logger.debug(f"[CURL EQUIVALENT] {curl_command}")

    try:
        if method.upper() == "GET":
            resp = requests.get(full_url, headers=headers, cookies=cookies_dict, timeout=(3, 3))
        else:
            resp = requests.post(full_url, headers=headers, cookies=cookies_dict, data=request_body, timeout=(3, 3))

        data = dump.dump_all(resp)
        logger.debug(data.decode("utf-8", errors="replace").replace("\r\n", " | "))

        try:
            body = resp.json()
        except:
            body = resp.text[:200]

        return resp.status_code, body

    except Exception as e:
        logger.error(f"Request failed: {e}")
        return 0, None

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
    logger.debug(f"[DEBUG] Trying to update header: run_id={run_id}, host={host}, path={path}, key={hkey}, is_required={is_req}")
    
    c.execute("""
        UPDATE headers
        SET is_required = ?
        WHERE run_id = ? AND host = ? AND path = ? AND key = ?
    """, (is_req, run_id, host, path, hkey))
    
    db_conn.commit()
    
    logger.debug(f"[DEBUG] Update result: {c.rowcount} row(s) affected")


def update_cookie_is_required(db_conn, run_id, host, path, ckey, is_req):
    """
    Updates the 'cookies' table, setting is_required = is_req for the specified record.
    """
    c = db_conn.cursor()
    logger.debug(f"[DEBUG] Trying to update cookie: run_id={run_id}, host={host}, path={path}, key={ckey}, is_required={is_req}")
    
    c.execute("""
        UPDATE cookies
        SET is_required = ?
        WHERE run_id = ? AND host = ? AND path = ? AND key = ?
    """, (is_req, run_id, host, path, ckey))
    
    db_conn.commit()
    
    logger.debug(f"[DEBUG] Update result: {c.rowcount} row(s) affected")

def update_body_is_required(db_conn, run_id, host, path, is_req):
    """
    Updates the 'sessions' table, setting is_body_required = is_req for the specified session.
    """
    c = db_conn.cursor()
    logger.debug(f"[DEBUG] Updating is_body_required: run_id={run_id}, host={host}, path={path}, is_required={is_req}")
    c.execute("""
        UPDATE sessions
        SET is_body_required = ?
        WHERE run_id = ? AND host = ? AND path = ?
    """, (int(is_req), run_id, host, path))
    db_conn.commit()
    logger.debug(f"[DEBUG] Updated sessions.is_body_required: {c.rowcount} row(s)")


