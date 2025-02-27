import os
import json
import sqlite3
from tqdm import tqdm

def generate_api_spec(db_conn, output_dir="openapi_specs", run_id=None):
    """
    Generates OpenAPI specification files for each API session.
    
    - If run_id is None, gets the latest run_id.
    - If run_id == "all", processes all run_id values (no filtering).
    - Otherwise, filters by a specific run_id.

    The function extracts:
      - Request headers (`is_required=1` headers are marked `required: true`)
      - Cookies (`is_required=1` cookies are marked `required: true`)
      - Query parameters
      - Response headers
      - Request/Response body schemas

    Each session's OpenAPI spec is stored as {pk}.json in `output_dir`.
    """

    # (A) Determine the run_id logic
    if run_id is None:
        run_id = get_latest_run_id(db_conn)
        if run_id is None:
            print("[ERROR] No run_id found in sessions. Exiting.")
            return
        print(f"[INFO] Using latest run_id: {run_id}")
    elif run_id.lower() == "all":
        print("[INFO] Processing ALL run_id values (no filtering).")
    else:
        print(f"[INFO] Processing specific run_id: {run_id}")

    # Ensure the output directory exists
    os.makedirs(output_dir, exist_ok=True)

    cursor = db_conn.cursor()

    # (B) Retrieve session information
    if run_id == "all":
        cursor.execute("""
            SELECT pk, method, protocol, host, path, query,
                   request_body, response_status, response_body, run_id
            FROM sessions
            ORDER BY pk
        """)
    else:
        cursor.execute("""
            SELECT pk, method, protocol, host, path, query,
                   request_body, response_status, response_body, run_id
            FROM sessions
            WHERE run_id = ?
            ORDER BY pk
        """, (run_id,))

    rows = cursor.fetchall()

    for row in tqdm(rows, desc="Generating OpenAPI specs", unit="session"):
        pk, method, protocol, host, path, query, request_body, response_status, response_body, actual_run_id = row

        # Construct the full path including query parameters
        path_with_query = path
        if query:
            path_with_query += "?" + query
        full_url = f"{protocol}{host}{path_with_query}"

        # ----------------------------
        # (A) Extract Request Headers (with is_required)
        # ----------------------------
        header_params = []
        hdr_cursor = db_conn.cursor()
        hdr_cursor.execute("""
            SELECT key, value, is_required
            FROM headers
            WHERE host = ? AND path = ? AND run_id = ?
        """, (host, path, actual_run_id))
        for hdr_key, hdr_val, is_req in hdr_cursor.fetchall():
            header_params.append({
                "name": hdr_key,
                "in": "header",
                "required": bool(is_req),  # Set required=True if is_required=1
                "schema": {"type": "string"},
                "example": hdr_val
            })

        # ----------------------------
        # (B) Extract Cookies (with is_required)
        # ----------------------------
        cookie_params = []
        c_cursor = db_conn.cursor()
        c_cursor.execute("""
            SELECT key, value, is_required
            FROM cookies
            WHERE host = ? AND path = ? AND run_id = ?
        """, (host, path, actual_run_id))
        for ckey, cval, is_req in c_cursor.fetchall():
            cookie_params.append({
                "name": ckey,
                "in": "cookie",
                "required": bool(is_req),  # Set required=True if is_required=1
                "schema": {"type": "string"},
                "example": cval
            })

        # ----------------------------
        # (C) Extract Query Parameters
        # ----------------------------
        query_params = []
        q_cursor = db_conn.cursor()
        q_cursor.execute("""
            SELECT param_name, param_value
            FROM request_params
            WHERE host = ? AND path = ? AND run_id = ?
        """, (host, path, actual_run_id))
        for pname, pvalue in q_cursor.fetchall():
            query_params.append({
                "name": pname,
                "in": "query",
                "required": False,  # Query params are usually optional
                "schema": {"type": "string"},
                "example": pvalue
            })

        # ----------------------------
        # (D) Extract Response Headers
        # ----------------------------
        response_headers_spec = {}
        r_cursor = db_conn.cursor()
        r_cursor.execute("""
            SELECT key, value
            FROM response_headers
            WHERE host = ? AND path = ? AND run_id = ?
        """, (host, path, actual_run_id))
        for rh_key, rh_val in r_cursor.fetchall():
            response_headers_spec[rh_key] = {
                "description": f"Response header {rh_key}",
                "schema": {"type": "string"},
                "example": rh_val
            }

        # ----------------------------
        # (E) Parse Request/Response Body
        # ----------------------------
        req_content_type, request_schema = parse_body_to_schema(request_body)
        resp_content_type, response_schema = parse_body_to_schema(response_body)

        # ----------------------------
        # (F) Construct OpenAPI Spec
        # ----------------------------
        openapi_spec = {
            "openapi": "3.0.0",
            "info": {
                "title": f"OpenAPI Spec for {full_url}",
                "version": "1.0.0"
            },
            "paths": {
                path_with_query: {
                    method.lower(): {
                        "parameters": header_params + cookie_params + query_params,
                        "requestBody": {
                            "content": {
                                req_content_type: {
                                    "schema": request_schema
                                }
                            }
                        },
                        "responses": {
                            str(response_status): {
                                "description": f"Response with status {response_status}",
                                "headers": response_headers_spec,
                                "content": {
                                    resp_content_type: {
                                        "schema": response_schema
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        # ----------------------------
        # (G) Save OpenAPI Spec to File
        # ----------------------------
        safe_filename = f"{pk}.json"
        output_file = os.path.join(output_dir, safe_filename)
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(openapi_spec, f, indent=4)

        print(f"[INFO] OpenAPI spec generated for {full_url} => {output_file}")

# ----------------------------
# Utility Functions
# ----------------------------

def get_latest_run_id(conn):
    """
    Retrieves the most recent run_id from the sessions table (descending order).
    """
    c = conn.cursor()
    c.execute("SELECT run_id FROM sessions ORDER BY run_id DESC LIMIT 1")
    row = c.fetchone()
    return row[0] if row else None

def parse_body_to_schema(body_str):
    """
    Attempts to parse body_str as JSON, else text/plain.
    Returns (content_type, schema).
    """
    if not body_str:
        return ("text/plain", {})
    try:
        obj = json.loads(body_str)
        schema = generate_json_schema(obj)
        return ("application/json", schema)
    except (json.JSONDecodeError, TypeError):
        return ("text/plain", {})

def generate_json_schema(json_obj):
    """
    Recursively generates a JSON schema with 'example' at each level.
    """
    if isinstance(json_obj, dict):
        return {"type": "object", "properties": {k: generate_json_schema(v) for k, v in json_obj.items()}, "example": json_obj}
    elif isinstance(json_obj, list):
        return {"type": "array", "items": generate_json_schema(json_obj[0]) if json_obj else {}, "example": json_obj}
    elif isinstance(json_obj, str):
        return {"type": "string", "example": json_obj}
    elif isinstance(json_obj, int):
        return {"type": "integer", "example": json_obj}
    elif isinstance(json_obj, float):
        return {"type": "number", "example": json_obj}
    elif isinstance(json_obj, bool):
        return {"type": "boolean", "example": json_obj}
    return {"type": "null", "example": None}
