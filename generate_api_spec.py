import os
import re
import json
from tqdm import tqdm

def generate_api_spec(db_conn, output_dir="openapi_specs", run_id=None):
    """
    Loads session data from the DB, performs JSON-based path parameterization if applicable,
    and then uses the resulting path to build and save an OpenAPI specification file for each session.
    """

    # Handle run_id logic
    if run_id is None:
        run_id = get_latest_run_id(db_conn)
        if run_id is None:
            print("[ERROR] No run_id found in sessions. Exiting.")
            return
        print(f"[INFO] Using latest_run_id: {run_id}")
    elif run_id.lower() == "all":
        print("[INFO] Processing ALL run_id values (no filtering).")
    else:
        print(f"[INFO] Processing specific run_id: {run_id}")

    os.makedirs(output_dir, exist_ok=True)
    cursor = db_conn.cursor()

    # Load session data
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

    # We'll store each session's info here
    sessions_info = []

    # JSON-based path parameterization
    for row in tqdm(rows, desc="Processing sessions", unit="session"):
        pk, method, protocol, host, path, query, req_body, resp_status, resp_body, actual_run_id = row

        # Combine path and query for reference
        path_with_query = path
        if query:
            path_with_query += "?" + query
        full_url = f"{protocol}{host}{path_with_query}"

        # Default: original path
        param_path = path

        # If request_body is JSON, attempt parameterization
        req_content_type, _ = parse_body_to_schema(req_body)
        if req_content_type == "application/json":
            try:
                req_obj = json.loads(req_body)
                param_path = parameterize_path_with_json(param_path, req_obj)
            except:
                pass

        # If response_body is JSON, attempt parameterization
        resp_content_type, _ = parse_body_to_schema(resp_body)
        if resp_content_type == "application/json":
            try:
                resp_obj = json.loads(resp_body)
                param_path = parameterize_path_with_json(param_path, resp_obj)
            except:
                pass

        sessions_info.append({
            "pk": pk,
            "method": method,
            "protocol": protocol,
            "host": host,
            "original_path": path,
            "query": query,
            "request_body": req_body,
            "response_status": resp_status,
            "response_body": resp_body,
            "final_path": param_path  # The final path after JSON-based parameterization
        })

    # Build and save OpenAPI specs
    for info in tqdm(sessions_info, desc="Building OpenAPI specs", unit="session"):
        pk = info["pk"]
        method = info["method"]
        protocol = info["protocol"]
        host = info["host"]
        original_path = info["original_path"]
        final_path = info["final_path"]
        query = info["query"]
        req_body = info["request_body"]
        resp_status = info["response_status"]
        resp_body = info["response_body"]

        # 1) Extract headers/cookies/query/response_headers
        header_params = extract_headers(db_conn, host, original_path, run_id)
        cookie_params = extract_cookies(db_conn, host, original_path, run_id)
        query_params = extract_query_params(db_conn, host, original_path, run_id)
        response_headers_spec = extract_response_headers(db_conn, host, original_path, run_id)

        # 2) Parse bodies into schemas
        req_content_type, request_schema = parse_body_to_schema(req_body)
        resp_content_type, response_schema = parse_body_to_schema(resp_body)

        # 3) Construct the OpenAPI spec
        full_url = f"{protocol}{host}{original_path}"
        openapi_spec = {
            "openapi": "3.0.0",
            "info": {
                "title": f"OpenAPI Spec for {full_url}",
                "version": "1.0.0"
            },
            "servers": [
                {"url": f"{protocol}{host}"}
            ],
            "paths": {
                final_path: {
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
                            str(resp_status): {
                                "description": f"Response with status {resp_status}",
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

        # If the request body contains a bearer token, add security settings
        if isinstance(req_body, str) and re.search(r"bearer\s+\S+", req_body, re.IGNORECASE):
            openapi_spec.setdefault("components", {})["securitySchemes"] = {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT"
                }
            }
            openapi_spec["paths"][final_path][method.lower()]["security"] = [
                {"bearerAuth": []}
            ]

        # 4) Save the file
        safe_filename = f"{pk}.json"
        output_file = os.path.join(output_dir, safe_filename)
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(openapi_spec, f, indent=4)

        print(f"[INFO] Final spec saved => {output_file}")


# ---------------------------------------------------------------------
# UTILITY FUNCTIONS
# ---------------------------------------------------------------------

def extract_headers(db_conn, host, path, run_id):
    """
    Retrieves a list of header parameters (key, value) from the 'headers' table for the given session data.
    Returns a list of dictionaries in the OpenAPI parameter format (in: header).
    """
    cursor = db_conn.cursor()
    cursor.execute("""
        SELECT key, value, is_required
        FROM headers
        WHERE host = ? AND path = ? AND run_id = ?
    """, (host, path, run_id))

    params = []
    for k, v, is_req in cursor.fetchall():
        params.append({
            "name": k,
            "in": "header",
            "required": bool(is_req),
            "schema": {"type": "string"},
            "example": v
        })
    return params


def extract_cookies(db_conn, host, path, run_id):
    """
    Retrieves a list of cookie parameters (key, value) from the 'cookies' table for the given session data.
    Returns a list of dictionaries in the OpenAPI parameter format (in: cookie).
    """
    cursor = db_conn.cursor()
    cursor.execute("""
        SELECT key, value, is_required
        FROM cookies
        WHERE host = ? AND path = ? AND run_id = ?
    """, (host, path, run_id))

    params = []
    for k, v, is_req in cursor.fetchall():
        params.append({
            "name": k,
            "in": "cookie",
            "required": bool(is_req),
            "schema": {"type": "string"},
            "example": v
        })
    return params


def extract_query_params(db_conn, host, path, run_id):
    """
    Retrieves a list of query parameters (param_name, param_value) from the 'request_params' table.
    Returns a list of dictionaries in the OpenAPI parameter format (in: query).
    """
    cursor = db_conn.cursor()
    cursor.execute("""
        SELECT param_name, param_value
        FROM request_params
        WHERE host = ? AND path = ? AND run_id = ?
    """, (host, path, run_id))

    params = []
    for pname, pvalue in cursor.fetchall():
        params.append({
            "name": pname,
            "in": "query",
            "required": False,
            "schema": {"type": "string"},
            "example": pvalue
        })
    return params


def extract_response_headers(db_conn, host, path, run_id):
    """
    Retrieves response headers (key, value) from the 'response_headers' table.
    Returns a dictionary that matches the OpenAPI format for response headers.
    Example:
      {
          "Content-Type": {
              "description": "Response header Content-Type",
              "schema": {"type": "string"},
              "example": "application/json"
          },
          ...
      }
    """
    cursor = db_conn.cursor()
    cursor.execute("""
        SELECT key, value
        FROM response_headers
        WHERE host = ? AND path = ? AND run_id = ?
    """, (host, path, run_id))

    resp_headers = {}
    for k, v in cursor.fetchall():
        resp_headers[k] = {
            "description": f"Response header {k}",
            "schema": {"type": "string"},
            "example": v
        }
    return resp_headers


def parameterize_path_with_json(original_path, example_data):
    """
    1) Flatten the example_data into (key, value) pairs where value is a string.
    2) Split the original_path by '/'.
    3) If a path segment == value, replace that segment with {key}.
    4) Return the updated path.
    """
    kv_pairs = flatten_json_to_pairs(example_data)
    segments = original_path.strip("/").split("/")

    for i, seg in enumerate(segments):
        for (k, v) in kv_pairs:
            if seg == v:
                segments[i] = "{" + k + "}"
                break

    return "/" + "/".join(segments)


def flatten_json_to_pairs(data, prefix=""):
    """
    Recursively gathers (key, value) pairs from a JSON-like object.
    Only stores pairs if 'value' is a string, so we can match path segments exactly.
    
    Example:
      data = {
        "driveId": "785c836add2fa75d",
        "nested": {"itemId": "root"}
      }
      => [("driveId", "785c836add2fa75d"), ("itemId", "root")]
    """
    pairs = []
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, str):
                pairs.append((k, v))
            elif isinstance(v, (dict, list)):
                pairs.extend(flatten_json_to_pairs(v, prefix + k + "."))
    elif isinstance(data, list):
        for item in data:
            pairs.extend(flatten_json_to_pairs(item, prefix))
    return pairs


def get_latest_run_id(conn):
    """
    Retrieves the most recent run_id from the sessions table in descending order.
    Returns None if there is no run_id.
    """
    c = conn.cursor()
    c.execute("SELECT run_id FROM sessions ORDER BY run_id DESC LIMIT 1")
    row = c.fetchone()
    return row[0] if row else None


def parse_body_to_schema(body_str):
    """
    Attempts to parse body_str as JSON. If successful, returns ("application/json", schema).
    Otherwise returns ("text/plain", {}) with an empty schema.
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
    Recursively generates a JSON schema with 'example' at each level,
    based on the data type of json_obj.
    """
    if isinstance(json_obj, dict):
        return {
            "type": "object",
            "properties": {k: generate_json_schema(v) for k, v in json_obj.items()},
            "example": json_obj
        }
    elif isinstance(json_obj, list):
        return {
            "type": "array",
            "items": generate_json_schema(json_obj[0]) if json_obj else {},
            "example": json_obj
        }
    elif isinstance(json_obj, str):
        return {"type": "string", "example": json_obj}
    elif isinstance(json_obj, int):
        return {"type": "integer", "example": json_obj}
    elif isinstance(json_obj, float):
        return {"type": "number", "example": json_obj}
    elif isinstance(json_obj, bool):
        return {"type": "boolean", "example": json_obj}
    return {"type": "null", "example": None}
