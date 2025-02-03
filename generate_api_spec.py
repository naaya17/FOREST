import os
import json

def generate_api_spec(db_conn, output_dir="openapi_specs"):
    cursor = db_conn.cursor()

    # Ensure the output directory exists
    os.makedirs(output_dir, exist_ok=True)

    # Read session information from the database
    cursor.execute("SELECT id, method, protocol, host, url, request_body, response_status, response_body FROM sessions")
    for session_id, method, protocol, host, url, request_body, response_status, response_body in cursor.fetchall():
        full_url = f"{protocol}{host}{url}"  # Combine protocol, host, and URL

        # Retrieve headers for this host to include in parameters
        headers_cursor = db_conn.cursor()
        headers_cursor.execute("SELECT key, value FROM headers WHERE host = ?", (host,))
        parameters = [
            {
                "name": header_key,
                "in": "header",
                "required": True,  # Assume headers are required by default; adjust as needed
                "schema": {"type": "string"},
                "example": header_value
            }
            for header_key, header_value in headers_cursor.fetchall()
        ]

        # Try to parse request body as JSON, fallback to plain text if parsing fails
        try:
            request_schema = generate_json_schema(json.loads(request_body)) if request_body else {}
            request_content_type = "application/json"
        except (json.JSONDecodeError, TypeError):
            request_schema = {}
            request_content_type = "text/plain"

        # Try to parse response body as JSON, fallback to plain text if parsing fails
        try:
            response_schema = generate_json_schema(json.loads(response_body)) if response_body else {}
            response_content_type = "application/json"
        except (json.JSONDecodeError, TypeError):
            response_schema = {}
            response_content_type = "text/plain"

        # Create a base OpenAPI spec structure
        openapi_spec = {
            "openapi": "3.0.0",
            "info": {
                "title": f"OpenAPI Spec for {full_url}",
                "version": "1.0.0"
            },
            "paths": {
                url: {
                    method.lower(): {
                        "parameters": parameters,  # Include header parameters
                        "requestBody": {
                            "content": {
                                request_content_type: {
                                    "schema": request_schema,
                                    "example": request_body if request_body else ""
                                }
                            }
                        },
                        "responses": {
                            str(response_status): {
                                "description": f"Response with status {response_status}",
                                "content": {
                                    response_content_type: {
                                        "schema": response_schema,
                                        "example": response_body if response_body else ""
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        # Create a safe file name based on the session ID
        safe_filename = f"{session_id}.json"
        output_file = os.path.join(output_dir, safe_filename)

        # Save each OpenAPI spec to a separate file
        with open(output_file, "w") as f:
            json.dump(openapi_spec, f, indent=4)
        print(f"OpenAPI spec generated for {full_url} at {output_file}")

# Function to generate JSON schema from a JSON object
def generate_json_schema(json_obj):
    if isinstance(json_obj, dict):
        return {
            "type": "object",
            "properties": {key: generate_json_schema(value) for key, value in json_obj.items()}
        }
    elif isinstance(json_obj, list) and json_obj:
        return {
            "type": "array",
            "items": generate_json_schema(json_obj[0])
        }
    elif isinstance(json_obj, str):
        return {"type": "string"}
    elif isinstance(json_obj, int):
        return {"type": "integer"}
    elif isinstance(json_obj, float):
        return {"type": "number"}
    elif isinstance(json_obj, bool):
        return {"type": "boolean"}
    else:
        return {"type": "null"}