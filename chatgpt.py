import openai
import yaml
import os
import json
import sqlite3

def process_sensitive_sessions_and_generate_openapi(db_name, output_dir):
    """Process sensitive sessions and generate individual OpenAPI specs."""
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    cursor.execute('''
        SELECT method, url, request_headers, request_body, response_body
        FROM sessions
        JOIN credentials ON sessions.id = credentials.session_id
    ''')

    session_count = 1
    os.makedirs(output_dir, exist_ok=True)

    for row in cursor.fetchall():
        session_data = {
            "method": row[0],
            "url": row[1],
            "request_headers": row[2],
            "request_body": row[3],
            "response_body": row[4]
        }

        # Check if session contains user-sensitive data via ChatGPT
        if ask_chatgpt(session_data):
            print(f"✅ Sensitive session detected: {row[1]}")

            # Generate OpenAPI spec for the session
            openapi_spec = generate_single_openapi_spec(session_data)

            # Save the spec to a file
            output_file = os.path.join(output_dir, f"openapi_session_{session_count}.yaml")
            with open(output_file, "w") as f:
                yaml.dump(openapi_spec, f, sort_keys=False)
            print(f"📄 OpenAPI spec saved: {output_file}")

            session_count += 1

    conn.close()

def ask_chatgpt(session_data):
    """Send the session data to ChatGPT and return the evaluation result."""
    prompt = f"""
    Analyze the following API request and response. Determine if the data relates to user-sensitive information like profiles, files, or messages.

    Request Method: {session_data['method']}
    URL: {session_data['url']}
    Request Headers: {session_data['request_headers']}
    Request Body: {session_data['request_body']}
    Response Body: {session_data['response_body']}

    Respond with 'Yes' if it contains user-sensitive data, otherwise respond with 'No'.
    """
    openai.api_key = os.getenv("OPENAI_API_KEY")
    response = openai.Completion.create(
        engine="gpt-4o-mini",
        prompt=prompt,
        max_tokens=10
    )

    answer = response.choices[0].text.strip().lower()
    return answer == "yes"

def generate_single_openapi_spec(session):
    """Generate OpenAPI specification for a single sensitive session."""
    query_params = extract_query_params(session["url"])
    request_body_schema = infer_json_schema(session["request_body"])
    response_body_schema = infer_json_schema(session["response_body"])

    openapi_spec = {
        "openapi": "3.0.0",
        "info": {
            "title": "Auto-Generated API Documentation",
            "version": "1.0.0"
        },
        "paths": {
            session["url"]: {
                session["method"].lower(): {
                    "summary": f"Detected sensitive API: {session['method'].upper()} {session['url']}",
                    "description": "This endpoint was detected as handling user-sensitive data.",
                    "parameters": query_params,
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": request_body_schema
                            }
                        }
                    } if session["request_body"] else None,
                    "responses": {
                        "200": {
                            "description": "Successful response",
                            "content": {
                                "application/json": {
                                    "schema": response_body_schema
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if not session["request_body"]:
        del openapi_spec["paths"][session["url"]][session["method"].lower()]["requestBody"]

    return openapi_spec

def extract_query_params(url):
    """Extract query parameters from the URL and format them for OpenAPI."""
    from urllib.parse import urlparse, parse_qs
    parsed_url = urlparse(url)
    query_params = []

    if parsed_url.query:
        query_dict = parse_qs(parsed_url.query)
        for param, values in query_dict.items():
            query_params.append({
                "name": param,
                "in": "query",
                "description": f"Query parameter '{param}'",
                "required": False,
                "schema": {
                    "type": "string" if len(values) == 1 else "array",
                    "items": {"type": "string"} if len(values) > 1 else None
                }
            })

    return query_params

def infer_json_schema(json_data):
    """Infer a basic JSON schema from the given JSON data."""
    try:
        parsed_data = json.loads(json_data)
        if isinstance(parsed_data, dict):
            return {
                "type": "object",
                "properties": {key: {"type": infer_type(value)} for key, value in parsed_data.items()}
            }
        elif isinstance(parsed_data, list):
            return {
                "type": "array",
                "items": {"type": infer_type(parsed_data[0]) if parsed_data else "string"}
            }
    except json.JSONDecodeError:
        pass  # Return a basic schema if the data is not valid JSON

    # Default fallback for non-JSON data
    return {"type": "string"}

def infer_type(value):
    """Infer the JSON type of a value."""
    if isinstance(value, str):
        return "string"
    elif isinstance(value, int):
        return "integer"
    elif isinstance(value, float):
        return "number"
    elif isinstance(value, bool):
        return "boolean"
    elif isinstance(value, list):
        return "array"
    elif isinstance(value, dict):
        return "object"
    else:
        return "string"
