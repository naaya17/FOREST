import sqlite3

def create_database(db_name):
    """
    Creates (or opens) a SQLite database with:
      - sessions (split into path and query columns)
      - headers, cookies, response_headers, request_params
        which also store host + path (or path + query) if needed.
    """
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    # sessions: now has path, query instead of a single url column
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            pk INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT,
            session_id TEXT,
            method TEXT,
            protocol TEXT,
            host TEXT,
            path TEXT,
            query TEXT,
            request_headers TEXT,
            request_body TEXT,
            is_body_required INTEGER DEFAULT 0,
            response_status INTEGER,
            response_headers TEXT,
            response_body TEXT
        )
    ''')

    # headers: run_id + host + path (optional query if you want)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS headers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT,
            host TEXT,
            path TEXT,
            key TEXT,
            value TEXT,
            is_required INTEGER DEFAULT 0,
            UNIQUE(run_id, host, path, key, value)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cookies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT,
            host TEXT,
            path TEXT,
            key TEXT,
            value TEXT,
            is_required INTEGER DEFAULT 0,
            UNIQUE(run_id, host, path, key, value)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS response_headers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT,
            host TEXT,
            path TEXT,
            key TEXT,
            value TEXT,
            UNIQUE(run_id, host, path, key, value)
        )
    ''')

    # request_params: run_id + host + path + param_name + param_value
    # (if you want to store query or not is up to you)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS request_params (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT,
            host TEXT,
            path TEXT,
            param_name TEXT,
            param_value TEXT,
            UNIQUE(run_id, host, path, param_name, param_value)
        )
    ''')
    conn.commit()
    return conn
