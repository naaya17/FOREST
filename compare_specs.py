# api_schema_tracker.py
import os
import json
import re
import sqlite3
import datetime
from collections import defaultdict

SKIP_KEYS = {"properties", "value", "items"}

def init_db(db_path="api_history.db"):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS api_snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        snapshot_id TEXT NOT NULL,
        file_name TEXT NOT NULL,
        path TEXT NOT NULL,
        method TEXT NOT NULL,
        request_keys TEXT,
        response_keys TEXT,
        raw_request_keys TEXT,
        raw_response_keys TEXT,
        request_values TEXT,
        response_values TEXT,
        UNIQUE(snapshot_id, path, method)
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS api_match_groups (
        group_id INTEGER PRIMARY KEY AUTOINCREMENT,
        similarity REAL,
        union_keys TEXT,
        intersection_keys TEXT
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS api_match_group_members (
        group_id INTEGER,
        snapshot_id TEXT,
        path TEXT,
        method TEXT,
        sim_score REAL,
        file_name TEXT,
        removed_request_keys TEXT,
        added_request_keys TEXT,
        removed_response_keys TEXT,
        added_response_keys TEXT,
        is_baseline INTEGER DEFAULT 0,
        PRIMARY KEY(group_id, snapshot_id, path, method)
    )""")

    conn.commit()
    conn.close()

# ------------------------- Schema Extraction ---------------------------


def extract_key_paths_from_schema(schema, prefix="", skip_type=True, skip_example=True):
    paths = set()
    if isinstance(schema, dict):
        for key, value in schema.items():
            lowered_key = key.lower()
            if skip_example and lowered_key.startswith("example"):
                continue
            if skip_type and lowered_key == "type":
                continue
            if lowered_key in SKIP_KEYS:
                paths.update(extract_key_paths_from_schema(value, prefix, skip_type, skip_example))
            else:
                new_prefix = f"{prefix}.{key}" if prefix else key
                paths.add(new_prefix)
                paths.update(extract_key_paths_from_schema(value, new_prefix, skip_type, skip_example))
    elif isinstance(schema, list):
        for item in schema:
            paths.update(extract_key_paths_from_schema(item, prefix, skip_type, skip_example))

    return paths

def replace_values_with_key_names(key_paths, value_to_keys):
        value_name_map = {}
        for val, names in value_to_keys.items():
            if len(val) > 6 and all(c.isalnum() for c in val):
                preferred_names = [n for n in names if n != "id"]
                if preferred_names:
                    most_common = max(set(preferred_names), key=preferred_names.count)
                else:
                    most_common = "id"
                value_name_map[val] = most_common

        replaced = set()
        for path in key_paths:
            for val, name in value_name_map.items():
                if val in path:
                    path = path.replace(val, f"<{name}>")
            replaced.add(path)
        return replaced

def collect_examples_from_schema(schema, prefix="", value_to_keys=None):
    if value_to_keys is None:
        value_to_keys = defaultdict(list)

    if isinstance(schema, dict):
        if "example" in schema:
            key_name = prefix.split('.')[-1] if prefix else "root"
            value_to_keys[str(schema["example"])].append(key_name)

        if schema.get("type") == "array" and "items" in schema:
            collect_examples_from_schema(schema["items"], f"{prefix}.items" if prefix else "items", value_to_keys)

        elif schema.get("type") == "object" and "properties" in schema:
            for prop, prop_schema in schema["properties"].items():
                collect_examples_from_schema(prop_schema, f"{prefix}.{prop}" if prefix else prop, value_to_keys)

    elif isinstance(schema, list):
        for item in schema:
            collect_examples_from_schema(item, prefix, value_to_keys)

    return value_to_keys

def build_global_value_map(spec_folder):
    global_value_map = defaultdict(list)

    for filename in os.listdir(spec_folder):
        if filename.endswith(".json") and not filename.startswith("."):
            path = os.path.join(spec_folder, filename)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    spec = json.load(f)
                    paths = spec.get("paths", {})

                    for path_item in paths.values():
                        for method_info in path_item.values():
                            # RequestBody
                            content = method_info.get("requestBody", {}).get("content", {})
                            for media in content.values():
                                schema = media.get("schema")
                                if schema:
                                    collect_examples_from_schema(schema, value_to_keys=global_value_map)

                            # Responses
                            responses = method_info.get("responses", {})
                            for response in responses.values():
                                content = response.get("content", {})
                                for media in content.values():
                                    schema = media.get("schema")
                                    if schema:
                                        collect_examples_from_schema(schema, value_to_keys=global_value_map)

            except Exception as e:
                print(f"❌ 오류 ({filename}): {e}")

    return global_value_map

def extract_schema_keys_from_spec(openapi_spec, global_value_map=None):
    schema_summary = {}

    paths = openapi_spec.get("paths", {})
    for path, methods in paths.items():
        schema_summary.setdefault(path, {})
        for method, details in methods.items():
            method_summary = {
                "requestBody": set(),
                "responses": {},
                "raw_request_keys": set(),
                "raw_response_keys": set(),
                "request_values": {},
                "response_values": {}
            }

            # 오직 requestBody schema에서만 값을 수집
            request_body_content = details.get("requestBody", {}).get("content", {})
            for content_info in request_body_content.values():
                schema = content_info.get("schema")
                if schema:
                    raw_keys = extract_key_paths_from_schema(schema)
                    method_summary["raw_request_keys"] = raw_keys

                    value_map = collect_examples_from_schema(schema)
                    method_summary["request_values"] = value_map

                    replaced_keys = replace_values_with_key_names(raw_keys, global_value_map or value_map)
                    method_summary["requestBody"] = replaced_keys

            # 오직 response schema에서만 값을 수집 (headers 무시)
            responses = details.get("responses", {})
            for status, response_info in responses.items():
                response_content = response_info.get("content", {})
                for content_info in response_content.values():
                    schema = content_info.get("schema")
                    if schema:
                        raw_keys = extract_key_paths_from_schema(schema)
                        method_summary["raw_response_keys"].update(raw_keys)

                        value_map = collect_examples_from_schema(schema)
                        method_summary["response_values"].update(value_map)

                        replaced_keys = replace_values_with_key_names(raw_keys, global_value_map or value_map)
                        method_summary["responses"][status] = replaced_keys
                    

            schema_summary[path][method] = method_summary

    return schema_summary


# ------------------------- Load and Store ------------------------------

def generate_snapshot_id(file_name):
    base = os.path.splitext(file_name)[0]
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{base}_{timestamp}"

def store_spec_to_db(spec, snapshot_id, file_name, db_path="api_history.db", global_value_map=None):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    schema_summary = extract_schema_keys_from_spec(spec, global_value_map)

    for path, methods in schema_summary.items():
        for method, details in methods.items():
            request_keys = sorted(details.get("requestBody", set()))
            response_keys = sorted(set().union(*details.get("responses", {}).values()))
            cur.execute("""
                INSERT OR REPLACE INTO api_snapshots
                (snapshot_id, file_name, path, method, request_keys, response_keys, raw_request_keys, raw_response_keys, request_values, response_values)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                snapshot_id,
                file_name,
                path,
                method.upper(),
                json.dumps(request_keys),
                json.dumps(response_keys),
                json.dumps(list(details.get("raw_request_keys", []))),
                json.dumps(list(details.get("raw_response_keys", []))),
                json.dumps(details.get("request_values", {})),
                json.dumps(details.get("response_values", {}))
            ))

    conn.commit()
    conn.close()

def store_all_specs_in_folder(spec_folder, db_path="api_history.db"):
    init_db(db_path)
    global_value_map = build_global_value_map(spec_folder)

    for filename in os.listdir(spec_folder):
        if filename.endswith(".json") and not filename.startswith("."):
            path = os.path.join(spec_folder, filename)
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    spec = json.load(f)
                    snapshot_id = generate_snapshot_id(filename)
                    store_spec_to_db(spec, snapshot_id, filename, db_path, global_value_map)
                    print(f"✅ 저장됨: {filename} → snapshot_id: {snapshot_id}")
            except Exception as e:
                print(f"❌ 오류 ({filename}): {e}")

# ------------------------- Comparison ----------------------------------

def jaccard_similarity(set1, set2):
    if not set1 and not set2:
        return 1.0
    union = set1 | set2
    if not union:
        return 0.0
    return len(set1 & set2) / len(union)

def compare_all_snapshots(threshold=0.55, db_path="api_history.db"):
    def track_schema_changes(group_id, cur, global_value_map):
        cur.execute("""
            SELECT m.snapshot_id, m.path, m.method, s.raw_request_keys, s.raw_response_keys
            FROM api_match_group_members m
            JOIN api_snapshots s ON m.snapshot_id = s.snapshot_id 
                AND m.path = s.path 
                AND m.method = s.method
            WHERE m.group_id = ?
            ORDER BY m.snapshot_id ASC
        """, (group_id,))
        rows = cur.fetchall()
        if len(rows) < 2:
            return

        base_req = replace_values_with_key_names(set(json.loads(rows[0][3] or "[]")), global_value_map)
        base_res = replace_values_with_key_names(set(json.loads(rows[0][4] or "[]")), global_value_map)

        cur.execute("""
            UPDATE api_match_group_members
            SET is_baseline = 1, sim_score = 1.0
            WHERE group_id = ? AND snapshot_id = ? AND path = ? AND method = ?
        """, (group_id, rows[0][0], rows[0][1], rows[0][2]))

        for row in rows[1:]:
            cur_req = replace_values_with_key_names(set(json.loads(row[3] or "[]")), global_value_map)
            cur_res = replace_values_with_key_names(set(json.loads(row[4] or "[]")), global_value_map)
            removed_req = sorted(base_req - cur_req)
            added_req = sorted(cur_req - base_req)
            removed_res = sorted(base_res - cur_res)
            added_res = sorted(cur_res - base_res)

            # ✅ baseline 기준 유사도 계산
            sim_score = jaccard_similarity(base_req | base_res, cur_req | cur_res)

            cur.execute("""
                UPDATE api_match_group_members
                SET removed_request_keys = ?, added_request_keys = ?,
                    removed_response_keys = ?, added_response_keys = ?,
                    sim_score = ?
                WHERE group_id = ? AND snapshot_id = ? AND path = ? AND method = ?
            """, (
                json.dumps(removed_req),
                json.dumps(added_req),
                json.dumps(removed_res),
                json.dumps(added_res),
                sim_score,
                group_id, row[0], row[1], row[2]
            ))

            # base_req, base_res = cur_req, cur_res  # 🔁 비슷한 또 다른 순서로 변경되는 경우 이 라인 취소로 해제해 사용가능

    # ✅ 전역 global_value_map 구성
    global_value_map = defaultdict(list)
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT request_values, response_values FROM api_snapshots")
    for row in cur.fetchall():
        for raw in row:
            try:
                valmap = json.loads(raw or "{}")
                for val, keys in valmap.items():
                    global_value_map[val].extend(keys)
            except:
                continue

    # ✅ raw 키 불러오기 후 치환 적용
    cur.execute("SELECT snapshot_id, path, method, raw_request_keys, raw_response_keys, file_name FROM api_snapshots")
    rows = cur.fetchall()
    endpoints = []
    for row in rows:
        raw_req = set(json.loads(row[3] or "[]"))
        raw_res = set(json.loads(row[4] or "[]"))
        replaced_req = replace_values_with_key_names(raw_req, global_value_map)
        replaced_res = replace_values_with_key_names(raw_res, global_value_map)
        schema = replaced_req | replaced_res
        endpoints.append({
            "snapshot_id": row[0],
            "path": row[1],
            "method": row[2],
            "file": row[5],
            "schema": schema
        })

    # ✅ 기존 그룹 정보 로딩 및 비교
    cur.execute("SELECT group_id FROM api_match_groups")
    all_group_ids = [row[0] for row in cur.fetchall()]
    for gid in all_group_ids:
        track_schema_changes(gid, cur, global_value_map)

    existing_groups = defaultdict(list)
    already_grouped_apis = set()
    cur.execute("""
        SELECT g.group_id, s.snapshot_id, s.path, s.method, s.raw_request_keys, s.raw_response_keys, s.file_name
        FROM api_match_group_members g
        JOIN api_snapshots s ON g.snapshot_id = s.snapshot_id AND g.path = s.path AND g.method = s.method
    """)
    for row in cur.fetchall():
        raw_req = set(json.loads(row[4] or "[]"))
        raw_res = set(json.loads(row[5] or "[]"))
        replaced_req = replace_values_with_key_names(raw_req, global_value_map)
        replaced_res = replace_values_with_key_names(raw_res, global_value_map)
        schema = replaced_req | replaced_res
        existing_groups[row[0]].append({
            "group_id": row[0], "snapshot_id": row[1], "path": row[2], "method": row[3],
            "schema": schema, "file": row[6]
        })
        already_grouped_apis.add((row[2], row[3], row[1]))

    used = [False] * len(endpoints)
    newly_updated_groups = set()

    for i in range(len(endpoints)):
        key = (endpoints[i]["path"], endpoints[i]["method"], endpoints[i]["snapshot_id"])
        if used[i] or key in already_grouped_apis:
            used[i] = True
            continue

        matched_group_id = None
        best_sim = 0
        for group_id, members in existing_groups.items():
            for ep in members:
                sim = jaccard_similarity(endpoints[i]["schema"], ep["schema"])
                if sim > best_sim:
                    best_sim = sim
                    matched_group_id = group_id

        if best_sim >= threshold:
            cur.execute("""
                INSERT OR IGNORE INTO api_match_group_members
                (group_id, snapshot_id, path, method, sim_score, file_name)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (matched_group_id, endpoints[i]["snapshot_id"], endpoints[i]["path"],
                  endpoints[i]["method"], 0.0, endpoints[i]["file"]))
            existing_groups[matched_group_id].append({
                "group_id": matched_group_id, "snapshot_id": endpoints[i]["snapshot_id"],
                "path": endpoints[i]["path"], "method": endpoints[i]["method"],
                "schema": endpoints[i]["schema"], "file": endpoints[i]["file"]
            })
            already_grouped_apis.add(key)
            newly_updated_groups.add(matched_group_id)  # ✅ 변경된 그룹 다시 비교하도록 등록
            used[i] = True
            continue

        # 새 그룹 생성
        group = [endpoints[i]]
        used[i] = True
        for j in range(i + 1, len(endpoints)):
            if used[j]:
                continue
            sim = jaccard_similarity(endpoints[i]["schema"], endpoints[j]["schema"])
            if sim >= threshold:
                endpoints[j]["sim"] = sim
                group.append(endpoints[j])
                used[j] = True

        if len(group) > 1:
            union_keys = sorted(set().union(*[ep["schema"] for ep in group]))
            intersection_keys = sorted(set.intersection(*[ep["schema"] for ep in group]))
            avg_sim = sum(ep.get("sim", 1.0) for ep in group) / len(group)

            cur.execute("""
                INSERT INTO api_match_groups (similarity, union_keys, intersection_keys)
                VALUES (?, ?, ?)
            """, (avg_sim, json.dumps(union_keys), json.dumps(intersection_keys)))
            group_id = cur.lastrowid

            for ep in group:
                cur.execute("""
                    INSERT INTO api_match_group_members
                    (group_id, snapshot_id, path, method, sim_score, file_name)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (group_id, ep["snapshot_id"], ep["path"], ep["method"], 0.0, ep["file"]))
                existing_groups[group_id].append({
                    "group_id": group_id, "snapshot_id": ep["snapshot_id"],
                    "path": ep["path"], "method": ep["method"],
                    "schema": ep["schema"], "file": ep["file"]
                })
                already_grouped_apis.add((ep["path"], ep["method"], ep["snapshot_id"]))

            newly_updated_groups.add(group_id)

    for gid in newly_updated_groups:
        track_schema_changes(gid, cur, global_value_map)

    conn.commit()
    conn.close()


# ------------------------- 실행 시작점 ---------------------------------

if __name__ == "__main__":
    SPEC_FOLDER = "./openapi_specs"
    store_all_specs_in_folder(SPEC_FOLDER)
    compare_all_snapshots(threshold=0.55)
    print("🎉 스냅샷 저장 및 비교 완료!")
