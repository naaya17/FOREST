import os
import json
import argparse
from itertools import combinations

SKIP_KEYS = {"properties", "value", "items"}  # container-like keys we want to skip

def extract_key_paths_from_schema(schema, prefix="", skip_type=True, skip_example=True):
    """
    Recursively extracts hierarchical key paths from a given schema object.
    
    - If a key is in SKIP_KEYS (e.g. "properties", "value", "items"), we do not include it
      in the path but continue to recurse into it, effectively flattening that level.
    - If skip_type is True, any key that equals "type" (case-insensitive) is skipped.
    - If skip_example is True, any key that starts with "example" (case-insensitive) is skipped.
    
    Example:
      If we see a path like:
        "properties" -> "folder" -> "properties" -> "folderView" -> "properties" -> "sortBy"
      we flatten it to:
        "folder.folderView.sortBy"
    """
    paths = set()
    if isinstance(schema, dict):
        for key, value in schema.items():
            # 1) Check if key should be skipped entirely
            lowered_key = key.lower()
            if skip_example and lowered_key.startswith("example"):
                continue
            if skip_type and lowered_key == "type":
                continue
            
            # 2) If key is a known container (properties, value, items), skip adding it
            #    to the path but recurse inside.
            if lowered_key in SKIP_KEYS:
                paths.update(extract_key_paths_from_schema(value, prefix, skip_type, skip_example))
            else:
                # Normal key -> add it to the path
                new_prefix = f"{prefix}.{key}" if prefix else key
                paths.add(new_prefix)
                paths.update(extract_key_paths_from_schema(value, new_prefix, skip_type, skip_example))
    elif isinstance(schema, list):
        for item in schema:
            paths.update(extract_key_paths_from_schema(item, prefix, skip_type, skip_example))
    return paths

def extract_schema_keys_from_spec(openapi_spec):
    """
    Extracts hierarchical key paths from the requestBody and response schemas for each endpoint (by method)
    in an OpenAPI specification, skipping container-like keys (properties, value, items).
    
    Returns a structure like:
      {
          <path>: {
              <method>: {
                  "requestBody": <set of flattened key paths> or empty set,
                  "responses": {
                      <status>: <set of flattened key paths> or empty set,
                      ...
                  }
              },
              ...
          },
          ...
      }
    """
    schema_summary = {}
    paths = openapi_spec.get("paths", {})
    for path, methods in paths.items():
        schema_summary.setdefault(path, {})
        for method, details in methods.items():
            method_summary = {"requestBody": set(), "responses": {}}
            
            # Process requestBody
            if "requestBody" in details:
                content = details["requestBody"].get("content", {})
                for ct, content_info in content.items():
                    if "schema" in content_info:
                        schema = content_info["schema"]
                        flattened_keys = extract_key_paths_from_schema(schema, prefix="")
                        method_summary["requestBody"] = flattened_keys
                        break  # Use only the first content-type
            
            # Process responses
            responses = details.get("responses", {})
            for status, response_info in responses.items():
                content = response_info.get("content", {})
                for ct, content_info in content.items():
                    if "schema" in content_info:
                        schema = content_info["schema"]
                        flattened_keys = extract_key_paths_from_schema(schema, prefix="")
                        method_summary["responses"][status] = flattened_keys
                        break
            
            schema_summary[path][method] = method_summary
    return schema_summary

def load_specs_from_folder(spec_folder):
    """
    Loads all OpenAPI spec JSON files from the specified folder and returns a dictionary
    mapping filename to the extracted hierarchical schema keys.
    """
    specs = {}
    for filename in os.listdir(spec_folder):
        if filename.endswith(".json"):
            filepath = os.path.join(spec_folder, filename)
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    spec = json.load(f)
                    extracted = extract_schema_keys_from_spec(spec)
                    specs[filename] = extracted
            except Exception as e:
                print(f"Error loading {filename}: {e}")
    return specs

def combine_endpoint_schema(details):
    """
    Combines all hierarchical key paths from requestBody and responses into a single set.
    """
    combined = set()
    combined.update(details.get("requestBody", set()))
    responses = details.get("responses", {})
    for status, keys in responses.items():
        combined.update(keys)
    return combined

def jaccard_similarity(set1, set2):
    """
    Calculates the Jaccard similarity between two sets.
    """
    if not set1 and not set2:
        return 1.0  # Both empty; treat as identical
    union = set1 | set2
    if not union:
        return 0.0
    return len(set1 & set2) / len(union)

def group_similar_apis_fuzzy(specs, threshold=0.75):
    """
    Groups endpoints from all spec files based on the combined set of hierarchical schema keys,
    using fuzzy matching with a given similarity threshold.
    
    If both endpoints have an empty combined schema, they are considered similar only if their path
    and method are identical.
    
    Each endpoint is stored as a dictionary with keys: {"file", "path", "method", "schema"}.
    """
    endpoints = []
    for file, spec in specs.items():
        for path, methods in spec.items():
            for method, details in methods.items():
                combined_schema = combine_endpoint_schema(details)
                endpoints.append({
                    "file": file,
                    "path": path,
                    "method": method,
                    "schema": combined_schema
                })
    
    # Debug: print the extracted schema for each endpoint
    for ep in endpoints:
        print(f"{ep['file']} {ep['path']} [{ep['method']}] => Flattened Schema: {sorted(ep['schema'])}")
    
    groups = []
    used = [False] * len(endpoints)
    for i in range(len(endpoints)):
        if used[i]:
            continue
        group = [endpoints[i]]
        used[i] = True
        for j in range(i+1, len(endpoints)):
            if used[j]:
                continue
            # If both endpoints have an empty schema, compare path and method
            if not endpoints[i]["schema"] and not endpoints[j]["schema"]:
                if endpoints[i]["path"] == endpoints[j]["path"] and endpoints[i]["method"] == endpoints[j]["method"]:
                    sim = 1.0
                else:
                    sim = 0.0
            else:
                sim = jaccard_similarity(endpoints[i]["schema"], endpoints[j]["schema"])
            if sim >= threshold:
                ep = endpoints[j].copy()
                ep["sim"] = sim
                group.append(ep)
                used[j] = True
        groups.append(group)
    return groups

def main():
    parser = argparse.ArgumentParser(
        description="Group similar APIs (fuzzy matching by hierarchical schema structure) from OpenAPI spec JSON files, skipping container keys like 'properties', 'value', 'items'."
    )
    parser.add_argument("spec_folder", help="Folder containing OpenAPI spec JSON files")
    parser.add_argument("--threshold", type=float, default=0.65, help="Similarity threshold (default: 0.75)")
    args = parser.parse_args()

    specs = load_specs_from_folder(args.spec_folder)
    if not specs:
        print("No valid OpenAPI spec files found in the folder.")
        return

    groups = group_similar_apis_fuzzy(specs, threshold=args.threshold)

    print("\nPairwise similarity scores for similar API groups (excluding groups with only one endpoint):")
    group_idx = 0
    for group in groups:
        if len(group) <= 1:
            continue  # Exclude groups with only one endpoint
        group_idx += 1
        print(f"\nGroup {group_idx}:")
        for ep1, ep2 in combinations(group, 2):
            sim_score = jaccard_similarity(ep1["schema"], ep2["schema"])
            print(f"{ep1['file']} ({ep1['path']} [{ep1['method']}])")
            print(f"{ep2['file']} ({ep2['path']} [{ep2['method']}])")
            print(f"=> Similarity: {sim_score:.2f}\n")

if __name__ == "__main__":
    main()
