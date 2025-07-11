#  FOREST: Inspecting and tracking RESTful APIs for constructing a cloud forensic knowledge base

FOREST is a research framework designed to support both digital forensic investigations and proactive security auditing by analyzing RESTful API behaviors. It enables the detection of undocumented endpoints, extraction of user-related data, and generation of OpenAPI specifications through real-world network traffic.

## 🧩 Features

- Detect undocumented (internal) RESTful API endpoints
- Extract sensitive user-related data from captured HTTP sessions
- Identify required request headers, cookies, and parameters
- Convert HTTP traffic into OpenAPI-compatible specifications
- Track changes in request/response schemas across versions
- Integrate AI-powered contextual analysis for forensic relevance

## 🛠️ Main Components

| File                          | Description |
|------------------------------|-------------|
| `forest.py`                  | Core engine for parsing HTTP sessions and identifying APIs |
| `generate_api_spec.py`       | Converts filtered API traffic into OpenAPI Specification format |
| `compare_specs.py`           | Compares OpenAPI schemas to detect structural changes |
| `test_required_paramters.py` | Tests required headers/cookies by removing them systematically |
| `db_schema.py`               | Defines the SQLite schema for storing API snapshot history |
| `openai_api_analyzer.py`     | Uses OpenAI API to detect user-sensitive data in responses |
| `loggers.py`                 | Logging utilities |
| `target_domains_dict.txt`   | List of target domains for domain-based filtering |
| `user_data_dict.txt`        | Keyword definitions for identifying user-related data |

## 📂 Folder Structure (Flat View)

FOREST/ \
├── forest.py \
├── generate_api_spec.py \
├── compare_specs.py \
├── test_required_paramters.py \
├── db_schema.py \
├── openai_api_analyzer.py \
├── loggers.py \
├── target_domains_dict.txt \
├── user_data_dict.txt \
├── README.md


## 🚀 Usage

### 🔧 Command Line Options: `forest.py`

You can use `forest.py` to process `.saz` files captured via tool like Fiddler, extract sensitive user-related API sessions, test request dependencies, and generate OpenAPI specifications.


| Option                          | Description |
|--------------------------------|-------------|
| `saz_file`                     | **(positional)** Path to the `.saz` file containing captured HTTP sessions |
| `-o`, `--db_name`              | SQLite database file name to store parsed results (default: `results.db`) |
| `--user_keywords_file`         | File containing user-sensitive keywords (default: `user_data_dict.txt`) |
| `--target_domains_file`        | File containing relevant target domains (default: `target_domains_dict.txt`) |
| `--test_required_parameters`   | Test which request headers/cookies/params are essential (removal-based) |
| `--generate_open_api_spec`     | Automatically generate OpenAPI specs from valid API sessions |
| `--run_id`                     | Specify a `run_id` to filter or label analysis (optional) |
| `--verbose`                    | Enable debug-level logging (default: INFO level) |

### 🧪 Example Commands

**Basic API session extraction**
```bash
python forest.py captured_traffic.saz --generate_open_api_spec --test_required_parameters
```

---

### 🔧 Command Line Options: `compare_specs.py`

You can use `compare_specs.py` to load OpenAPI spec files from a folder, store them in a database, and automatically detect schema-level changes across versions based on structural similarity.

| Option             | Description |
|--------------------|-------------|
| `--spec_folder`    | **(required)** Folder containing OpenAPI `.json` files for multiple API versions |
| `--db`             | SQLite database file path (default: `api_history.db`) |
| `--threshold`      | Schema similarity threshold for grouping (default: `0.55`) |

---

### 🧪 Example Commands

**Compare API schemas across multiple OpenAPI specs in a folder:**

```bash
python compare_specs.py --spec_folder ./openapi_specs
python compare_specs.py --spec_folder ./openapi_specs --db api_history.db --threshold 0.55
```
