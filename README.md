# Auth Log Analyzer

A simple Python script to analyze failed SSH authentication attempts from log files. It summarizes attempts per IP address and can generate a structured JSON report.

## 🚀 Usage

### On Linux / macOS

```bash
python3 auth_log_analyzer.py -l /path/to/logfile -o /path/to/output.json
```

### On Windows

```bash
python auth_log_analyzer.py -l C:\path\to\logfile -o C:\path\to\output.json
```

### Arguments

- `-l`, `--log`: **(required)** Path to the log file to analyze.
- `-o`, `--output`: Path to save the output as a JSON file (optional).

### 📝 Example

```bash
python auth_log_analyzer.py -l logs\sample.log -o report.json
```

## 📦 Output Example (JSON)

```json
{
    "analyzed_file": "logs/sample.log",
    "unique_attackers": 3,
    "attack_summary": {
        "192.168.1.10": 5,
        "203.0.113.25": 3,
        "10.0.0.2": 1
    }
}
```

## 📁 Logs

Make sure your log file follows a similar structure to `/var/log/auth.log`.

---

🔍For security analysis.
