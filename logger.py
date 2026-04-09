import json
import uuid
import datetime
import os

class AuditLogger:
    def __init__(self, log_dir="audit_logs"):
        self.log_dir = log_dir
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)

    def _write_log(self, log_type, violation_type, message):
        log_entry = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "type": log_type,
            "violation": violation_type,
            "message": message
        }
        
        # Write to a daily log file
        date_str = datetime.datetime.utcnow().strftime("%Y-%m-%d")
        log_path = os.path.join(self.log_dir, f"cspm_audit_{date_str}.jsonl")
        
        with open(log_path, "a") as f:
            f.write(json.dumps(log_entry) + "\n")
            
        print(f"[{log_type}] {message}")

    def log_finding(self, violation_type, message):
        """Log a detected misconfiguration."""
        self._write_log("FINDING", violation_type, message)

    def log_remediation(self, violation_type, message):
        """Log an automated remediation action taken."""
        self._write_log("REMEDIATION", violation_type, message)
