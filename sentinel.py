import re
import time
import json
import logging
from collections import defaultdict
from datetime import datetime, timedelta

# Setup sentinel's own logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
log = logging.getLogger("log-sentinel")

# Configuration
CONFIG = {
    "log_path": "test_auth.log",
    "state_path": "sentinel_state.json",
    "alert_threshold": 5,
    "alert_window_minutes": 10,
    "poll_interval_sec": 2
}

class StateManager:
    def __init__(self, path):
        self.path = path
        self.data = self._load()

    def _load(self):
        try:
            with open(self.path, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {"offset": 0, "alerts": {}}

    def save(self):
        with open(self.path, "w") as f:
            json.dump(self.data, f)

class LogSentinel:
    def __init__(self, config):
        self.config = config
        self.state = StateManager(config["state_path"])
        # Regex for typical sshd failed auth lines (adjust for your OS)
        self.pattern = re.compile(
            r"Failed password for (?:invalid user )?\S+ from (\d+\.\d+\.\d+\.\d+) port \d+"
        )
        self.failed_counts = defaultdict(list)  # ip -> [timestamp, ...]

    def _read_new_lines(self):
        with open(self.config["log_path"], "r") as f:
            f.seek(self.state.data["offset"])
            new_lines = f.readlines()
            self.state.data["offset"] = f.tell()
        return new_lines

    def _process_lines(self, lines):
        now = datetime.now()
        window = timedelta(minutes=self.config["alert_window_minutes"])

        for line in lines:
            match = self.pattern.search(line)
            if not match:
                continue
            ip = match.group(1)
            self.failed_counts[ip].append(now)

            # Prune old timestamps outside the window
            self.failed_counts[ip] = [
                ts for ts in self.failed_counts[ip] if (now - ts) <= window
            ]

            # Check threshold
            if len(self.failed_counts[ip]) >= self.config["alert_threshold"]:
                self._trigger_alert(ip)

    def _trigger_alert(self, ip):
        alert_key = f"{ip}_{datetime.now().strftime('%Y%m%d_%H%M')}"
        if alert_key in self.state.data["alerts"]:
            return  # Deduplicate within window

        log.warning(f"🚨 ALERT: {self.config['alert_threshold']}+ failed SSH logins from {ip} in {self.config['alert_window_minutes']}m window")
        # In production: send to webhook, syslog, ticketing system, or trigger SOAR
        self.state.data["alerts"][alert_key] = datetime.now().isoformat()
        self.state.save()

    def run(self):
        log.info(f"Starting log sentinel on {self.config['log_path']}")
        while True:
            try:
                lines = self._read_new_lines()
                if lines:
                    self._process_lines(lines)
                time.sleep(self.config["poll_interval_sec"])
            except KeyboardInterrupt:
                log.info("Shutting down gracefully.")
                self.state.save()
                break
            except Exception as e:
                log.error(f"Unexpected error: {e}")
                time.sleep(5)

if __name__ == "__main__":
    sentinel = LogSentinel(CONFIG)
    sentinel.run()