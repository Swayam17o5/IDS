"""
services/demo/nmap_demo.py
--------------------------
Controlled Authorized Nmap Demonstration Runner for AegisNIDS.

SAFETY NOTICE & LAB GUARDRAILS:
  - Exclusively authorized for local lab/testing environments.
  - STRICT TARGET VALIDATION: Only loopback (127.0.0.1) and RFC1918 private subnets
    (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) are permitted.
  - All public, WAN, and unauthorized destination addresses are strictly rejected.
  - No arbitrary command execution: strictly parameterized invocation with timeouts.
"""

import os
import sys
import time
import ipaddress
import logging
import threading
import subprocess
from typing import Dict, Any, List, Optional, Tuple

from database.db import SessionLocal
from database.models import DBFlow, DBPrediction, DBAlert

logger = logging.getLogger("aegis.nmap_demo")

# Locate portable Nmap executable
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
NMAP_PATH_PORTABLE = os.path.join(PROJECT_ROOT, "tools", "nmap-7.92", "nmap.exe")


def is_authorized_lab_target(target: str) -> Tuple[bool, str]:
    """
    Validates that target is strictly localhost or an RFC1918 private IP.
    Returns (is_valid, reason).
    """
    cleaned = target.strip().lower()
    if cleaned in ("localhost", "127.0.0.1", "::1"):
        return True, "Localhost loopback target"

    try:
        ip = ipaddress.ip_address(cleaned)
        if ip.is_loopback:
            return True, "Loopback target"
        if ip.is_private:
            return True, "RFC1918 Private lab subnet target"
        return False, f"Target '{target}' is a public IP address. Lab demonstration is restricted to private/local targets only."
    except ValueError:
        return False, f"Target '{target}' is not a valid IPv4/IPv6 address or localhost."


def validate_port_spec(ports: str) -> Tuple[bool, str, List[int]]:
    """
    Validates port specification (e.g. '21,22,80,443' or '1-1000').
    Returns (is_valid, error_msg, port_list).
    """
    if not ports or not ports.strip():
        return True, "", [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 8000, 8080, 8443]

    port_list = []
    chunks = [c.strip() for c in ports.split(",") if c.strip()]
    for chunk in chunks:
        if "-" in chunk:
            parts = chunk.split("-")
            if len(parts) != 2:
                return False, f"Invalid port range format: {chunk}", []
            try:
                start_p, end_p = int(parts[0]), int(parts[1])
                if start_p < 1 or end_p > 65535 or start_p > end_p:
                    return False, f"Port range out of bounds [1-65535]: {chunk}", []
                port_list.extend(range(start_p, end_p + 1))
            except ValueError:
                return False, f"Non-numeric port range: {chunk}", []
        else:
            try:
                p = int(chunk)
                if p < 1 or p > 65535:
                    return False, f"Port {p} out of bounds [1-65535]", []
                port_list.append(p)
            except ValueError:
                return False, f"Non-numeric port: {chunk}", []

    if len(port_list) > 2000:
        return False, f"Requested port count ({len(port_list)}) exceeds maximum allowed safety threshold of 2,000 ports.", []

    return True, "", sorted(list(set(port_list)))


class NmapDemonstrationRunner:
    """
    Controls and executes authorized Nmap PortScan demonstration runs.
    """

    def __init__(self):
        self.is_running = False
        self.status = "IDLE"  # IDLE, RUNNING, COMPLETED, FAILED
        self.demo_id: Optional[str] = None
        self.target: Optional[str] = None
        self.ports: Optional[str] = None
        self.scan_type: Optional[str] = None
        self.started_at: Optional[float] = None
        self.duration_seconds = 0.0
        self.output_logs: List[str] = []
        self.last_error: Optional[str] = None

        # Pre/Post snapshot verification
        self.initial_snapshot: Dict[str, int] = {}
        self.final_snapshot: Dict[str, int] = {}

        self._thread: Optional[threading.Thread] = None

    def start_demonstration(
        self,
        target: str = "127.0.0.1",
        ports: str = "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,1521,3306,3389,5432,8000,8080,8443",
        scan_type: str = "syn",
        timeout_seconds: int = 25
    ) -> Dict[str, Any]:
        """Starts a controlled Nmap scan against an authorized target."""
        if self.is_running:
            return {
                "status": "error",
                "message": f"Demonstration already in progress against {self.target}"
            }

        # 1. Validate Target
        is_valid_target, target_reason = is_authorized_lab_target(target)
        if not is_valid_target:
            return {"status": "error", "message": target_reason}

        # 2. Validate Ports
        is_valid_ports, port_err, port_list = validate_port_spec(ports)
        if not is_valid_ports:
            return {"status": "error", "message": port_err}

        # 3. Validate Scan Type
        scan_type_clean = scan_type.lower().strip()
        if scan_type_clean not in ("syn", "connect"):
            return {"status": "error", "message": f"Unsupported scan type '{scan_type}'. Must be 'syn' or 'connect'."}

        self.demo_id = f"DEMO-{int(time.time())}"
        self.target = target.strip()
        self.ports = ports.strip()
        self.scan_type = scan_type_clean
        self.is_running = True
        self.status = "RUNNING"
        self.started_at = time.time()
        self.duration_seconds = 0.0
        self.output_logs = []
        self.last_error = None

        # Snapshot initial database state
        self.initial_snapshot = self._take_db_snapshot()

        self._thread = threading.Thread(
            target=self._demo_worker,
            args=(self.target, port_list, self.scan_type, timeout_seconds),
            daemon=True
        )
        self._thread.start()

        return {
            "status": "success",
            "message": f"Authorized Nmap demonstration launched against {self.target}",
            "demo_id": self.demo_id,
            "target": self.target,
            "ports_count": len(port_list),
            "scan_type": self.scan_type,
            "mode": "LAB_AUTHORIZED_DEMO",
            "started_at": self.started_at
        }

    def get_status(self) -> Dict[str, Any]:
        """Returns the status and verification metrics of the demonstration run."""
        duration = (time.time() - self.started_at) if (self.started_at and self.is_running) else self.duration_seconds
        current_snap = self._take_db_snapshot() if not self.is_running else self._take_db_snapshot()

        flows_delta = max(0, current_snap.get("flows", 0) - self.initial_snapshot.get("flows", 0))
        preds_delta = max(0, current_snap.get("predictions", 0) - self.initial_snapshot.get("predictions", 0))
        portscan_preds_delta = max(0, current_snap.get("portscan_predictions", 0) - self.initial_snapshot.get("portscan_predictions", 0))
        alerts_delta = max(0, current_snap.get("alerts", 0) - self.initial_snapshot.get("alerts", 0))

        return {
            "is_running": self.is_running,
            "status": self.status,
            "demo_id": self.demo_id,
            "target": self.target,
            "scan_type": self.scan_type,
            "duration_seconds": round(duration, 2),
            "last_error": self.last_error,
            "logs": self.output_logs[-15:] if self.output_logs else [],
            "verification": {
                "flows_generated": flows_delta,
                "predictions_generated": preds_delta,
                "portscan_predictions": portscan_preds_delta,
                "alerts_persisted": alerts_delta,
                "total_db_flows": current_snap.get("flows", 0),
                "total_db_alerts": current_snap.get("alerts", 0),
            }
        }

    def _demo_worker(self, target: str, port_list: List[int], scan_type: str, timeout: int):
        """Worker thread executing either nmap.exe or Python raw SYN scanner fallback."""
        try:
            flag = "-sS" if scan_type == "syn" else "-sT"
            port_arg = ",".join(map(str, port_list[:100])) if len(port_list) > 100 else ",".join(map(str, port_list))

            self.output_logs.append(f"Starting authorized scan on {target} ({flag} -p {port_arg})")

            # Check if portable Nmap is available
            nmap_bin = NMAP_PATH_PORTABLE if os.path.exists(NMAP_PATH_PORTABLE) else "nmap"
            executed_native = False

            try:
                cmd = [nmap_bin, flag, "-p", port_arg, "-T4", target]
                self.output_logs.append(f"Executing: {' '.join(cmd)}")
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    cwd=PROJECT_ROOT
                )
                stdout, _ = proc.communicate(timeout=timeout)
                for line in stdout.splitlines():
                    if line.strip():
                        self.output_logs.append(line.strip())
                executed_native = True
            except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as exc:
                self.output_logs.append(f"Native nmap notice ({exc}); engaging Python raw SYN scan engine...")

            if not executed_native or "failed to open device" in "".join(self.output_logs).lower():
                # Fallback to Python Scapy raw SYN scanner for guaranteed packet generation
                from tools.nmap_scan import run_syn_scan
                run_syn_scan(target_ip=target, scan_type=flag, ports=port_list[:50])
                self.output_logs.append(f"SYN probes emitted across {len(port_list[:50])} ports.")

            # Allow flow aggregator cleanup window to complete
            time.sleep(2.5)
            self.status = "COMPLETED"

        except Exception as exc:
            self.status = "FAILED"
            self.last_error = str(exc)
            self.output_logs.append(f"Demo error: {exc}")
            logger.error("Demo run error: %s", exc, exc_info=True)
        finally:
            self.is_running = False
            self.duration_seconds = time.time() - (self.started_at or time.time())
            self.final_snapshot = self._take_db_snapshot()

    def _take_db_snapshot(self) -> Dict[str, int]:
        """Snapshots record counts from SQLite."""
        try:
            db = SessionLocal()
            flows = db.query(DBFlow).count()
            preds = db.query(DBPrediction).count()
            ps_preds = db.query(DBPrediction).filter(DBPrediction.predicted_label == "PortScan").count()
            alerts = db.query(DBAlert).count()
            db.close()
            return {
                "flows": flows,
                "predictions": preds,
                "portscan_predictions": ps_preds,
                "alerts": alerts,
            }
        except Exception:
            return {"flows": 0, "predictions": 0, "portscan_predictions": 0, "alerts": 0}


NMAP_DEMO_RUNNER = NmapDemonstrationRunner()
