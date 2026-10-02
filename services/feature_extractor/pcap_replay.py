"""
services/feature_extractor/pcap_replay.py
-----------------------------------------
Offline PCAP Replay Pipeline for AegisNIDS.

Processes historical network packet captures completely offline:
  PCAP File → Scapy Reader → Flow Aggregation → 77 Features → ML Inference → Alert Engine → DB

SECURITY GUARANTEE:
  Operates strictly in userland memory. Packets are NEVER transmitted or injected
  onto any real physical or virtual network interface.
"""

import os
import sys
import time
import uuid
import logging
import threading
from typing import Dict, Any, Optional, Callable

from database.db import SessionLocal
from database.models import DBPCAPReplay
from services.feature_extractor.flow_aggregator import FlowAggregator

logger = logging.getLogger("aegis.pcap_replay")

try:
    import scapy.all as scapy
    from scapy.all import PcapReader, IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class PCAPReplayService:
    """
    Manages background execution of offline PCAP replay sessions.
    """

    def __init__(self, feature_list_path: str = "models/cicids2017/feature_list.json"):
        self.feature_list_path = feature_list_path
        self.is_replaying = False
        self.active_replay_id: Optional[str] = None
        self.active_pcap_path: Optional[str] = None
        self.packet_count = 0
        self.flow_count = 0
        self.prediction_count = 0
        self.alert_count = 0
        self.started_at: Optional[float] = None
        self.last_error: Optional[str] = None
        self.status = "IDLE"  # IDLE, RUNNING, COMPLETED, STOPPED, FAILED

        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._on_flow_callback: Optional[Callable[[Dict[str, Any]], None]] = None

    def validate_pcap_file(self, file_path: str) -> Dict[str, Any]:
        """Validates that a target PCAP file exists, is non-empty, and has a supported extension."""
        if not file_path:
            return {"valid": False, "error": "PCAP file path is required"}

        abs_path = os.path.abspath(file_path)
        if not os.path.exists(abs_path):
            return {"valid": False, "error": f"File does not exist: {file_path}"}

        if not os.path.isfile(abs_path):
            return {"valid": False, "error": f"Path is not a regular file: {file_path}"}

        ext = os.path.splitext(abs_path)[1].lower()
        if ext not in (".pcap", ".pcapng", ".cap"):
            return {"valid": False, "error": f"Unsupported file extension '{ext}'. Must be .pcap, .pcapng, or .cap"}

        file_size = os.path.getsize(abs_path)
        if file_size == 0:
            return {"valid": False, "error": "PCAP file is empty (0 bytes)"}

        return {
            "valid": True,
            "path": abs_path,
            "filename": os.path.basename(abs_path),
            "size_bytes": file_size,
        }

    def start_replay(
        self,
        pcap_path: str,
        on_flow_callback: Callable[[Dict[str, Any]], None],
        packet_delay: float = 0.0
    ) -> Dict[str, Any]:
        """Starts an offline PCAP replay session in a background daemon thread."""
        if self.is_replaying:
            return {
                "status": "error",
                "message": f"Replay already active for: {self.active_pcap_path} (ID: {self.active_replay_id})"
            }

        val = self.validate_pcap_file(pcap_path)
        if not val["valid"]:
            return {"status": "error", "message": val["error"]}

        if not SCAPY_AVAILABLE:
            return {"status": "error", "message": "Scapy is not installed. Offline replay requires Scapy."}

        self.replay_id = f"RPL-{int(time.time())}-{uuid.uuid4().hex[:6]}"
        self.active_replay_id = self.replay_id
        self.active_pcap_path = val["path"]
        self.filename = val["filename"]
        self.is_replaying = True
        self.status = "RUNNING"
        self.packet_count = 0
        self.flow_count = 0
        self.prediction_count = 0
        self.alert_count = 0
        self.started_at = time.time()
        self.last_error = None
        self._stop_event.clear()
        self._on_flow_callback = on_flow_callback

        # Initialize DB replay audit record
        self._record_db_start(self.replay_id, self.filename)

        self._thread = threading.Thread(
            target=self._replay_worker,
            args=(val["path"], packet_delay),
            daemon=True
        )
        self._thread.start()

        logger.info("PCAP replay started: %s (ID: %s)", self.filename, self.replay_id)

        return {
            "status": "success",
            "message": f"Offline PCAP replay started for {self.filename}",
            "replay_id": self.replay_id,
            "filename": self.filename,
            "mode": "PCAP_REPLAY",
            "started_at": self.started_at
        }

    def stop_replay(self) -> Dict[str, Any]:
        """Gracefully halts an active replay session."""
        if not self.is_replaying:
            return {"status": "success", "message": "No active PCAP replay session"}

        self.is_replaying = False
        self._stop_event.set()
        self.status = "STOPPED"

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)

        duration = time.time() - (self.started_at or time.time())
        self._record_db_finish(self.active_replay_id, "STOPPED", duration)

        return {
            "status": "success",
            "message": f"PCAP replay stopped. Processed {self.packet_count} packets and {self.flow_count} flows.",
            "replay_id": self.active_replay_id,
            "packet_count": self.packet_count,
            "flow_count": self.flow_count,
            "duration_seconds": round(duration, 2)
        }

    def get_status(self) -> Dict[str, Any]:
        """Returns the real-time operational telemetry of the replay pipeline."""
        duration = (time.time() - self.started_at) if (self.started_at and self.is_replaying) else 0.0
        return {
            "is_replaying": self.is_replaying,
            "status": self.status,
            "mode": "PCAP_REPLAY" if self.is_replaying else "LIVE",
            "replay_id": self.active_replay_id,
            "filename": os.path.basename(self.active_pcap_path) if self.active_pcap_path else None,
            "packets_processed": self.packet_count,
            "flows_generated": self.flow_count,
            "predictions_generated": self.prediction_count,
            "alerts_generated": self.alert_count,
            "duration_seconds": round(duration, 2),
            "last_error": self.last_error
        }

    def _replay_worker(self, file_path: str, packet_delay: float):
        """Worker loop streaming packets from file into FlowAggregator."""
        aggregator = FlowAggregator(self.feature_list_path, flow_timeout_seconds=2.0)
        try:
            with PcapReader(file_path) as pcap_reader:
                for pkt in pcap_reader:
                    if self._stop_event.is_set():
                        break

                    self.packet_count += 1

                    if not pkt.haslayer(IP):
                        continue

                    ip = pkt[IP]
                    proto = ip.proto
                    src_ip = ip.src
                    dst_ip = ip.dst

                    src_port = 0
                    dst_port = 0
                    tcp_flags = 0
                    win_size = 0
                    hdr_len = 20

                    if pkt.haslayer(TCP):
                        tcp = pkt[TCP]
                        src_port = tcp.sport
                        dst_port = tcp.dport
                        tcp_flags = int(tcp.flags)
                        win_size = tcp.window
                        hdr_len = tcp.dataofs * 4 if tcp.dataofs else 20
                    elif pkt.haslayer(UDP):
                        udp = pkt[UDP]
                        src_port = udp.sport
                        dst_port = udp.dport
                        hdr_len = 8

                    ts = float(pkt.time) if hasattr(pkt, "time") else time.time()
                    length = len(pkt)

                    completed = aggregator.process_packet(
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        proto=proto,
                        length=length,
                        timestamp=ts,
                        tcp_flags=tcp_flags,
                        win_size=win_size,
                        header_len=hdr_len
                    )

                    if completed and self._on_flow_callback:
                        self.flow_count += 1
                        try:
                            self._on_flow_callback(completed)
                            self.prediction_count += 1
                        except Exception as cb_err:
                            logger.error("Callback error during replay: %s", cb_err)

                    if packet_delay > 0:
                        time.sleep(packet_delay)

            # Flush remaining active flows at EOF
            remaining = aggregator.flush_all()
            for flow in remaining:
                if self._stop_event.is_set():
                    break
                if self._on_flow_callback:
                    self.flow_count += 1
                    try:
                        self._on_flow_callback(flow)
                        self.prediction_count += 1
                    except Exception:
                        pass

            if not self._stop_event.is_set():
                self.status = "COMPLETED"

        except Exception as exc:
            self.status = "FAILED"
            self.last_error = str(exc)
            logger.error("Error in PCAP replay worker: %s", exc, exc_info=True)
        finally:
            self.is_replaying = False
            duration = time.time() - (self.started_at or time.time())
            self._record_db_finish(self.active_replay_id, self.status, duration, self.last_error)

    def _record_db_start(self, replay_id: str, filename: str):
        try:
            db = SessionLocal()
            rec = DBPCAPReplay(
                replay_id=replay_id,
                filename=filename,
                status="RUNNING",
            )
            db.add(rec)
            db.commit()
            db.close()
        except Exception as e:
            logger.debug("Could not record replay start to DB: %s", e)

    def _record_db_finish(self, replay_id: Optional[str], status: str, duration: float, error: Optional[str] = None):
        if not replay_id:
            return
        try:
            db = SessionLocal()
            rec = db.query(DBPCAPReplay).filter(DBPCAPReplay.replay_id == replay_id).first()
            if rec:
                rec.status = status
                rec.packets_processed = self.packet_count
                rec.flows_generated = self.flow_count
                rec.predictions_generated = self.prediction_count
                rec.alerts_generated = self.alert_count
                rec.duration_seconds = round(duration, 2)
                rec.error_message = error
                rec.completed_at = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
                db.commit()
            db.close()
        except Exception as e:
            logger.debug("Could not record replay finish to DB: %s", e)


REPLAY_SERVICE = PCAPReplayService()
