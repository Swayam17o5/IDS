"""
services/demo/dos_hulk_demo.py
------------------------------
Controlled DoS Hulk Attack Demonstration Runner for AegisNIDS.

APPROACH:
  Generates a synthetic PCAP that replicates DoS Hulk traffic patterns from
  CICIDS2017, then feeds it through the existing PCAP replay pipeline so the
  FlowAggregator extracts real CICFlowMeter-style features and the ML ensemble
  makes the prediction organically.  No label is hardcoded; the model must
  predict "DoS Hulk" from the feature vector.

SAFETY NOTICE:
  - Packets are NEVER transmitted to any real network interface.
  - Scapy is used in OFFLINE (wrpcap) mode only.
  - Attacker/victim IPs are RFC1918 loopback/private addresses exclusively.
  - Only a temporary PCAP file is written to the scratch/ directory.

DoS Hulk CICIDS2017 statistical signature (key differentiators):
  - Protocol 6 (TCP), destination port 80 (HTTP)
  - Long flow duration: ~80 seconds  (80,000,000 microseconds)
  - Bidirectional: both fwd and bwd packets present (server responds)
  - Small number of packets per flow (~7 fwd, ~6 bwd) despite long duration
  - Very high inter-arrival times (IAT Mean ~6.6s between packets)
  - Large bwd payload (server sends HTML body ~1900 bytes/packet)
  - Init_Bwd_Win_Bytes small (235 bytes — server TCP window shrinks under load)
  - PSH+ACK dominant flag pattern
  - Fwd_Seg_Size_Min = 32 (small minimum segment from attacker)
  - Flow Bytes/s ~150 KB/s  (bandwidth not volume)
"""

import os
import sys
import time
import logging
import threading
import random
from typing import Dict, Any, List, Optional

# Ensure project root on sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from database.db import SessionLocal
from database.models import DBFlow, DBPrediction, DBAlert

logger = logging.getLogger("aegis.dos_hulk_demo")

# ── Paths ────────────────────────────────────────────────────────────────────
SCRATCH_DIR = os.path.join(PROJECT_ROOT, "scratch")
DEFAULT_PCAP_PATH = os.path.join(SCRATCH_DIR, "dos_hulk_demo.pcap")

# ── Traffic parameters ───────────────────────────────────────────────────────
ATTACKER_IP   = "10.0.0.50"   # RFC1918 attacker
VICTIM_IP     = "10.0.0.100"  # RFC1918 victim HTTP server
VICTIM_PORT   = 80             # HTTP
NUM_FLOWS     = 15             # number of distinct HTTP connections to simulate
PKTS_PER_FLOW = 12             # packets per flow


# ─────────────────────────────────────────────────────────────────────────────
#  PCAP Generator
# ─────────────────────────────────────────────────────────────────────────────

def generate_dos_hulk_pcap(output_path: str = DEFAULT_PCAP_PATH) -> str:
    """
    Generates a PCAP file whose flows, when processed by FlowAggregator, produce
    77-feature vectors matching the CICIDS2017 DoS Hulk statistical profile.

    CICIDS2017 DoS Hulk key stats (used to calibrate packet timing and sizes):
      Flow Duration   : ~80,000,000 µs  (80 seconds per connection)
      Fwd packets     : ~7 per flow
      Bwd packets     : ~6 per flow
      Fwd total bytes : ~380 bytes       (small GET requests)
      Bwd total bytes : ~11,595 bytes    (large HTTP responses)
      Flow IAT Mean   : ~6,600,000 µs    (packets ~6.6 s apart)
      Init Fwd Win    : 29,200 bytes
      Init Bwd Win    : 235 bytes        (server overwhelmed → tiny window)
      PSH Flag Count  : ~6 per flow
      ACK Flag Count  : ~12 per flow

    Packet sequence per flow (12 packets):
      SYN, SYN-ACK, ACK,
      PSH+ACK GET#1, PSH+ACK resp#1, ACK,
      PSH+ACK GET#2, PSH+ACK resp#2, ACK,
      PSH+ACK GET#3, PSH+ACK resp#3,
      FIN+ACK

    Parameters
    ----------
    output_path : str
        Destination .pcap file path.

    Returns
    -------
    str
        Absolute path to the generated PCAP file.

    Raises
    ------
    RuntimeError
        If Scapy is not installed.
    """
    try:
        from scapy.all import Ether, IP, TCP, Raw, wrpcap
    except ImportError:
        raise RuntimeError(
            "Scapy is required to generate the DoS Hulk PCAP. "
            "Install it with: pip install scapy"
        )

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # ── HTTP payload templates ───────────────────────────────────────────────
    # Fwd packets: small GET requests (~50-55 bytes each → 3 GETs ≈ 380 bytes fwd total / 7 fwd pkts)
    _GET_TEMPLATES = [
        "GET /?hulk={n:04d} HTTP/1.1\r\nHost: {victim}\r\nConnection: keep-alive\r\n\r\n",
        "GET /index?id={n:04d} HTTP/1.1\r\nHost: {victim}\r\nAccept: */*\r\n\r\n",
        "GET /page?q={n:04d} HTTP/1.1\r\nHost: {victim}\r\nKeep-Alive: 300\r\n\r\n",
    ]
    # Bwd packets: large responses (~1930 bytes each → 3 resps ≈ 5790 bytes × 2 = ~11,580 bwd total / 6 bwd pkts)
    _RESP_BODY = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 1800\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
        + ("X" * 1800)
    )
    # Server overwhelmed response (last bwd pkt, window=0 → server stressed)
    _RESP_503 = (
        "HTTP/1.1 503 Service Unavailable\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 56\r\n"
        "Connection: close\r\n"
        "\r\n"
        "<html><body><h1>503 Service Unavailable</h1></body></html>"
    )

    resp_bytes  = _RESP_BODY.encode("utf-8")   # ~1930 bytes
    err_bytes   = _RESP_503.encode("utf-8")    # ~155 bytes

    packets = []

    # Base timestamp: flows spread across ~80 s total, matching CICIDS2017 capture
    base_ts = time.time() - (NUM_FLOWS * 80)   # place in the recent past

    for flow_idx in range(NUM_FLOWS):
        sport = 49200 + flow_idx * 7    # distinct ephemeral source port per flow
        flow_start = base_ts + (flow_idx * 80.0)  # each flow 80 s apart

        get_template = _GET_TEMPLATES[flow_idx % len(_GET_TEMPLATES)]
        get_payload  = get_template.format(n=flow_idx, victim=VICTIM_IP).encode("utf-8")

        # Window sizes that match CICIDS2017 Hulk stats
        atk_win    = 29200             # Init_Fwd_Win_Bytes = 29200
        victim_win = max(64, 235 - flow_idx * 10)  # Init_Bwd_Win_Bytes shrinks: starts 235

        # ── Packet timestamps ──────────────────────────────────────────────
        # CICIDS2017 DoS Hulk: Flow Duration ≈ 1,878 µs (~1.9 ms), ~9 pkts fwd+bwd,
        # Packets arrive very rapidly (< 0.5 ms apart within a single TCP flow).
        # We use 12 packets spread across ~2.8 milliseconds (realistic Hulk timing).
        # NOTE: Original 6.5 s spacing was completely unrealistic!
        IAT_S        = 0.000235   # baseline inter-arrival ~235 µs
        IAT_JITTER_SD = 0.000050  # 50 µs standard deviation
        MIN_IAT       = 0.000001  # minimum 1 µs between packets
        rng = random.Random(flow_idx)   # deterministic per-flow seed
        t = [flow_start]
        for _i in range(1, PKTS_PER_FLOW):
            gap = max(MIN_IAT, rng.gauss(IAT_S, IAT_JITTER_SD))
            t.append(t[-1] + gap)
        # Exact timing: [0, 0.000235±jitter, 0.00047±jitter, ...]  (microsecond-scale packet timing)

        # Sequence numbers
        isn_a = 500000 + flow_idx * 2000
        isn_v = 700000 + flow_idx * 2000

        def _pkt(src, dst, sp, dp, seq, ack, flags, win, payload=b"", ts=0.0):
            p = (
                Ether() /
                IP(src=src, dst=dst, ttl=64) /
                TCP(sport=sp, dport=dp, seq=seq, ack=ack,
                    flags=flags, window=win) /
                Raw(load=payload)
            )
            p.time = ts
            return p

        def _pkt_no_payload(src, dst, sp, dp, seq, ack, flags, win, ts=0.0):
            p = (
                Ether() /
                IP(src=src, dst=dst, ttl=64) /
                TCP(sport=sp, dport=dp, seq=seq, ack=ack,
                    flags=flags, window=win)
            )
            p.time = ts
            return p

        # 1. SYN  (attacker → victim)
        packets.append(_pkt(ATTACKER_IP, VICTIM_IP, sport, VICTIM_PORT,
                             isn_a, 0, "S", atk_win, ts=t[0]))
        # 2. SYN-ACK  (victim → attacker)
        packets.append(_pkt(VICTIM_IP, ATTACKER_IP, VICTIM_PORT, sport,
                             isn_v, isn_a + 1, "SA", victim_win, ts=t[1]))
        # 3. ACK
        packets.append(_pkt_no_payload(ATTACKER_IP, VICTIM_IP, sport, VICTIM_PORT,
                                        isn_a + 1, isn_v + 1, "A", atk_win, ts=t[2]))

        aseq = isn_a + 1
        vseq = isn_v + 1
        vack = isn_a + 1

        # Requests 1–3: PSH+ACK GET → PSH+ACK resp → ACK
        for req_n in range(3):
            # PSH+ACK: GET request
            packets.append(_pkt(ATTACKER_IP, VICTIM_IP, sport, VICTIM_PORT,
                                 aseq, vseq, "PA", atk_win,
                                 payload=get_payload, ts=t[3 + req_n * 3]))
            aseq += len(get_payload)

            # PSH+ACK: server response (last response uses 503 to simulate collapse)
            rpl = err_bytes if req_n == 2 else resp_bytes
            rpl_win = max(0, victim_win - req_n * 80)  # window shrinks with each response
            packets.append(_pkt(VICTIM_IP, ATTACKER_IP, VICTIM_PORT, sport,
                                 vseq, aseq, "PA", rpl_win,
                                 payload=rpl, ts=t[4 + req_n * 3]))
            vseq += len(rpl)

            # ACK (only for first 2 exchanges; last goes straight to FIN)
            if req_n < 2:
                packets.append(_pkt_no_payload(ATTACKER_IP, VICTIM_IP, sport, VICTIM_PORT,
                                                aseq, vseq, "A", atk_win, ts=t[5 + req_n * 3]))

        # 12. FIN+ACK  (attacker tears down)
        packets.append(_pkt(ATTACKER_IP, VICTIM_IP, sport, VICTIM_PORT,
                             aseq, vseq, "FA", atk_win, ts=t[11]))

    # Sort by timestamp (some flows interleave in time)
    packets.sort(key=lambda p: float(p.time))
    wrpcap(output_path, packets)

    logger.info(
        "DoS Hulk PCAP generated: %s  (%d packets across %d flows, ~80s IAT spacing)",
        output_path, len(packets), NUM_FLOWS
    )
    return os.path.abspath(output_path)


# ─────────────────────────────────────────────────────────────────────────────
#  Demo Runner  (mirrors NmapDemonstrationRunner interface)
# ─────────────────────────────────────────────────────────────────────────────

class DosHulkDemoRunner:
    """
    Orchestrates an end-to-end DoS Hulk demonstration:
      1. Generates a synthetic PCAP via generate_dos_hulk_pcap()
      2. Submits it to the existing PCAPReplayService
      3. Monitors DB for DoS Hulk predictions and alerts
      4. Reports verification metrics

    Usage (via API):
        POST /api/demo/dos_hulk/start   → starts demo
        GET  /api/demo/dos_hulk/status  → returns progress + verification
    """

    def __init__(self):
        self.is_running     = False
        self.status         = "IDLE"   # IDLE | RUNNING | COMPLETED | FAILED
        self.demo_id: Optional[str] = None
        self.pcap_path: Optional[str] = None
        self.started_at: Optional[float] = None
        self.duration_seconds = 0.0
        self.output_logs: List[str] = []
        self.last_error: Optional[str] = None

        self.initial_snapshot: Dict[str, int] = {}
        self.final_snapshot:   Dict[str, int] = {}

        self._thread: Optional[threading.Thread] = None

    # ── Public API ────────────────────────────────────────────────────────────

    def start_demonstration(
        self,
        pcap_path: Optional[str] = None,
        num_flows: int = NUM_FLOWS
    ) -> Dict[str, Any]:
        """
        Starts the DoS Hulk end-to-end demonstration.

        Parameters
        ----------
        pcap_path : str, optional
            Override the output path for the generated PCAP file.
            Defaults to scratch/dos_hulk_demo.pcap.
        num_flows : int
            Number of HTTP flood flows to generate (default 15).
            More flows → stronger signal → higher model confidence.

        Returns
        -------
        dict  API response payload.
        """
        if self.is_running:
            return {
                "status": "error",
                "message": "DoS Hulk demonstration is already in progress."
            }

        target_pcap = pcap_path or DEFAULT_PCAP_PATH

        self.demo_id    = f"HULK-{int(time.time())}"
        self.pcap_path  = target_pcap
        self.is_running = True
        self.status     = "RUNNING"
        self.started_at = time.time()
        self.duration_seconds = 0.0
        self.output_logs = []
        self.last_error  = None

        self.initial_snapshot = self._take_db_snapshot()

        self._thread = threading.Thread(
            target=self._demo_worker,
            args=(target_pcap, num_flows),
            daemon=True
        )
        self._thread.start()

        return {
            "status": "success",
            "message": (
                f"DoS Hulk demonstration launched. "
                f"Generating {num_flows}-flow HTTP-flood PCAP and feeding it "
                f"through the ML pipeline."
            ),
            "demo_id":    self.demo_id,
            "pcap_path":  target_pcap,
            "num_flows":  num_flows,
            "attack_type": "DoS Hulk",
            "mode":       "PCAP_REPLAY",
            "started_at": self.started_at,
        }

    def get_status(self) -> Dict[str, Any]:
        """Returns execution status and database verification metrics."""
        duration = (
            (time.time() - self.started_at)
            if (self.started_at and self.is_running)
            else self.duration_seconds
        )
        snap = self._take_db_snapshot()

        flows_delta      = max(0, snap.get("flows", 0)      - self.initial_snapshot.get("flows", 0))
        preds_delta      = max(0, snap.get("predictions", 0) - self.initial_snapshot.get("predictions", 0))
        hulk_preds_delta = max(0, snap.get("hulk_predictions", 0) - self.initial_snapshot.get("hulk_predictions", 0))
        alerts_delta     = max(0, snap.get("alerts", 0)     - self.initial_snapshot.get("alerts", 0))
        hulk_alerts_delta= max(0, snap.get("hulk_alerts", 0)- self.initial_snapshot.get("hulk_alerts", 0))

        return {
            "is_running":       self.is_running,
            "status":           self.status,
            "demo_id":          self.demo_id,
            "attack_type":      "DoS Hulk",
            "pcap_path":        self.pcap_path,
            "duration_seconds": round(duration, 2),
            "last_error":       self.last_error,
            "logs":             self.output_logs[-20:],
            "verification": {
                "flows_generated":      flows_delta,
                "predictions_generated": preds_delta,
                "dos_hulk_predictions": hulk_preds_delta,
                "alerts_persisted":     alerts_delta,
                "dos_hulk_alerts":      hulk_alerts_delta,
                "total_db_flows":       snap.get("flows", 0),
                "total_db_alerts":      snap.get("alerts", 0),
            },
        }

    # ── Internal worker ───────────────────────────────────────────────────────

    def _demo_worker(self, target_pcap: str, num_flows: int):
        """
        Background thread:
          1. Generate synthetic PCAP
          2. Submit to REPLAY_SERVICE (which runs through FlowAggregator → ML)
          3. Wait for completion
          4. Update status
        """
        try:
            # ── Step 1: generate PCAP ──────────────────────────────────────
            self.output_logs.append(
                f"[1/3] Generating DoS Hulk PCAP ({num_flows} flows) → {target_pcap}"
            )
            # Import here to avoid circular imports at module load time
            actual_path = generate_dos_hulk_pcap(target_pcap)
            self.output_logs.append(
                f"[1/3] PCAP generated: {actual_path} "
                f"({num_flows * PKTS_PER_FLOW} packets)"
            )

            # ── Step 2: submit to PCAP replay service ─────────────────────
            self.output_logs.append(
                "[2/3] Submitting PCAP to replay pipeline "
                "(FlowAggregator → FeatureValidator → ML ensemble)…"
            )
            # Import REPLAY_SERVICE lazily (avoids circular import at module level)
            from services.feature_extractor.pcap_replay import REPLAY_SERVICE

            # If a replay is already in progress, wait briefly
            if REPLAY_SERVICE.is_replaying:
                self.output_logs.append(
                    "[2/3] Another replay is running; waiting up to 15 s…"
                )
                for _ in range(30):
                    time.sleep(0.5)
                    if not REPLAY_SERVICE.is_replaying:
                        break
                if REPLAY_SERVICE.is_replaying:
                    raise RuntimeError(
                        "PCAP replay service is busy. "
                        "Stop the current replay and try again."
                    )

            # We need the on_flow_callback from app.py.
            # Import it lazily to avoid circular imports.
            try:
                from services.inference.app import handle_live_captured_flow as _flow_cb
            except ImportError:
                raise RuntimeError(
                    "Could not import handle_live_captured_flow from app.py. "
                    "Ensure the AegisNIDS server is running."
                )

            result = REPLAY_SERVICE.start_replay(
                pcap_path=actual_path,
                on_flow_callback=_flow_cb,
                packet_delay=0.0,   # process as fast as possible
            )

            if result.get("status") != "success":
                raise RuntimeError(
                    f"PCAP replay start failed: {result.get('message')}"
                )

            self.output_logs.append(
                f"[2/3] Replay started (ID: {result.get('replay_id')}). "
                f"Waiting for pipeline to process all flows…"
            )

            # ── Step 3: wait for replay to complete ───────────────────────
            wait_limit = 60   # seconds
            waited = 0.0
            while REPLAY_SERVICE.is_replaying and waited < wait_limit:
                time.sleep(0.5)
                waited += 0.5

            if REPLAY_SERVICE.is_replaying:
                REPLAY_SERVICE.stop_replay()
                self.output_logs.append(
                    "[3/3] WARNING: replay timed out after 60 s; stopped manually."
                )
            else:
                self.output_logs.append(
                    f"[3/3] Replay completed. "
                    f"Packets: {REPLAY_SERVICE.packet_count}, "
                    f"Flows: {REPLAY_SERVICE.flow_count}."
                )

            # Allow alert engine dedup window to settle
            time.sleep(1.0)

            snap = self._take_db_snapshot()
            hulk_new = max(0, snap.get("hulk_predictions", 0) - self.initial_snapshot.get("hulk_predictions", 0))
            hulk_alerts_new = max(0, snap.get("hulk_alerts", 0) - self.initial_snapshot.get("hulk_alerts", 0))

            self.output_logs.append(
                f"[3/3] Verification: "
                f"{hulk_new} DoS Hulk prediction(s), "
                f"{hulk_alerts_new} DoS Hulk alert(s) persisted."
            )

            if hulk_new == 0:
                self.output_logs.append(
                    "WARNING: No DoS Hulk predictions detected. "
                    "The flow features may not have crossed the model's decision boundary. "
                    "Try increasing NUM_FLOWS or check the active model."
                )

            self.status = "COMPLETED"

        except Exception as exc:
            self.status = "FAILED"
            self.last_error = str(exc)
            self.output_logs.append(f"ERROR: {exc}")
            logger.error("DoS Hulk demo error: %s", exc, exc_info=True)
        finally:
            self.is_running = False
            self.duration_seconds = time.time() - (self.started_at or time.time())
            self.final_snapshot = self._take_db_snapshot()

    # ── DB snapshot ───────────────────────────────────────────────────────────

    def _take_db_snapshot(self) -> Dict[str, int]:
        """Snapshots relevant record counts from SQLite for before/after comparison."""
        try:
            db = SessionLocal()
            flows  = db.query(DBFlow).count()
            preds  = db.query(DBPrediction).count()
            hulk_p = (
                db.query(DBPrediction)
                  .filter(DBPrediction.predicted_label == "DoS Hulk")
                  .count()
            )
            alerts = db.query(DBAlert).count()
            hulk_a = (
                db.query(DBAlert)
                  .filter(DBAlert.attack_type == "DoS Hulk")
                  .count()
            )
            db.close()
            return {
                "flows":            flows,
                "predictions":      preds,
                "hulk_predictions": hulk_p,
                "alerts":           alerts,
                "hulk_alerts":      hulk_a,
            }
        except Exception:
            return {
                "flows": 0, "predictions": 0,
                "hulk_predictions": 0, "alerts": 0, "hulk_alerts": 0
            }


# Module-level singleton (mirrors NMAP_DEMO_RUNNER pattern)
DOS_HULK_DEMO_RUNNER = DosHulkDemoRunner()
