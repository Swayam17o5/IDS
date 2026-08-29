import os
import sys
import time
import socket
import ctypes
import threading
from typing import Dict, List, Any, Optional, Callable, Tuple

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from services.feature_extractor.flow_aggregator import FlowAggregator

try:
    import scapy.all as scapy
    from scapy.all import IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def check_capture_capabilities() -> Dict[str, Any]:
    """
    Checks Npcap / WinPcap driver availability and administrative privilege level on Windows.
    Returns clear diagnosis and installation instructions if missing.
    """
    has_pcap_driver = False
    pcap_driver_error = None
    if SCAPY_AVAILABLE:
        has_pcap_driver = bool(getattr(scapy.conf, "use_pcap", False))
        if not has_pcap_driver:
            pcap_driver_error = (
                "Npcap / WinPcap capture driver is not installed on this host. "
                "Raw packet sniffing at Layer 2 requires Npcap on Windows."
            )

    is_admin = False
    try:
        if os.name == "nt":
            is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin() != 0)
            if not is_admin and has_pcap_driver:
                # With Npcap installed in WinPcap mode, kernel capture service provides elevated driver access
                is_admin = True
        else:
            is_admin = bool(os.geteuid() == 0)
    except Exception:
        is_admin = bool(has_pcap_driver)

    install_instructions = [
        "1. Download the Npcap installer from https://npcap.com/#download",
        "2. Run the installer and ensure 'Install Npcap in WinPcap API-compatible Mode' is CHECKED.",
        "3. Ensure 'Support raw 802.11 traffic' and 'Restrict Npcap driver' settings match your security policy.",
        "4. Restart your terminal or server to refresh system drivers."
    ]

    return {
        "scapy_available": SCAPY_AVAILABLE,
        "is_admin": is_admin,
        "has_pcap_driver": has_pcap_driver,
        "can_capture_live": (has_pcap_driver or is_admin),
        "status_message": "Ready for Live Sniffing" if (has_pcap_driver and is_admin) else (
            "Driver/Permission Required: " + (pcap_driver_error or "Administrator privileges required")
        ),
        "install_instructions": install_instructions if not has_pcap_driver else []
    }


def _reload_scapy_ifaces() -> None:
    """
    Forces Scapy to rediscover all network adapters from the OS.

    scapy.conf.ifaces is populated once at import time.  When the user
    switches from Wi-Fi to a mobile hotspot the OS assigns a new adapter
    index / device name but the stale Scapy cache still points at the old
    one, so sniff() silently binds to the wrong (or non-existent) adapter.
    Calling reload() before every interface enumeration or capture start
    ensures we always see the *currently active* adapters.
    """
    if not SCAPY_AVAILABLE:
        return
    try:
        scapy.conf.ifaces.reload()
        print("[CAPTURE] scapy.conf.ifaces reloaded - adapter list refreshed from OS.", flush=True)
    except Exception as e:
        print("[CAPTURE] WARNING: ifaces.reload() failed: " + str(e), flush=True)


def get_available_interfaces() -> List[Dict[str, Any]]:
    """
    Enumerates available network interfaces on the system with friendly names,
    IP addresses, and loopback flags.  Always reloads the Scapy adapter cache
    first so newly connected adapters (e.g. a mobile hotspot) are visible.
    """
    interfaces = []

    # 1. Loopback safety default
    interfaces.append({
        "id": "loopback",
        "name": "Software Loopback Interface (127.0.0.1)",
        "description": "Localhost traffic only (Safe Guardrail)",
        "ip": "127.0.0.1",
        "is_loopback": True,
        "is_default": True
    })

    if SCAPY_AVAILABLE:
        # BUG FIX: reload adapter list so hotspot / new adapters are visible
        _reload_scapy_ifaces()
        try:
            for k, iface in scapy.conf.ifaces.items():
                name = getattr(iface, "name", str(k))
                desc = getattr(iface, "description", name)
                ip = getattr(iface, "ip", "0.0.0.0")
                mac = getattr(iface, "mac", "")

                # Exclude internal virtual adapters with no valid IP or duplicates
                if ip and ip != "0.0.0.0" and ip != "127.0.0.1":
                    interfaces.append({
                        "id": str(name) if name else str(k),
                        "device": str(k),
                        "name": str(name),
                        "description": str(desc),
                        "ip": str(ip),
                        "mac": str(mac),
                        "is_loopback": False,
                        "is_default": False
                    })
        except Exception as e:
            print("[CAPTURE] WARNING: interface enumeration error: " + str(e), flush=True)

    return interfaces


class LiveCaptureService:
    """
    Real-time network traffic capture service.
    Aggregates packets into bidirectional flows and flushes them to a callback
    for instantaneous ML classification and alert generation.
    """
    def __init__(
        self,
        feature_list_path: str = "models/cicids2017/feature_list.json",
        flow_timeout_seconds: float = 2.0
    ):
        self.feature_list_path = feature_list_path
        self.flow_timeout_seconds = flow_timeout_seconds
        self.aggregator = FlowAggregator(feature_list_path, flow_timeout_seconds=flow_timeout_seconds)

        self.is_running = False
        self.active_interface: Optional[str] = None
        self.active_ip: Optional[str] = None          # Resolved local IP for the active interface
        self.packet_count = 0
        self.flow_count = 0
        self.started_at: Optional[float] = None
        self.last_error: Optional[str] = None

        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._on_flow_callback: Optional[Callable[[Dict[str, Any]], None]] = None

    # -------------------------------------------------------------------------
    # Interface resolution (network-agnostic)
    # -------------------------------------------------------------------------

    def _resolve_interface(self, interface_name: str) -> Tuple[Any, str]:
        """
        Reloads the Scapy adapter cache and resolves *interface_name* to the
        actual Scapy device object (or the raw string fallback).  Also extracts
        and caches the local IPv4 address for the matched adapter.

        Returns (scapy_iface_arg, local_ip_str).

        This is the single authoritative place for interface resolution so that
        both start_capture() and _capture_worker() always use up-to-date info.
        """
        if not SCAPY_AVAILABLE or interface_name == "loopback":
            self.active_ip = "127.0.0.1"
            print("[CAPTURE] Interface resolved: loopback -> 127.0.0.1", flush=True)
            return None, "127.0.0.1"

        # Always reload so we pick up the current OS adapter list
        _reload_scapy_ifaces()

        resolved_iface = None
        resolved_ip = "0.0.0.0"

        try:
            resolved_iface = scapy.conf.ifaces.dev_from_name(interface_name)
            resolved_ip = getattr(resolved_iface, "ip", "0.0.0.0") or "0.0.0.0"
        except Exception:
            # dev_from_name failed — fall back to iterating manually
            for k, iface in scapy.conf.ifaces.items():
                iface_name_attr = getattr(iface, "name", str(k))
                if str(k) == interface_name or iface_name_attr == interface_name:
                    resolved_iface = iface
                    resolved_ip = getattr(iface, "ip", "0.0.0.0") or "0.0.0.0"
                    break

        if resolved_iface is None:
            # Last resort: pass the raw string and let Scapy/Npcap figure it out
            resolved_iface = interface_name
            print(
                "[CAPTURE] WARNING: Could not resolve '" + interface_name + "' in scapy.conf.ifaces "
                "- passing raw name to sniff(). This may fail on Windows.",
                flush=True
            )
        else:
            print(
                "[CAPTURE] Interface resolved: '" + interface_name + "' -> device=" + str(resolved_iface) + " ip=" + str(resolved_ip),
                flush=True
            )

        self.active_ip = resolved_ip
        return resolved_iface, resolved_ip

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    def start_capture(
        self,
        interface: str = "loopback",
        on_flow_callback: Optional[Callable[[Dict[str, Any]], None]] = None
    ) -> Dict[str, Any]:
        """Starts live capture in a background daemon thread."""
        if self.is_running:
            return {"status": "error", "message": f"Capture already active on {self.active_interface}"}

        capabilities = check_capture_capabilities()
        if not capabilities["has_pcap_driver"] and not capabilities["is_admin"]:
            err_msg = (
                "Cannot start live capture: Npcap packet driver is not installed, "
                "and process is not running as Administrator."
            )
            self.last_error = err_msg
            return {
                "status": "error",
                "message": err_msg,
                "capabilities": capabilities
            }

        # Resolve interface eagerly so we can report the IP in the response
        _, local_ip = self._resolve_interface(interface)

        self.is_running = True
        self.active_interface = interface
        self.packet_count = 0
        self.flow_count = 0
        self.started_at = time.time()
        self.last_error = None
        self._stop_event.clear()
        self._on_flow_callback = on_flow_callback

        self._thread = threading.Thread(target=self._capture_worker, daemon=True)
        self._thread.start()

        print(
            "[CAPTURE] Started capture on interface='" + interface + "' ip=" + str(local_ip),
            flush=True
        )

        return {
            "status": "success",
            "message": f"Live capture started on {interface}",
            "interface": interface,
            "active_ip": local_ip,
            "started_at": self.started_at
        }

    def stop_capture(self) -> Dict[str, Any]:
        """Stops active live capture and flushes remaining flows."""
        if not self.is_running:
            return {"status": "success", "message": "Capture was not running"}

        iface_for_log = self.active_interface

        self.is_running = False
        self._stop_event.set()

        # BUG FIX: give the sniff() thread enough time to finish its 1-second
        # timeout window and release the Npcap handle.  The old 1.5 s join was
        # too short and could cause a race with the next start_capture() call.
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.5)
            if self._thread.is_alive():
                print(
                    "[CAPTURE] WARNING: capture thread on '" + str(iface_for_log) + "' did not exit within "
                    "3.5 s - Npcap handle may still be held. Proceeding anyway.",
                    flush=True
                )

        # Small settle period to ensure Npcap releases the adapter
        time.sleep(0.2)

        # Flush any remaining unclosed flows
        remaining_flows = self.aggregator.flush_all()
        if self._on_flow_callback:
            for flow in remaining_flows:
                try:
                    self._on_flow_callback(flow)
                    self.flow_count += 1
                except Exception:
                    pass

        print(
            "[CAPTURE] Stopped capture on '" + str(iface_for_log) + "'. "
            "Total: " + str(self.packet_count) + " packets, " + str(self.flow_count) + " flows.",
            flush=True
        )

        self.active_interface = None
        self.active_ip = None

        return {
            "status": "success",
            "message": f"Live capture stopped. Captured {self.packet_count} packets and {self.flow_count} flows.",
            "packet_count": self.packet_count,
            "flow_count": self.flow_count
        }

    def get_status(self) -> Dict[str, Any]:
        return {
            "is_capturing": self.is_running,
            "active_mode": "LIVE_CAPTURE" if self.is_running else "REPLAY_MODE",
            "active_interface": self.active_interface,
            "active_ip": self.active_ip,          # ← New: exposed for dashboard indicator
            "packet_count": self.packet_count,
            "flow_count": self.flow_count,
            "started_at": self.started_at,
            "duration_seconds": (time.time() - self.started_at) if self.started_at and self.is_running else 0.0,
            "last_error": self.last_error,
            "capabilities": check_capture_capabilities()
        }

    def reset(self):
        """Resets capture counters and flushes active flow tables."""
        self.packet_count = 0
        self.flow_count = 0
        if self.is_running:
            self.started_at = time.time()
        self.last_error = None
        self.aggregator.active_flows.clear()
        if hasattr(self.aggregator, "host_port_scans"):
            self.aggregator.host_port_scans.clear()

    # -------------------------------------------------------------------------
    # Internal worker
    # -------------------------------------------------------------------------

    def _capture_worker(self):
        """Worker thread executing packet capture."""
        try:
            # BUG FIX: resolve the interface *inside* the worker thread with a
            # fresh ifaces.reload() so that if the OS has reassigned adapter
            # indices since start_capture() was called (e.g. after a network
            # switch) we still bind to the correct device.
            iface_arg, local_ip = self._resolve_interface(self.active_interface or "loopback")

            print(
                "[CAPTURE] Worker starting. interface='" + str(self.active_interface) + "' "
                "resolved_device=" + str(iface_arg) + " local_ip=" + str(local_ip),
                flush=True
            )

            # Periodic flush timer loop
            last_flush = time.time()
            cycle_packets = 0

            def process_pkt(pkt):
                nonlocal cycle_packets
                if self._stop_event.is_set():
                    return

                self.packet_count += 1
                cycle_packets += 1

                if not pkt.haslayer(IP):
                    return

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

                ts = float(pkt.time)
                length = len(pkt)

                completed = self.aggregator.process_packet(
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
                    except Exception as cb_err:
                        print("[CAPTURE] Flow callback error: " + str(cb_err), flush=True)

            # Sniff loop with timeout chunking
            consecutive_errors = 0
            while not self._stop_event.is_set():
                try:
                    scapy.sniff(
                        iface=iface_arg,
                        prn=process_pkt,
                        timeout=1.0,
                        store=False,
                        stop_filter=lambda p: self._stop_event.is_set()
                    )
                    consecutive_errors = 0  # reset on successful sniff cycle
                except Exception as sniff_err:
                    consecutive_errors += 1
                    err_str = str(sniff_err)
                    self.last_error = err_str
                    print(
                        "[CAPTURE] ERROR in sniff() on '" + str(self.active_interface) + "' "
                        "(attempt " + str(consecutive_errors) + "): " + err_str,
                        flush=True
                    )
                    if consecutive_errors >= 3:
                        print(
                            "[CAPTURE] FATAL: 3 consecutive sniff errors on '" + str(self.active_interface) + "'. "
                            "Stopping capture. Use Change Network to restart on a working adapter.",
                            flush=True
                        )
                        break
                    time.sleep(0.5)

                # Check for expired flows every second
                now = time.time()
                if now - last_flush >= 1.0:
                    expired = self.aggregator.flush_expired_flows(now)
                    for exp_flow in expired:
                        if self._on_flow_callback:
                            self.flow_count += 1
                            try:
                                self._on_flow_callback(exp_flow)
                            except Exception:
                                pass

                    # Periodic heartbeat log (every ~10 s)
                    elapsed = now - (self.started_at or now)
                    if int(elapsed) % 10 == 0 and int(elapsed) > 0:
                        print(
                            "[CAPTURE] Heartbeat - interface='" + str(self.active_interface) + "' "
                            "ip=" + str(self.active_ip) + " uptime=" + str(int(elapsed)) + "s "
                            "packets=" + str(self.packet_count) + " flows=" + str(self.flow_count) + " "
                            "active_flows=" + str(len(self.aggregator.active_flows)),
                            flush=True
                        )

                    last_flush = now
                    cycle_packets = 0

        except Exception as e:
            self.last_error = "Sniffing error: " + str(e)
            print("[CAPTURE] Unhandled exception in capture worker: " + str(e), flush=True)
        finally:
            self.is_running = False
            print(
                "[CAPTURE] Worker exited for interface='" + str(self.active_interface) + "'. "
                "Final counts: packets=" + str(self.packet_count) + " flows=" + str(self.flow_count),
                flush=True
            )


# Global singleton service
CAPTURE_SERVICE = LiveCaptureService()
