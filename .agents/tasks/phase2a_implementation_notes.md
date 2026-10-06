# Phase 2A Implementation Notes

## Objective
Test whether SYN/FIN flags are responsible for synthetic DoS Hulk traffic being classified as PortScan.

## Changes Made

### New Function: `generate_dos_hulk_phase2a()`
- **Location**: `services/demo/dos_hulk_demo.py`
- **Default output**: `scratch/dos_hulk_phase2a.pcap`
- **Default flows**: 5 (for controlled test)

### Flag Modifications

| Packet Type | Phase 1 (Original) | Phase 2A (SYN/FIN Removed) | Rationale |
|-------------|------------------|---------------------------|-----------|
| Initial handshake (pkt 1) | `"S"` (SYN) | `""` (no flags) | SYN flag removed |
| Server response (pkt 2) | `"SA"` (SYN+ACK) | `"A"` (ACK only) | SYN flag removed, keep ACK |
| Handshake ACK (pkt 3) | `"A"` (ACK) | `"A"` (ACK) | UNCHANGED |
| Request packets (pkt 4,7,10) | `"PA"` (PSH+ACK) | `"PA"` (PSH+ACK) | UNCHANGED |
| Response packets (pkt 5,8,11) | `"PA"` (PSH+ACK) | `"PA"` (PSH+ACK) | UNCHANGED |
| ACK packets (pkt 6,9) | `"A"` (ACK) | `"A"` (ACK) | UNCHANGED |
| Connection close (pkt 12) | `"FA"` (FIN+ACK) | `"A"` (ACK only) | FIN flag removed |

### TCP Flags Affected
- **SYN (0x02)**: Removed from all packets
- **FIN (0x01)**: Removed from all packets

### TCP Flags Preserved
- **PSH (0x08)**: Unchanged (kept on packets 4,5,7,8,10,11)
- **ACK (0x10)**: Unchanged (kept on packets 2,3,4,5,6,7,8,9,10,11,12)
- **RST (0x04)**: Unchanged (not present in original generator)

## Implementation Details

### Preserved from Phase 1
- **Flow duration**: 30–90 seconds (uniformly sampled per flow)
- **Packet count**: 12 packets per flow
- **Payload**: HTTP GET requests (~55 bytes) and responses (~1930 bytes)
- **Window sizes**: Attack win=29200, Victim win=235 (shrinking)
- **Source/Destination**: 10.0.0.50 (attacker) → 10.0.0.100 (victim, port 80)
- **Protocol**: TCP on port 80
- **Inter-packet timing**: 50–100 ms spread uniformly across flow duration
- **Sequence numbers**: Deterministic per flow (standard TCP handshake)

### Unchanged Code
- Original `generate_dos_hulk_pcap()` function remains identical
- Original `generate_dos_hulk_pcap_phase1()` function remains identical
- `DosHulkDemoRunner` class unchanged
- No modification to database schema, XGBoost model, preprocessing, or inference pipeline

## Testing Protocol

1. Generate 5 Phase 2A flows → `scratch/dos_hulk_phase2a.pcap`
2. Generate 5 Phase 1 flows → `scratch/dos_hulk_phase1.pcap` (or use existing)
3. Run both through production pipeline:
   - PCAP replay
   - FlowAggregator (77-feature extraction)
   - Preprocessing (feature normalization, ordering)
   - XGBoost inference
   - Database recording
4. Compare predictions:
   - Phase 1: likely PortScan (with SYN/FIN)
   - Phase 2A: test whether removal shifts prediction toward DoS Hulk
5. If Phase 2A remains PortScan: SYN/FIN is not the root cause
6. If Phase 2A becomes DoS Hulk: SYN/FIN flags were a strong signal for PortScan classification

## Backup Location
Phase 1 state preserved at: `services/demo/dos_hulk_demo_phase1_before_phase2a.py`

## Critical Constraints (Not Modified)
- XGBoost model: no changes
- Preprocessing pipeline: no changes
- Alert threshold (0.80): no changes
- PortScan implementation: no changes
- Database schema: no changes
- Inference pipeline: no changes
- Any other attack implementation: no changes
