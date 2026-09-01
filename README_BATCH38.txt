FourFaith RouterDiag v1.3 RC13 - Batch38 WAN Three-Topology Model

Field topology model
--------------------
Batch38 corrects the WAN deployment assumption. Field devices are modeled as exactly one of four diagnostic states:
- primary-only: only the primary WAN path is credibly present.
- backup-only: only the backup WAN path is credibly present.
- dual: both primary and backup paths have credible deployment evidence. This is treated as the uncommon case.
- unknown: the snapshot is insufficient to identify the deployment topology.

Important rule
--------------
Dormant/default `bkup_*` NVRAM keys do not by themselves make a device dual-link. This matters because normal field deployments are usually primary-only or backup-only.

Diagnosis behavior
-------------------
- Primary-only does not warn that a backup link is missing.
- Backup-only does not treat disabled/empty primary WAN fields as a fault.
- Dual-link-only advice (current egress, failover/switching priority) is emitted only when both paths are credibly present.
- Active-link selection remains separate from topology classification. Live interface/default-route evidence remains authoritative over imported snapshots.
