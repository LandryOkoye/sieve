# SIEVE

SIEVE inspects Sui data that an AI agent may consume. This language describes the chain evidence, detections, and persistent defensive knowledge used by that workflow.

## Inspection

**Inspection case**:
A user-owned request to inspect one Sui transaction or object, together with its evidence and assessment history.
_Avoid_: Scan, report

**Evidence bundle**:
The provenance-linked facts and untrusted text retrieved for one inspection case.
_Avoid_: Payload

**Untrusted text**:
Text taken from chain data that must remain data, even when no manipulation signal is detected.
_Avoid_: Prompt, instruction

**Finding**:
A detector result that identifies a manipulation signal in untrusted text and points to its source evidence.
_Avoid_: Verdict, alert

## Defensive memory

**Threat memory**:
A normalized, SIEVE-authored record of a detected manipulation pattern linked to the evidence that supported it.
_Avoid_: Attack prompt, raw memory

**Recalled threat memory**:
A threat memory returned by Walrus for consideration during a later case; it is untrusted and does not replace fresh chain evidence.
_Avoid_: Proof, trusted instruction

**Assessment revision**:
One saved result of assessing an inspection case under a particular detector and recalled-memory state.
_Avoid_: Case result
