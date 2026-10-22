# Publication protocol

## Purpose

The publication contract decides whether a proposed public action may proceed.
It does not perform the action and does not manage credentials.

The protocol exists because "continue implementation" is not equivalent to
"publish the result".

## Inputs

A caller supplies:

- action type;
- exact target;
- exact payload SHA256;
- whether the current owner message explicitly requested that action;
- how many target identifiers match the owner message;
- optional risk flags;
- an optional approval of an exact manifest hash.

No raw prompt or payload is required by the contract.

## Manifest

```json
{
  "schema_version": "publication-contract/v1",
  "policy_version": "2.0.0",
  "action_type": "comment",
  "target": "issue #7 owner/repo",
  "payload_sha256": "<64 hex characters>",
  "source": "caller-supplied"
}
```

The SHA256 of the canonical JSON manifest is the approval fingerprint.

## Decisions

### AUTO_SEND

Returned only when one of these is true:

- the owner message explicitly requested the action and supplied enough target
  identifiers;
- an exact manifest fingerprint was approved.

Hard or sensitive risk flags can prevent either shortcut.

### REQUIRE_OWNER_APPROVAL

Returned when:

- the target is incomplete;
- the owner instruction is implicit or ambiguous;
- a sensitive flag such as `core_material` or `first_time_target` is present.

The response includes:

```text
APPROVE_PUBLIC_ACTION <manifest sha256>
```

The caller must ask the owner to approve exactly that manifest. Approval state,
expiry, and one-time consumption belong to a stateful enforcement layer outside
this pure contract.

### BLOCK

Returned for flags including:

- `credential_or_secret`;
- `private_source_overlap`;
- `content_unavailable`;
- `scan_incomplete`;
- `gate_bypass`.

Blocking cannot be overridden by manifest approval. The payload must be
remediated first.

## Stateful integration

A stateful gate should additionally enforce:

- approval expires after a short interval;
- one approval can authorize only one execution;
- policy-version changes invalidate old approvals;
- content and target are re-hashed immediately before execution;
- scan failure is fail-closed;
- the public-write credential is isolated from the planning process.

## Guarantees and limits

Guaranteed by this pure module:

- deterministic output for the same inputs;
- no implicit I/O, model usage, command execution, or network access;
- no payload text stored in the manifest or decision.

Not guaranteed by this module:

- that target or payload hashes were truthfully calculated;
- that a source adapter reported the truth;
- that a downstream process obeys the decision;
- that an approval file cannot be tampered with by a privileged local process.
