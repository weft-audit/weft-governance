# WEFT 2.0

Deterministic primitives for scoped intent, context trust, and public-action
authorization.

**Status:** 2.0 release candidate. This repository is a deliberately narrow
open-source reference core. It does not claim to be a complete agent platform,
a sandbox, or a production control plane.

The exact included and excluded surface is defined in
[docs/release-scope.md](docs/release-scope.md).

The public repository is intended to make the governance primitives inspectable,
reusable, and independently testable. The complete conversational runtime,
private memory, live agent configuration, connectors, hosted services, and
future commercial extensions remain separate and are not part of this release.

## Implemented primitives

### 1. Goal compiler

`weft_governance.goal_compiler` turns an explicit intent record into a reviewable
specification containing scope, verification, rollback, approval gates, and
red-line checks.

- never calls a model;
- never reads project files on its own;
- never executes commands;
- always returns `execution_authorized=false`, even for `READY`;
- reports missing facts instead of inventing them.

### 2. Context trust boundary

`weft_governance.trust_boundary` classifies already-supplied records before they reach a
model.

| Trust level | May act as an instruction? | Intended source |
| --- | --- | --- |
| `core_policy` | yes, highest authority | deployment-controlled policy source |
| `owner_intent` | yes, below core policy | explicit owner intent |
| `project_fact` | no | project documentation and observations |
| `project_instruction` | no, reference data only | `AGENTS.md`, `CLAUDE.md`, `MANIFESTO.md`, or declared project instructions |
| `untrusted_context` | no | external or otherwise untrusted text |

The module performs no implicit file discovery or reading. Source labels are
only as trustworthy as the adapter that supplies them.

### 3. Publication contract

`weft_governance.publication_contract` evaluates a proposed public action without
performing it.

```text
explicit owner action + sufficient target matches + no risk flags
    -> AUTO_SEND

ambiguous target OR sensitive risk
    -> REQUIRE_OWNER_APPROVAL

secret, private-source overlap, hidden content, bypass, or incomplete scan
    -> BLOCK
```

The contract contains no I/O, model calls, command execution, network access,
or persistent approval state. Callers supply only the exact action, target,
payload hash, owner-intent facts, and risk flags.

The approval fingerprint binds:

- contract schema and policy version;
- action type;
- exact target;
- exact payload SHA256;
- action source.

Changing any bound value invalidates an old approval.

## Run

```powershell
$env:PYTHONPATH = "$PWD\src"
python -m weft_governance --input examples\intent-ready.json

# after installing the wheel
weft-governance --input examples\intent-ready.json
```

Exit codes:

- `0`: `READY`
- `2`: `NEEDS_OWNER_INPUT` or invalid input
- `3`: `BLOCKED`

## Test

```powershell
python -m unittest discover -s tests -p "test_*.py"
```

Runtime dependencies: Python 3.10+ standard library only. Building a wheel uses
setuptools as declared in `pyproject.toml`.

## Security boundaries

- No sandbox is provided.
- No cryptographic signature is produced by the library itself.
- No truth claim is made about a trusted source; source adapters remain part of
  the trusted computing base.
- No production deployment, hosted service, or complete multi-agent workflow
  is included.
- Project-local instructions remain reference data even when they claim higher
  authority.

## Versioning

The contract policy version is part of every publication fingerprint. A policy
change intentionally invalidates approvals produced under the previous policy.

Component versions are independent:

- package: `2.0.0`;
- Goal Compiler internals: `0.1.1` (component `V0`);
- Trust Boundary internals: `0.1.0` (component `V0`);
- Publication Contract schema: `publication-contract/v1`;
- Publication Contract policy: `2.0.0`.

## License

Source code and repository documentation are licensed under the
[Apache License 2.0](LICENSE).

The Apache license grants copyright and patent licenses but does not grant
trademark rights to the project name or logo. See [TRADEMARKS.md](TRADEMARKS.md)
and [docs/licensing.md](docs/licensing.md).

Copyright 2026 The WEFT Project. See [NOTICE](NOTICE).

Apache-2.0 grants rights to use and redistribute the code; it does not transfer
copyright ownership.
