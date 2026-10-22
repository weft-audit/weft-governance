# WEFT 2.0 release scope

## Public/private boundary

WEFT 2.0 is the public governance core, not the complete private platform.
The boundary exists so the public release can demonstrate technical capability
without exposing personal data, internal operations, or future commercial work.

### Public executable code

- deterministic Goal Compiler V0;
- deterministic Trust Boundary V0;
- deterministic Publication Contract V1;
- offline tests, synthetic examples, and the package entry point.

### Public design material only

- the intent-entry and confirmation boundary;
- audit and evidence principles;
- memory-index interface principles and source traceability;
- reproducible architecture and threat-model descriptions.

No private runtime implementation is transferred merely because its interface
or design principle is documented here.

### Private and excluded

- personal memory, persona, relationship, and private-fact content;
- live Agent identities, prompts, sessions, permissions, tools, or credentials;
- the complete multi-agent orchestrator and conversational runtime;
- the private memory database, source corpus, cards, and benchmark ground truth;
- the DSH ACP bridge implementation;
- production logs, incident raw logs, approval records, or operating
  configuration;
- commercial editions, hosted services, enterprise integrations, support
  material, and future proprietary extensions;
- private strategy, employment, financial, legal, or health information.

## Included

- the public executable code listed above;
- Apache-2.0 license and project-policy documents;
- architecture, licensing, provenance, and release-check documentation;
- a reproducible Python package and wheel build.

## Excluded

- every item in the private and excluded boundary above;
- any code or data that depends on a machine-local path or private service.

## Claims

This repository proves that the included deterministic primitives can be tested
locally. It does not prove that any complete agent platform has been deployed,
that arbitrary owner intent is correctly understood, or that downstream agents
obey the contracts without a correctly implemented host.

## Public source

This release candidate is based on code and specifications written for the WEFT
project. External frameworks referenced in private research are not relicensed
or redistributed here.

Apache-2.0 permits downstream commercial and closed-source use. The license does
not grant trademark rights, and it does not transfer copyright ownership.
