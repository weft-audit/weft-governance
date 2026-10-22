# Security policy

## Reporting

Do not disclose a vulnerability in a public issue before a maintainer has
acknowledged it.

Until a private reporting channel is published, report only through a private
channel explicitly provided by the repository owner. Do not send credentials,
private logs, personal data, or third-party secrets.

## Scope

Security review covers the code in this repository. It does not cover:

- external model providers;
- downstream agent runtimes;
- project-source adapters outside this repository;
- production deployment configuration;
- untrusted plugins or extensions.

## Required report details

- affected version and commit;
- minimal reproduction using synthetic data;
- expected and observed behavior;
- whether data, approval state, or execution authority can cross a boundary;
- any known prerequisites or limitations.
