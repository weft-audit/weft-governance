# Contributing

## Development rules

1. Use only Python standard-library dependencies unless a change explicitly
   justifies another dependency and includes supply-chain review.
2. Every behavioral change needs an offline test that fails without the change.
3. Do not submit real owner prompts, personal data, private project material, or
   credentials in fixtures, tests, issues, or commit messages.
4. Keep deterministic library code free of implicit file, network, model, and
   command execution.
5. Public-action authorization tests must cover exact allow, owner-approval, and
   hard-block paths.

## Initial contribution boundary

The initial release welcomes issue reports, reproducibility results, security
research, and documentation corrections through the issue tracker.

The project does **not** yet accept pull requests containing source code or
other copyrightable material. This is a temporary rights-management boundary,
not a statement that external contributions are unwelcome. A contribution
agreement must be published before code pull requests are opened to the public.

Do not submit a code patch until the maintainers explicitly open that process.
Opening a pull request is not, by itself, a grant of the broader rights needed
to offer the same code under a future alternative or commercial license.

## Developer Certificate of Origin

If a future contribution process uses a Developer Certificate of Origin, every
commit must include:

```text
Signed-off-by: Your Name <your-public-email>
```

By signing off, you certify that you have the right to submit the contribution
under this repository's Apache-2.0 license.

A DCO sign-off does not assign copyright and does not grant a relicensing right.
That distinction matters if the project later offers different license terms.
The project may require a separate contribution agreement for code.

## Pull requests

A change is not complete if:

- tests were skipped without explanation;
- a security boundary was weakened without documentation;
- private data was added to fixtures or history;
- the public API changed without a corresponding changelog entry.
