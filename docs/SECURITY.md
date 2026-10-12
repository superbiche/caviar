# Security and supported use

Each trust domain owns its HMAC key. Worker initialization uses private pipes;
no key in argv, environment, diagnostics or release metadata. Missing/short
keys refuse. Consumers must abort persistence or export on redaction failure.

Redaction follows a fixed contract, not entropy guesses or an LLM. It cannot
promise detection of every secret; report uncovered shapes with synthetic
examples and no actual credentials. Supported content is valid Unicode and
JSON-compatible values; unsupported inputs are refused instead of coerced.

The synthetic conformance fixtures are losslessly encoded for source scanners.
Encoding is not encryption or a security boundary. The decoded hash establishes
fixture identity. Plaintext materialization stays in ignored tmp/, never logs.

## Reporting vulnerabilities

Use GitHub private vulnerability reporting for
[superbiche/caviar](https://github.com/superbiche/caviar/security/advisories).
Select **Report a vulnerability** and provide a synthetic reproduction,
affected version and impact. Never include real credentials or private
transcripts in public issues or reports. Ordinary issues are for non-sensitive
bugs; suspected vulnerabilities belong in the private reporting channel.

Public releases require installed qualification, independent security review,
real source/artifact scans and GitHub push protection. A scanner or protection
refusal stops publication without a waiver.
