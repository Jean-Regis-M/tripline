# Security notes

## Scope

Tripline is a research prototype built for a hackathon. It is not audited and should not be the only control protecting production secrets.

## Reporting a problem

Open a GitHub issue titled "Security" with a minimal reproduction. For anything sensitive, use GitHub's private vulnerability reporting on this repository.

## Threat model

* **In scope:** hidden instructions in tool metadata, prompt injection arriving through tool output, exfiltration through outbound tools, silent changes to approved tools, simple encoding evasion (base64, hex, URL encoding).
* **Known evasions:** spelling data out in other words, keyed ciphers, compression, paraphrase, and a scanner payload that is a pure euphemism. These are covered only by rule R2 or not at all, and are asserted as known limitations in the tests.
* **Out of scope:** a compromised host, a malicious allow listed destination, covert channels such as timing, and semantic leaks where a model re-expresses private information in new words with no copied fragment (partially mitigated by rule R2).

## Web app hardening

The app is static and has no backend. All rendering uses `textContent` and never `innerHTML`. The local server sets a strict Content Security Policy, `nosniff`, rejects methods other than GET and HEAD and blocks path traversal. All secrets in the demo are synthetic.
