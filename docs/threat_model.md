# Threat Model — LeakProof Scanner

Author: Ibukun Olaniyan
Date: 29th May, 2026.
Version: 1.0
Project: LeakProof Scanner


## 1. Overview
LeakProof Scanner is a Python CLI tool and GitHub Action that scans Git diffs and files for accidentally committed secrets like: API keys, database passwords, tokens, and private keys before they reach a remote repository.

This document was written before any code was implemented.
All design decisions in this project trace back to the threats identified here.


## 2. The problem
A malicious bot could detect leak credentials within seconds of a push to a public repository and use them to cause serious damage depending on the secret type:

- AWS credentials  → full account takeover, data theft, thousands in charges from crypto miners
- Database passwords  → direct access to production data, customer records stolen or deleted
- API keys → abuse of paid services, identity spoofing, service disruption
- GitHub tokens   → access to private repos, code theft, supply chain attacks on your codebase
- Private keys  → impersonation, encrypted data decrypted

 This tool exists to eliminate this entire attack surface.


## 3. What are we building?
A two-part tool that intercepts secrets at two points:

Part 1 — Pre-commit hook (local)
Runs on the developer's machine before every commit.
Scans the staged diff. Blocks the commit if secrets found.
The earliest possible interception point.

Part 2 — GitHub Action (remote)
Runs on every pull request in CI/CD.
Catches anything that bypassed the pre-commit hook.
The last line of defence before code merges.


## 4. What are we protecting? — Assets
Format: Asset -- Description -- Impact if compromised 

 AWS credentials -- Access key + secret key  Full account takeover 
 Database passwords -- Connection string passwords -- Data theft or destruction 
 API keys -- Third party service keys -- Service abuse, financial loss 
 GitHub tokens -- Personal access tokens -- Repo access, supply chain attack 
 Private keys -- RSA/SSH private keys -- Impersonation, decryption 
 The scanner itself -- LeakProof codebase -- If tampered, secrets bypass detection 


## 5. STRIDE Analysis
 **S**poofing: Attacker pretends to be someone else. Example include- Stolen GitHub token used to push malicious code as legitimate developer
 **T**ampering: Attacker modifies data. Example include- Pre-commit hook script modified to silently skip secret detection 
 **R**epudiation: Actions cannot be traced. Example include- No record of which commit introduced a secret and attacker denies knowledge. 
 **I**nformation Disclosure: Sensitive data exposed. Example include- Secret committed in plaintext visible in public GitHub repo history 
 **D**enial of Service: Tool made unavailable. Example include- Scanner crashes on large diffs, secrets pass through undetected 
 **E**levation of Privilege: Attacker gains more access. Example include- Leaked AWS key used to escalate from read-only to admin via IAM misconfiguration 


## 6. Attack vectors — how secrets leak in practice
 Format: Vector -- How it happens -- Likelihood 

 Hardcoded credentials -- Developer pastes key directly into source code -- Very High 
 Config files committed -- .env, config.yml, settings.py pushed without .gitignore -- High 
 Debug code left in -- Temporary print statement exposing a token -- Medium 
 Test files -- Credentials used in unit tests committed -- Medium 
 Git history -- Secret removed from latest commit but still in history -- High 
 IDE auto-complete -- Editor suggests previously typed secret -- Low 


## 7. Detection methods

**Pattern matching**
Regex rules that recognise the known shape of specific secret types.
Precise — low false positive rate for known formats.
Limitation: only catches secrets we have patterns for.

**Shannon entropy analysis**
Mathematical measurement of randomness in a string.
High entropy = likely a secret, even without a known pattern.
Catches passwords and tokens that don't match any known format.
Limitation: higher false positive rate — random-looking strings
in legitimate code can trigger it.


## 8. Mitigations implemented
- Scanner runs as a pre-commit hook and intercepts before push
- GitHub Action provides second layer if hook is bypassed
- Both pattern matching AND entropy used together to reduce false negatives
- Non-zero exit code blocks commits and PR merges automatically
- .gitignore template provided to prevent common config files being committed


## 9. Limitations and what LeakProof Scanner does not catch
- Does not scan Git history — only current diff and staged files
- Does not detect secrets in binary files or images
- Entropy analysis generates false positives on minified JS, hashes, and UUIDs
- A developer can bypass the pre-commit hook with git commit --no-verify
- Does not rotate or revoke detected secrets automatically plus human action is required after detection
- Does not scan dependencies or third party packages for embedded secrets


## 10. Assumptions
- The developer's machine running the pre-commit hook is trusted
- GitHub Actions environment is not compromised
- Detected secrets are treated as fully compromised and rotated mmediately — detection alone is not sufficient remediation


## 11. References
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [truffleHog — open source secrets scanner](https://github.com/trufflesecurity/trufflehog)
- [GitGuardian State of Secrets Sprawl Report](https://www.gitguardian.com/state-of-secrets-sprawl)
- [Shannon Entropy — Wikipedia](https://en.wikipedia.org/wiki/Entropy_(information_theory))
- [GitHub — Removing sensitive data from a repository](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
