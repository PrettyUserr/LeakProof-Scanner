# Results — LeakProof Scanner

Author: Ibukun Olaniyan  
Date: 1st June, 2026.  
Version: 1.0  


## Test Environment
 Test file -- tests/test_secrets.py 
 Total lines scanned -- 20 
 Scan duration -- <1 second 
 Detection methods used -- Pattern matching + Shannon entropy 


## Findings Summary
 Critical - 5 
 High - 3 
 Medium - 0 
 Low - 0 
 Total - 8


## Findings Detail

| Line | Secret Type | Severity | Method |

| 4 | AWS Access Key | CRITICAL | Pattern Match |
| 5 | AWS Secret Key | CRITICAL | Pattern Match |
| 8 | GitHub Personal Access Token | CRITICAL | Pattern Match |
| 11 | Database Connection String | CRITICAL | Pattern Match |
| 20 | Private Key Header | CRITICAL | Pattern Match |
| 14 | Generic API Key | HIGH | Pattern Match |
| 14 | Google API Key | HIGH | Pattern Match |
| 17 | Generic Password | HIGH | Pattern Match |


## False Positives Identified

| File | Line | Flagged As | Reason | Fixed |

| core/entropy.py | 21 | High Entropy String | BASE64_CHARS constant flagged as secret | Yes — added to IGNORED_LINES |
| core/entropy.py | 22 | High Entropy String | HEX_CHARS constant flagged as secret | Yes — added to IGNORED_LINES |

False positive rate on test file: 0%  
False positive rate on own codebase before fix: 2 findings  
False positive rate on own codebase after fix: 0%  


## Pre-commit Hook Test

| Test | Result |
|
| Commit with secrets staged | Blocked — exit code 1 |
| Commit without secrets staged | Passed — exit code 0 |


## Before vs After

| Scenario | Without LeakProof | With LeakProof |

| AWS key committed | Reaches GitHub in seconds, bots detect within minutes | Blocked at commit stage |
| Database password committed | Full database exposed | Blocked before push |
| Private key committed | Account impersonation possible | Blocked before push |
| Unknown secret (entropy) | Passes all pattern checks | Flagged for manual review |