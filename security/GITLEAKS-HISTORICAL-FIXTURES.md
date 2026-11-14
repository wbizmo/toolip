# Historical Gitleaks fixture classification

Gitleaks v8.24.3 reported six findings while scanning repository history. They
are all in test source that intentionally constructs fake credentials to verify
secret detection. The checked-in worktree-only scan reports no findings. The
historical values are not present in current tracked files.

| Historical commit                          | File and line                               | Rule              | Classification evidence                                                              |
| ------------------------------------------ | ------------------------------------------- | ----------------- | ------------------------------------------------------------------------------------ |
| `46eb4dfaaf6581606468191487c0eb6ec7f25790` | `tests/analyzers/git-history.test.ts:40`    | `github-pat`      | Test-local PAT-shaped value has the obvious sequential `1234567890` fixture prefix.  |
| `54844de9763f0b7f1b08b20f70a0c6ad8c9c01bf` | `tests/analyzers/git-history.test.ts:91`    | `github-pat`      | Short, invalid-length PAT-shaped negative-test value.                                |
| `09f871ced881e376a1061a899c39f4cdc204b3fe` | `tests/analyzers/git-history.test.ts:48`    | `github-pat`      | Test-local synthetic value contains an explicit test marker and is not a usable PAT. |
| `99daadeead92cc2fc9b2ffbb628dd1f762495143` | `tests/security-doctor.test.ts:25`          | `github-pat`      | Test-local sequential fixture value used as the detector's positive input.           |
| `54185d96c94024fd759fde94bf42859417b97b9e` | `tests/security-doctor-fixtures.test.ts:16` | `generic-api-key` | Short placeholder used only as scanner test input; below a usable credential length. |
| `43022955aa32dc8d6b3fa4a2369e59e7268ff9a3` | `tests/security-doctor.test.ts:17`          | `generic-api-key` | Test-local API-key-shaped value has an obvious sequential fixture prefix.            |

The original full-history findings were inspected with fully redacted reports;
only rule, path, line and commit metadata were retained. No credential value was
printed or copied into this record. The source contexts assign the values to
test fixtures and assert scanner behavior; they are not credentials used by
Toolip or its CI. No rotation is applicable. The current worktree scan verifies
that none of these values remains in the present source tree.

`.gitleaksignore` suppresses only these six exact fingerprints, each bound to a
specific commit, path, rule and line. It does not suppress the same rule in any
other file or commit. This preserves the scanner regression fixtures in history
without widening directory or rule-level exclusions. New findings continue to
fail Gitleaks.
