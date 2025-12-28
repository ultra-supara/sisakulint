---
title: "Commit Sha"
weight: 1
# bookFlatSection: false
# bookToc: true
# bookHidden: false
# bookCollapseSection: false
# bookComments: false
# bookSearchExclude: false
---

### Commit SHA Rule Overview

This rule is designed to detect actions that are not using SHA-1 to specify the version.

```yaml
name: CI
on: [push, pull_request]

jobs:
  lint:
    name: Lint
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-go@v4
        with:
          go-version: "1.21.3"
      - name: Run GolangCI-Lint
        uses: golangci/golangci-lint-action@v2
        with:
          version: v1.49
          args: --timeout 5m
```

result

```bash
.github/workflows/CI.yaml:24:3: timeout-minutes is not set for job docker; see https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idtimeout-minutes for more details. [missing-timeout-minutes]
       24 👈|  docker:
         
.github/workflows/release.yml:12:3: timeout-minutes is not set for job goreleaser; see https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idtimeout-minutes for more details. [missing-timeout-minutes]
       12 👈|  goreleaser:
         
.github/workflows/release.yml:30:9: unexpected key "env" for "element of \"steps\" sequence" section. expected one of  [syntax]
       30 👈|        env:
               
.github/workflows/release.yml:34:3: timeout-minutes is not set for job after_release; see https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idtimeout-minutes for more details. [missing-timeout-minutes]
       34 👈|  after_release:
         
(.venv) [kforfk@gmkhost sisakulint_dev]$ ./sisakulint script/commitsha.yaml
script/commitsha.yaml:5:3: timeout-minutes is not set for job lint; see https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idtimeout-minutes for more details. [missing-timeout-minutes]
      5 👈|  lint:
        
script/commitsha.yaml:9:9: the action ref in 'uses' for step '<unnamed>' should be a full length commit SHA for immutability and security. See documents: https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions [commit-sha]
      9 👈|      - uses: actions/checkout@v2
              
script/commitsha.yaml:10:9: the action ref in 'uses' for step '<unnamed>' should be a full length commit SHA for immutability and security. See documents: https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions [commit-sha]
       10 👈|      - uses: actions/setup-go@v4
               
script/commitsha.yaml:13:9: the action ref in 'uses' for step 'Run GolangCI-Lint' should be a full length commit SHA for immutability and security. See documents: https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions [commit-sha]
       13 👈|      - name: Run GolangCI-Lint
```

### Feature background
As the risk of supply chain attacks increases, ensuring the integrity of dependencies has become even more crucial. Since SHA values are immutable, they are more reliable than tags or branches, allowing you to securely lock in a specific version of an action. By using SHA-based versioning, you can minimize the risk of unintended updates or tampering, helping to protect against supply chain attacks.

In the past, one drawback of SHA-based versioning was the inability to automatically receive critical bug fixes or security updates for actions. To address this, tools like Renovate have emerged, and Dependabot has been enhanced to enable automated updates even when a version is pinned by SHA. This approach preserves the security of SHA-based versioning while ensuring updates to the latest secure versions, effectively balancing robust protection against supply chain attacks with the convenience of automated updates.


See also documents below.

{{< popup_link2 href="https://docs.github.com/en/actions/learn-github-actions/finding-and-customizing-actions#using-shas" >}}

{{< popup_link2 href="https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions" >}}



{{< popup_link2 href=https://www.chainguard.dev/unchained/what-the-fork-imposter-commits-in-github-actions-and-ci-cd >}}