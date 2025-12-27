---
title: "Timeoutminutes Rule"
weight: 1
# bookFlatSection: false
# bookToc: true
# bookHidden: false
# bookCollapseSection: false
# bookComments: false
# bookSearchExclude: false
---

### Rule Overview: Timeout Minutes Rule

This rule is designed to analyze YAML configuration files for GitHub Actions workflows, specifically focusing on the absence of the `timeout-minutes` attribute for jobs. It aims to enhance workflow reliability and prevent potential issues caused by long-running jobs. The rule identifies errors in the following cases:

#### Missing Timeout Minutes for Jobs:

- Checks for the presence of the `timeout-minutes` attribute in each job definition within the workflow.
- Triggers an error if a job is found without a specified timeout, as this can lead to jobs running indefinitely and consuming resources unnecessarily. Setting a timeout helps to ensure that jobs are terminated after a reasonable period, preventing resource exhaustion.

#### Importance of Timeout Minutes:

- Encourages the specification of timeout values for all jobs to maintain control over execution time and resource usage.
- Helps to avoid situations where a job may hang or take longer than expected, which can disrupt the overall workflow and lead to delays in CI/CD processes.

#### Security Implications:

- By enforcing timeout limits, this rule indirectly contributes to security by mitigating the risk of GitHub Actions being exploited through long-running jobs (e.g., in a potential C2 attack scenario). 
- Limiting job execution time can help prevent unauthorized access or resource abuse, ensuring that workflows remain efficient and secure.

The test sample [sisakulint yaml file on GitHub!](https://github.com/ultra-supara/sisakulint/.github/workflows/CI.yaml) file is below.

```yaml
name: CI
on: [push, pull_request]

jobs:
  lint:
    name: Lint
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332 # v4.1.7
      - uses: actions/setup-go@0a12ed9d6a96ab950c8f026ed9f722fe0da7ef32 # v5.0.2
        with:
          go-version: "1.21.4"
      - name: Check Go sources are formatted
        run: |
          diffs="$(gofmt -d ./pkg/core/*.go ./cmd/sisakulint/*.go)"
          if [[ "$diffs" != "" ]]; then
            echo "$diffs" >&2
          fi
      - name: Install staticcheck
        run: |
          go install honnef.co/go/tools/cmd/staticcheck@latest
          echo "$(go env GOPATH)/bin" >> "$GITHUB_PATH"

  docker:
    name: Dockerfile
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332 # v4.1.7
      - name: generatetoken
        id: generate_token
        uses: actions/create-github-app-token@5d869da34e18e7287c1daad50e0b8ea0f506ce69 # v1.11.0
        with:
          app-id: ${{ secrets.APP_ID }}
          private-key: ${{ secrets.PRIVATE_KEY }}
      - name: Build image
        id: image
        uses: docker/build-push-action@5cd11c3a4ced054e52742c5fd54dca954e0edd85 # v6.7.0
        with:
          build-args: |
            GOLANG_VER=1.21.4
            "TOKEN=${{ steps.generate_token.outputs.token }}"
          push: false
```

result

```bash
CI.yaml:5:3: timeout-minutes is not set for job lint; see https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idtimeout-minutes for more details. [missing-timeout-minutes]
      5 👈|  lint:
        
CI.yaml:24:3: timeout-minutes is not set for job docker; see https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idtimeout-minutes for more details. [missing-timeout-minutes]
       24 👈|  docker:
```

####  General Best Practices:
- Recommends setting appropriate timeout values based on the expected duration of jobs, taking into account the complexity and resource requirements of the tasks being performed.
- Raises awareness about the importance of managing job execution times in CI/CD pipelines, promoting adherence to best practices in workflow management and security.