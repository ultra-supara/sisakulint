---
title: "Workflowcall Rule"
weight: 1
# bookFlatSection: false
# bookToc: true
# bookHidden: false
# bookCollapseSection: false
# bookComments: false
# bookSearchExclude: false
---

---

**Rule Overview:**

This rule is designed to analyze GitHub Actions workflows for common misconfigurations when using reusable workflows. It focuses on ensuring that certain settings are correctly applied according to GitHub Actions standards, and it identifies errors in the following cases:

1. **Validation of `runs-on` with Reusable Workflows**:
   - Checks for improper use of the `runs-on` keyword when calling a reusable workflow using the `uses` keyword.
   - Triggers an error if `runs-on` is specified when calling a reusable workflow since this is not supported. Instead, the reusable workflow should define its own `runs-on` internally.

2. **Local File Paths with Refs**:
   - Analyzes the use of `uses` with a reference (`@main`, `@v1`, etc.) pointing to a local workflow file path (e.g., `./.github/workflows/ci.yml@main`).
   - Flags an error if a local workflow file path is specified with a version ref, as this is not allowed. Local workflows should not include version references.

3. **Use of `with` for Reusable Workflows**:
   - Checks for improper usage of the `with` field when calling reusable workflows.
   - Raises an error if `with` is used outside of the proper context (e.g., in regular workflows instead of reusable ones). Parameters in the `with` block should only be used for inputs when calling reusable workflows correctly.

This rule helps enforce proper usage of reusable workflows and GitHub Actions syntax, reducing potential configuration errors and ensuring workflows are set up according to best practices.

The test sample `permissions.yaml` file is below.

```yaml
on: push
jobs:
  job1:
    uses: ultra-supara/sisakulint/workflow.yml@v1
    # ERROR: 'runs-on' is not available on calling reusable workflow
    runs-on: ubuntu-latest
  job2:
    # ERROR: Local file path with ref is not available
    uses: ./.github/workflows/ci.yml@main
  job3:
    # ERROR: 'with' is only available on calling reusable workflow
    with:
      foo: bar
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
```

results

```bash
a.yaml:6:5: when a reusable workflow is called with "uses", "runs-on" is not available. only following keys are allowed: "name", "uses", "with", "secrets", "needs", "if", and "permissions" in job "job1" [syntax]
      6 👈|    runs-on: ubuntu-latest
          
a.yaml:6:14: one ${{ }} expression should be included in "runner label at \"runs-on\" section" value but got 0 expressions [expression]
      6 👈|    runs-on: ubuntu-latest
                   
a.yaml:9:11: reusable workflow call "./.github/workflows/ci.yml@main" at uses is not following the format "owner/repo/path/to/workflow.yml@ref" nor "./path/to/workflow.yml". please visit to https://docs.github.com/en/actions/learn-github-actions/reusing-workflows for more details [workflow-call]
      9 👈|    uses: ./.github/workflows/ci.yml@main
                
a.yaml:12:5: "with" is only available for a reusable workflow call with "uses" but "uses" is not found in job "job3" [syntax]
       12 👈|    with:
           
a.yaml:14:14: one ${{ }} expression should be included in "runner label at \"runs-on\" section" value but got 0 expressions [expression]
       14 👈|    runs-on: ubuntu-latest
```

This rule helps enforce proper usage of reusable workflows and GitHub Actions syntax, reducing potential configuration errors and ensuring workflows are set up according to best practices.

For more information, please refer to below.

{{< popup_link2 href=https://docs.github.com/en/actions/sharing-automations/reusing-workflows >}}
