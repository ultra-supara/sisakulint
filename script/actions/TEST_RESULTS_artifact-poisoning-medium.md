# Test Results: artifact-poisoning-medium Rule

This document contains the test results for the `artifact-poisoning-medium` rule using example workflows from [CodeQL documentation](https://codeql.github.com/codeql-query-help/actions/actions-artifact-poisoning-medium/#example).

## Test Files

1. **artifact-poisoning-medium-vulnerable.yaml** - Vulnerable pattern (no safe path)
2. **artifact-poisoning-medium-safe.yaml** - Safe pattern (with runner.temp path)
3. **artifact-poisoning-medium-heuristic.yaml** - Tests heuristic detection for unknown actions

## Test Results

### 1. Vulnerable Workflow Detection

**File:** `script/actions/artifact-poisoning-medium-vulnerable.yaml`

```bash
$ ./sisakulint script/actions/artifact-poisoning-medium-vulnerable.yaml
```

**Result:** ✅ Successfully detected

```
script/actions/artifact-poisoning-medium-vulnerable.yaml:27:9: artifact poisoning risk: third-party action "dawidd6/action-download-artifact@v2" downloads artifacts in workflow with untrusted triggers (workflow_run) without safe extraction path. This may allow malicious artifacts to overwrite existing files. Extract to '${{ runner.temp }}/artifacts' and validate content before use. See https://codeql.github.com/codeql-query-help/actions/actions-artifact-poisoning-medium/ [artifact-poisoning-medium]
```

**Analysis:**
- ✅ Correctly identifies `dawidd6/action-download-artifact@v2` as third-party artifact action
- ✅ Correctly detects `workflow_run` as untrusted trigger
- ✅ Correctly identifies missing safe extraction path
- ✅ Provides clear remediation guidance

### 2. Safe Workflow with Extraction Path

**File:** `script/actions/artifact-poisoning-medium-safe.yaml`

```bash
$ ./sisakulint script/actions/artifact-poisoning-medium-safe.yaml
```

**Result:** ✅ Different warning level (still warns about untrusted content)

```
script/actions/artifact-poisoning-medium-safe.yaml:29:9: artifact poisoning risk: third-party action "dawidd6/action-download-artifact@v2" downloads artifacts in workflow with untrusted triggers (workflow_run). Even with safe extraction paths, validate artifact content before use (checksums, signatures) and avoid executing scripts directly. See https://codeql.github.com/codeql-query-help/actions/actions-artifact-poisoning-medium/ [artifact-poisoning-medium]
```

**Analysis:**
- ✅ Correctly recognizes safe extraction path (`${{ runner.temp }}/artifacts/`)
- ✅ Still warns about untrusted content (appropriate defense-in-depth approach)
- ✅ Provides guidance on content validation
- ✅ Does not trigger auto-fix (path is already safe)

### 3. Heuristic Detection for Unknown Actions

**File:** `script/actions/artifact-poisoning-medium-heuristic.yaml`

```bash
$ ./sisakulint script/actions/artifact-poisoning-medium-heuristic.yaml
```

**Result:** ✅ Successfully detected both unknown actions

```
script/actions/artifact-poisoning-medium-heuristic.yaml:24:9: artifact poisoning risk: third-party action "some-org/download-artifact-action@v1" downloads artifacts in workflow with untrusted triggers (pull_request_target) without safe extraction path. [artifact-poisoning-medium]

script/actions/artifact-poisoning-medium-heuristic.yaml:29:9: artifact poisoning risk: third-party action "custom/artifact-download@main" downloads artifacts in workflow with untrusted triggers (pull_request_target) without safe extraction path. [artifact-poisoning-medium]
```

**Analysis:**
- ✅ Heuristic detection works for `some-org/download-artifact-action` (contains "download" + "artifact")
- ✅ Heuristic detection works for `custom/artifact-download` (contains "artifact" + "download")
- ✅ Correctly identifies `pull_request_target` as untrusted trigger
- ✅ Properly excludes `actions/download-artifact` (handled by critical rule)

## Unit Test Results

All unit tests pass successfully:

```bash
$ go test -v ./pkg/core -run TestArtifactPoisoningMedium
=== RUN   TestArtifactPoisoningMedium_VisitWorkflowPre
--- PASS: TestArtifactPoisoningMedium_VisitWorkflowPre (0.00s)
=== RUN   TestArtifactPoisoningMedium_VisitStep
--- PASS: TestArtifactPoisoningMedium_VisitStep (0.00s)
=== RUN   TestArtifactPoisoningMedium_FixStep
--- PASS: TestArtifactPoisoningMedium_FixStep (0.00s)
=== RUN   TestArtifactPoisoningMedium_Integration
--- PASS: TestArtifactPoisoningMedium_Integration (0.00s)
PASS
ok  	github.com/ultra-supara/sisakulint/pkg/core	0.744s
```

## Code Refactoring Results

The following refactoring was performed based on PR review comments:

### 1. Removed Code Duplication

**Created:** `pkg/core/artifactpoisoningutil.go`

This utility file provides:
- `UntrustedTriggers` - Shared map of untrusted workflow triggers
- `AddPathToWithSection()` - Shared YAML manipulation function

**Updated files:**
- `pkg/core/artifactpoisoningmedium.go` - Now uses shared utilities
- `pkg/core/artifactpoisoningcritical.go` - Now uses `AddPathToWithSection()`
- `pkg/core/cachepoisoningrule.go` - Now uses `UntrustedTriggers`

### 2. All Tests Pass After Refactoring

```bash
$ go test -v ./pkg/core -run "TestArtifactPoisoning|TestCachePoisoning"
PASS
ok  	github.com/ultra-supara/sisakulint/pkg/core	1.030s
```

## Summary

✅ **All test cases pass successfully**
✅ **Heuristic detection works as expected**
✅ **Safe and unsafe patterns correctly distinguished**
✅ **Code duplication removed**
✅ **All unit tests pass**
✅ **Integration with existing rules verified**

The `artifact-poisoning-medium` rule is working correctly and ready for production use.
