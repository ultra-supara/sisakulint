---
title: "ID Rule"
weight: 1
# bookFlatSection: false
# bookToc: true
# bookHidden: false
# bookCollapseSection: false
# bookComments: false
# bookSearchExclude: false
---

**Rule Overview:**

This rule is designed to analyze job and step IDs in GitHub Actions workflows, ensuring they adhere to specified naming conventions. The rule checks the following:

1. **Job ID Validation**:
   - Validates that job IDs start with a letter or underscore (`_`).
   - Ensures job IDs may only contain alphanumeric characters, hyphens (`-`), or underscores (`_`).
   - Flags any job IDs that contain invalid characters or formats, such as those starting with a hyphen, containing periods, or starting with a number.

2. **Step ID Validation**:
   - Ensures that step IDs also start with a letter or underscore (`_`).
   - Validates that step IDs may only contain alphanumeric characters, hyphens (`-`), or underscores (`_`).
   - Raises an error for any step IDs that contain spaces or other invalid characters.

3. **General Naming Best Practices**:
   - Encourages the use of clear and descriptive IDs to enhance readability and maintainability of workflows.
   - Flags any IDs that do not conform to the established conventions, guiding users to correct their configurations.

The test sample `id_name_convention.yaml` file is below.

```yaml
on: push

jobs:
  foo-v1.2.3:
    runs-on: ubuntu-latest
    steps:
      - run: echo 'job ID with version'
        id: echo for test
  -hello-world-:
    runs-on: ubuntu-latest
    steps:
      - run: echo 'oops'
  2d-game:
    runs-on: ubuntu-latest
    steps:
      - run: echo 'oops'
```

results

```bash
a.yaml:5:3: Invalid job ID "foo-v1.2.3". job IDs must start with a letter or '_', and may contain only alphanumeric characters, '-', or '_'. [id]
      5 👈|  foo-v1.2.3:
                   
a.yaml:10:13: Invalid step ID "echo for test". step IDs must start with a letter or '_', and may contain only alphanumeric characters, '-', or '_'. [id]
       10 👈|        id: echo for test
                   
a.yaml:12:3: Invalid job ID "-hello-world-". job IDs must start with a letter or '_', and may contain only alphanumeric characters, '-', or '_'. [id]
       12 👈|  -hello-world-:
                    
a.yaml:17:3: Invalid job ID "2d-game". job IDs must start with a letter or '_', and may contain only alphanumeric characters, '-', or '_'. [id]
       17 👈|  2d-game:
```

This rule helps maintain best practices in naming conventions for job and step IDs in GitHub Actions workflows, reducing the risk of misconfigurations and ensuring that workflows are set up according to GitHub's guidelines.