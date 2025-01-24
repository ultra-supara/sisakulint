# Development Guide

This document provides guidelines for developing sisakulint.

## Development Environment Setup

1. Install Go
```bash
curl -LO https://golang.org/dl/go<version>.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go<version>.linux-amd64.tar.gz
set -Ux PATH /usr/local/go/bin $PATH
go version
```

2. Install development dependencies
```bash
go mod init
go mod tidy
```

## Project Structure

```
.
├── cmd/sisakulint          # command line tools root
│   ├── main.go             # Entry point
│
├── pkg/                    # core source code
│   ├── ast/
│   └── core/
│   └── expressions/
└── script/                 # script files
```

## Development Workflow

1. Create a new branch for your feature
```bash
git checkout -b feature/your-feature-name
```

2. Run tests during development
```bash
go test
```

3. Release new version
```bash
git tag -d v0.0.9            # Delete the local tag
git push origin --delete v0.0.9  # Delete the remote tag (if it's pushed)
git tag v0.0.9                # Create the new tag
git push
git push origin v0.0.9        # Push the new tag to the remote repository
```

## Testing

- Write unit tests witten in Go for new functionality

## Pull Request Guidelines

1. Ensure all tests pass
2. Update documentation
3. Add test cases
4. Follow Go coding standards
5. Include vulnerability detection rules if applicable

## Security Considerations

- Do not include non-value commits.
- Use safe coding practices in the main tool
- Document security implications
