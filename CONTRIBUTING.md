# Contributing to SIEM++

Thank you for your interest in contributing to SIEM++! This document outlines the process for setting up a development environment and contributing changes.

## Development Setup

```bash
git clone https://github.com/jojin1709/SIEM-.git
cd SIEM-
npm install
npm start
```

The server will run at `http://localhost:4000`. The API key is printed to the console.

## How to Contribute

1. **Fork** the repository
2. **Create a branch** (`git checkout -b feature/your-feature`)
3. **Make your changes**
4. **Test** thoroughly — all API endpoints should respond correctly with the API key
5. **Run linting** if available
6. **Commit** with a clear message
7. **Push** to your fork
8. **Open a Pull Request**

## Code Style

- Use 2-space indentation
- Use single quotes for strings (except in template literals)
- Add comments for complex logic
- Follow existing file naming conventions (`snake_case` for files, `camelCase` for variables)

## Testing

Before submitting a PR, verify:
- New API endpoints return correct status codes and JSON
- Security validation works (invalid inputs rejected)
- No XSS vectors introduced (all output escaped)
- Database migrations (`src/db.js`) are backward-compatible
- README is updated if new env vars or features are added

## Areas That Need Help

- **Parser improvements** — better format detection, more log formats
- **Detection rules** — additional rule templates for common attack patterns
- **Frontend components** — dashboard visualizations, charts
- **Threat intel** — more blocklist sources, IOC matching
- **Documentation** — guides, tutorials, best practices

## Security Disclosures

If you find a security vulnerability, please email jojin@users.noreply.github.com rather than opening a public issue.
