# 🤝 Contributing to Sentinel HIDS

Thank you for your interest in contributing to Sentinel HIDS! This document explains how to contribute effectively.

---

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Submitting Changes](#submitting-changes)
- [Adding Detection Rules](#adding-detection-rules)
- [Bug Reports](#bug-reports)
- [Feature Requests](#feature-requests)

---

## Code of Conduct

- Be respectful and constructive in all communications
- Focus on the technical merit of contributions
- Security vulnerabilities must be reported privately — do NOT open a public issue

---

## How to Contribute

### Types of contributions welcome

- 🐛 Bug fixes
- ✨ New detection rules (Sigma YAML)
- 📚 Documentation improvements
- 🔧 Performance improvements
- 🧪 Test cases
- 🌐 Dashboard UI improvements
- 🔒 Security improvements

---

## Development Setup

### 1. Fork and clone

```bash
git clone https://github.com/YOUR-USERNAME/sentinel-hids.git
cd sentinel-hids
git remote add upstream https://github.com/ORIGINAL-USERNAME/sentinel-hids.git
```

### 2. Set up agent development

```bash
cd agent
cargo build
cargo test
cargo clippy    # must pass with no warnings
cargo fmt       # must be formatted
```

### 3. Set up server development

```bash
cd server
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run tests
pytest tests/

# Run linting
flake8 .
black .
```

### 4. Run locally

```bash
# Start server stack
docker compose up -d postgres redis

# Run server locally
cd server
uvicorn main:app --reload --port 8000

# Run agent locally (in another terminal)
cd agent
RUST_LOG=debug cargo run
```

---

## Project Structure

```
agent/src/
├── main.rs        # Entry point — add new collectors here
├── models.rs      # Add new event types here
├── fim.rs         # File integrity monitoring
├── process.rs     # Process monitoring
├── network.rs     # Network monitoring
├── auth.rs        # Authentication monitoring
├── rootkit.rs     # Rootkit detection
└── sender.rs      # HTTP batch sender

server/
├── api/           # Add new API endpoints here
├── detection/     # Detection engine — modify rules here
├── ingest/        # Event processing pipeline
└── db/            # Database layer

rules/sigma/
└── linux_rules.yml   # Add new detection rules here
```

---

## Submitting Changes

### 1. Create a branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/bug-description
```

### 2. Make your changes

Follow these coding standards:

**Rust (agent):**
- Run `cargo fmt` before committing
- Run `cargo clippy` — no warnings allowed
- All public functions must have doc comments
- Handle all `Result` and `Option` types explicitly

**Python (server):**
- Run `black .` before committing
- Run `flake8 .` — no errors allowed
- Type hints required for all function signatures
- Use async/await for all I/O operations

**Detection Rules (Sigma YAML):**
- Must include: `id`, `title`, `description`, `severity`, `mitre`, `detection`
- Must map to a valid MITRE ATT&CK technique
- Must include test case in `tests/rules/`

### 3. Write tests

```bash
# Agent tests
cd agent && cargo test

# Server tests
cd server && pytest tests/ -v

# Rule tests
cd server && python3 tests/test_rules.py
```

### 4. Commit with clear message

```bash
git commit -m "feat: add detection rule for SSH key injection"
git commit -m "fix: false positive in rootkit module baseline"
git commit -m "docs: update installation guide for Ubuntu 22.04"
git commit -m "perf: reduce FIM scan memory usage by 30%"
```

Commit message prefixes:
- `feat:` — new feature
- `fix:` — bug fix
- `docs:` — documentation only
- `perf:` — performance improvement
- `refactor:` — code refactoring
- `test:` — adding tests
- `chore:` — maintenance

### 5. Open a Pull Request

```bash
git push origin feature/your-feature-name
```

Then open a PR on GitHub with:
- Clear title describing the change
- Description of what and why
- Link to any related issues
- Screenshots for dashboard changes

---

## Adding Detection Rules

To add a new Sigma detection rule:

### 1. Add to linux_rules.yml

```yaml
---
title: Your Rule Title
id: SENT-XXX-001
status: stable
description: |
  Brief description of what this rule detects and why it matters.
severity: high
tags:
  - attack.technique_category
  - tXXXX
mitre:
  tactic: Tactic Name
  technique_id: TXXXX
  technique_name: Technique Name
detection:
  # Choose the appropriate condition type:
  cmdline_contains:
    - suspicious_pattern
  # or
  auth_action:
    - action_name
  # or
  file_path_contains:
    - /suspicious/path
logsource:
  product: sentinel-hids
```

### 2. Test your rule

```bash
# Reload rules without restart
docker cp rules/sigma/linux_rules.yml sentinel-server:/app/rules/sigma/linux_rules.yml
docker compose restart server
docker compose logs server | grep "rules loaded"
```

### 3. Verify detection works

Test the detection by simulating the attack in a safe environment and confirming the alert fires.

---

## Bug Reports

Open a GitHub Issue with:

1. **Title**: Clear, concise description of the bug
2. **Environment**: OS version, Docker version, agent version
3. **Steps to reproduce**: Exact commands to reproduce
4. **Expected behaviour**: What should happen
5. **Actual behaviour**: What actually happens
6. **Logs**: Relevant log output

```bash
# Collect logs for bug report
docker compose logs server --tail=50 > server.log
sudo journalctl -u sentinel-agent -n 50 > agent.log
```

---

## Feature Requests

Open a GitHub Issue with the `enhancement` label and include:

1. **Problem**: What problem does this feature solve?
2. **Proposed solution**: How should it work?
3. **Alternatives**: Other approaches considered
4. **Additional context**: Screenshots, examples, references

---

## Security Vulnerabilities

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, email the maintainer directly with:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if known)

You will receive a response within 48 hours.
