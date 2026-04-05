# 🔒 Security Policy — Sentinel HIDS

## Supported Versions

| Version | Supported |
|---|---|
| 2.0.x | ✅ Yes |
| 1.5.x | ✅ Yes |
| 1.0.x | ❌ No |

---

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues.**

Security vulnerabilities in a HIDS are especially sensitive because they could allow an attacker to blind the detection system.

### How to report

1. **Email** the maintainer directly (see GitHub profile)
2. Include in your report:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix if known

### What to expect

- **Acknowledgement** within 48 hours
- **Status update** within 7 days
- **Fix release** within 30 days for critical issues
- **Credit** in the CHANGELOG if desired

---

## Security Considerations for Deployment

### API Key Protection
- Use a strong, randomly generated API key (minimum 32 characters)
- Never commit `agent.json` or `.env` files to version control
- Rotate API keys periodically

### Network Security
- Run the server behind Nginx with TLS in production
- Restrict port 8000 to localhost only — let Nginx handle external access
- Use a firewall to limit dashboard access to trusted IP ranges

### Agent Security
- Run the agent as root (required for /proc access)
- The agent binary should be owned by root and not writable by other users
- Verify the agent binary hash after download

### Database Security
- Use a strong PostgreSQL password
- The database container should not be exposed externally
- Take regular backups of the PostgreSQL data volume

### Dashboard Security
- Enable HTTPS via Nginx TLS configuration
- Use strong JWT secrets (minimum 64 characters)
- Session tokens expire after 24 hours by default

---

## Known Security Limitations

- The agent requires root access to monitor /proc, /var/log/auth.log, and kernel modules
- Communication between agent and server uses HTTP by default — configure TLS for production
- The dashboard does not currently support multi-user role-based access control (RBAC)
- Alert data in PostgreSQL is not encrypted at rest by default
