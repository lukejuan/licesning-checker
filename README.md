# Driver Licensing Register

Council admin dashboard + public licence checker. Python 3.9+ standard library only (SQLite storage).

```
ADMIN_PASSWORD=choose-something python3 app.py
```

- Public checker: http://localhost:8000/  (look up by licence/badge number)
- Admin dashboard: http://localhost:8000/admin  (default password `changeme`)

A driver appears on the public checker only if their status is **Active** and their licence is in date.
Setting **Suspended** or **Revoked** hides them immediately; every change is written to the audit log.

Delete `drivers.db` to reset to the sample data.
