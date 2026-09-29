# Taxi Licensing Register

Council staff dashboard for licensed drivers and vehicles, plus public licence registers. Python 3.9+ standard library only (SQLite storage).

```
python3 app.py
```

- Public registers: http://localhost:8000/
  - Drivers: `/drivers` (look up by licence/badge number)
  - Vehicles: `/vehicles` (look up by registration or council plate number)
- Staff dashboard: http://localhost:8000/admin (drivers) and `/admin/vehicles`

## First run

With no staff accounts yet, `/admin` sends you to `/setup` to create the first **admin** account.
This page stops working as soon as one account exists.

## Staff accounts

- **Officers** can view and manage drivers. **Admins** can also manage staff at `/admin/staff`.
- Adding a staff member generates a one-time temporary password; they must choose their own at first sign-in.
- Admins can reset passwords, change roles and deactivate accounts. Deactivating signs the person out
  immediately. There must always be at least one active admin, and admins can't change their own access.
- Passwords are stored as salted PBKDF2 hashes. Five failed sign-ins lock that email for 15 minutes.
- Every driver change is logged with the staff member who made it; account changes have their own log.

## Drivers and vehicles

Both registers work the same way. A record appears on its public register only if its status is
**Active** and it is in date. Setting **Suspended** or **Revoked** hides it immediately.

- **Drivers:** name, licence number, licence type, licence expiry, contact details.
- **Vehicles:** registration, council plate number, make, model, colour, proprietor, licence type,
  licence expiry and test certificate expiry. A vehicle is hidden if *either* date has passed.
  The proprietor's name is shown to staff only, not on the public register.

## Importing an existing register

Admins can bulk-import drivers or vehicles from a spreadsheet saved as CSV
(**Import spreadsheet** on either register page, or `/admin/drivers/import` and `/admin/vehicles/import`).

- Column names are matched automatically ("Badge No", "Surname" + "Forename", "VRM", "MOT due"…) and can be
  corrected before importing. Title rows above the headers and blank rows are ignored.
- UK dates in most formats are understood, as are Excel date numbers and short licence types ("PH", "HC").
- A preview shows what each row will do: new, update, already up to date, or a problem with the reason.
  Nothing is saved until you confirm, and existing records are only updated if you tick the box.
- Rows with problems are skipped; download them with the reason added, fix them and import again.
  Re-importing the same file never creates duplicates.
- Each imported or updated record is recorded in the activity log. Up to 5,000 rows per file.

The column-matching and value-cleaning rules live in `importer.py`.

Delete `drivers.db` to reset to the sample data (this also removes all staff accounts).
Existing databases are upgraded automatically on start-up.
