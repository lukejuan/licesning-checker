"""Turn messy spreadsheet exports (CSV) into clean register records.

Councils' existing registers are usually hand-built spreadsheets: title rows above
the headers, inconsistent column names, dates in any format, "PH"/"Hackney" for
licence types. This module works out what each column means and normalises the
values; app.py does the validation against the database and the saving.
"""
import csv
import datetime as dt
import io
import re

MAX_ROWS = 5000
MAX_BYTES = 5_000_000

# Cells people use to mean "nothing here".
EMPTY_VALUES = {"", "-", "--", "n/a", "na", "none", "null", "nil", "tbc", "?"}

LICENCE_TYPE_FIELD = ("licence_type", "Licence type",
                      ["licence type", "license type", "type", "category", "licence category",
                       "licence class", "hc or ph", "hc ph"])
STATUS_FIELD = ("status", "Status", ["status", "licence status", "license status", "state"])
NOTES_FIELD = ("notes", "Notes", ["notes", "note", "comments", "comment", "remarks"])

# (field, label shown in the column picker, header names that mean this field)
IMPORT_FIELDS = {
    "drivers": [
        ("full_name", "Full name",
         ["name", "full name", "driver", "driver name", "drivers name", "licence holder",
          "licensee", "licensee name"]),
        ("first_name", "First name (combined with surname)",
         ["first name", "forename", "forenames", "given name", "first names", "christian name"]),
        ("last_name", "Surname (combined with first name)",
         ["surname", "last name", "family name"]),
        ("licence_number", "Licence / badge number",
         ["licence number", "licence no", "license number", "license no", "badge", "badge number",
          "badge no", "licence", "license", "licence ref", "badge ref", "driver licence number",
          "drivers licence number", "licence id", "reference", "ref"]),
        LICENCE_TYPE_FIELD,
        ("expiry_date", "Licence expiry",
         ["expiry", "expiry date", "licence expiry", "license expiry", "expires", "licence expires",
          "expiry of licence", "valid until", "valid to", "renewal date", "renewal due",
          "licence expiry date", "date of expiry", "end date"]),
        STATUS_FIELD,
        ("phone", "Phone",
         ["phone", "telephone", "tel", "mobile", "mobile number", "phone number", "contact number",
          "tel no"]),
        ("email", "Email", ["email", "e mail", "email address"]),
        NOTES_FIELD,
    ],
    "vehicles": [
        ("registration", "Registration",
         ["registration", "reg", "reg no", "reg number", "registration number", "vrm",
          "vehicle registration", "vehicle reg", "registration mark", "index"]),
        ("plate_number", "Council plate number",
         ["plate", "plate no", "plate number", "licence number", "licence no", "license number",
          "vehicle licence number", "vehicle licence", "plate ref", "licence plate"]),
        ("make_model", "Make and model (in one column)",
         ["vehicle", "make and model", "make model", "vehicle make and model", "description",
          "vehicle description"]),
        ("make", "Make", ["make", "manufacturer", "vehicle make"]),
        ("model", "Model", ["model", "vehicle model"]),
        ("colour", "Colour", ["colour", "color", "vehicle colour"]),
        ("proprietor_name", "Proprietor",
         ["proprietor", "proprietor name", "owner", "owner name", "keeper", "licence holder",
          "licensee", "vehicle proprietor", "registered keeper"]),
        LICENCE_TYPE_FIELD,
        ("licence_expiry", "Licence expiry",
         ["licence expiry", "license expiry", "expiry", "expiry date", "plate expiry",
          "licence expires", "vehicle licence expiry", "valid until", "renewal date",
          "licence expiry date", "date of expiry"]),
        ("test_expiry", "Test certificate expiry",
         ["test expiry", "test certificate expiry", "test date", "test due", "mot", "mot expiry",
          "mot due", "mot date", "compliance test", "compliance test expiry", "test cert",
          "test certificate", "vehicle test expiry", "test cert expiry", "next test due"]),
        STATUS_FIELD,
        NOTES_FIELD,
    ],
}

# Fallback when a header isn't an exact match: first keyword found wins.
KEYWORD_RULES = {
    "drivers": [("badge", "licence_number"), ("surname", "last_name"), ("forename", "first_name"),
                ("expir", "expiry_date"), ("renewal", "expiry_date"), ("mobile", "phone"),
                ("phone", "phone"), ("mail", "email"), ("type", "licence_type"),
                ("status", "status"), ("note", "notes"), ("name", "full_name")],
    "vehicles": [("mot", "test_expiry"), ("test", "test_expiry"), ("plate", "plate_number"),
                 ("vrm", "registration"), ("reg", "registration"), ("proprietor", "proprietor_name"),
                 ("owner", "proprietor_name"), ("keeper", "proprietor_name"),
                 ("expir", "licence_expiry"), ("renewal", "licence_expiry"),
                 ("colour", "colour"), ("color", "colour"), ("make", "make"), ("model", "model"),
                 ("type", "licence_type"), ("status", "status"), ("note", "notes")],
}

TEMPLATE_ROWS = {
    "drivers": [["Full name", "Licence number", "Licence type", "Licence expiry", "Status",
                 "Phone", "Email", "Notes"],
                ["Jane Smith", "PH-12345", "Private Hire", "31/03/2027", "Active",
                 "07700 900123", "jane@example.com", ""]],
    "vehicles": [["Registration", "Plate number", "Make", "Model", "Colour", "Proprietor",
                  "Licence type", "Licence expiry", "Test certificate expiry", "Status", "Notes"],
                 ["AB12 CDE", "PHV-0123", "Toyota", "Prius", "Silver", "Jane Smith",
                  "Private Hire", "31/03/2027", "30/09/2026", "Active", ""]],
}

LICENCE_TYPES = {
    "Hackney Carriage": ["hc", "hcd", "hcv", "hackney", "hackneycarriage", "hackneycarriagedriver",
                         "hackneycarriagevehicle", "hackneycab", "taxi", "blackcab"],
    "Private Hire": ["ph", "phd", "phv", "phdriver", "private", "privatehire", "privatehiredriver",
                     "privatehirevehicle", "minicab"],
    "Dual": ["dual", "combined", "joint", "both", "hcph", "hcandph", "hcph", "dualdriver",
             "hackneyandprivatehire", "hackneycarriageandprivatehire"],
}

STATUS_WORDS = {
    "active": ["active", "current", "valid", "licensed", "licenced", "live", "granted", "issued",
               "ok", "yes", "y", "renewed"],
    "suspended": ["suspended", "susp", "suspension", "onhold", "hold"],
    "revoked": ["revoked", "revoke", "revocation", "refused", "surrendered", "cancelled",
                "canceled", "withdrawn"],
    # The expiry date already hides these from the public register.
    "_expired": ["expired", "lapsed", "outofdate"],
}

MULTI_WORD_MAKES = ["mercedes benz", "mercedes-benz", "land rover", "alfa romeo", "aston martin",
                    "rolls royce", "london taxi company", "london ev company"]

DATE_FORMATS = ["%d %b %Y", "%d %B %Y", "%d %b %y", "%d %B %y", "%b %d %Y", "%B %d %Y",
                "%d-%b-%Y", "%d-%b-%y", "%d-%B-%Y", "%Y/%m/%d"]


# ---------------------------------------------------------------- reading the file

def read_rows(text):
    """Parse CSV text (comma, semicolon or tab separated) into a list of rows."""
    text = text.lstrip("﻿")
    sample = text[:5000]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    # Blank rows are kept so row numbers match what people see in their spreadsheet.
    return [[cell.strip() for cell in row] for row in csv.reader(io.StringIO(text), dialect)]


def _norm_header(value):
    value = str(value or "").lower().replace("&", " and ")
    value = re.sub(r"[^a-z0-9]+", " ", value)
    return re.sub(r"\s+", " ", value).strip()


def _synonym_lookup(register):
    return {_norm_header(s): field
            for field, _, synonyms in IMPORT_FIELDS[register] for s in synonyms}


def find_header_row(rows, register):
    """Spreadsheets often have a title or blank rows above the real headers."""
    lookup = _synonym_lookup(register)
    best, best_score = 0, 0
    for i, row in enumerate(rows[:15]):
        score = sum(1 for cell in row if _norm_header(cell) in lookup)
        if score >= 3:
            return i
        if score > best_score:
            best, best_score = i, score
    return best


def auto_map(headers, register):
    """Guess which column holds which field. Returns {field: column index}."""
    lookup = _synonym_lookup(register)
    mapping = {}
    for i, header in enumerate(headers):
        field = lookup.get(_norm_header(header))
        if field and field not in mapping:
            mapping[field] = i
    used = set(mapping.values())
    for i, header in enumerate(headers):
        if i in used:
            continue
        h = _norm_header(header).replace(" ", "")
        for keyword, field in KEYWORD_RULES[register]:
            if field == "full_name" and ("first_name" in mapping or "last_name" in mapping):
                continue
            if keyword in h and field not in mapping:
                mapping[field] = i
                used.add(i)
                break
    # A combined make/model column is only needed when there aren't separate ones.
    if "make" in mapping and "model" in mapping:
        mapping.pop("make_model", None)
    # Separate first name / surname columns only matter without a full-name column.
    if "full_name" in mapping:
        mapping.pop("first_name", None)
        mapping.pop("last_name", None)
    return mapping


# ---------------------------------------------------------------- cleaning values

def is_empty(value):
    return str(value or "").strip().lower() in EMPTY_VALUES


def parse_date(value):
    """Return (iso_date, warning). Raises ValueError if it can't be read.
    Day-first (UK) unless that's impossible and month-first isn't."""
    s = str(value).strip()
    s = re.sub(r"(\d)(st|nd|rd|th)\b", r"\1", s, flags=re.I).replace(",", " ")
    s = re.sub(r"\s+", " ", s).strip()

    m = re.fullmatch(r"(\d{4})-(\d{1,2})-(\d{1,2})(?:[ T].*)?", s)
    if m:
        return dt.date(int(m[1]), int(m[2]), int(m[3])).isoformat(), None

    m = re.fullmatch(r"(\d{1,2})[/.\-](\d{1,2})[/.\-](\d{2}|\d{4})(?: .*)?", s)
    if m:
        a, b, year = int(m[1]), int(m[2]), int(m[3])
        if year < 100:
            year += 2000 if year < 70 else 1900
        if b > 12 and a <= 12:  # clearly month-first, e.g. 03/25/2027
            return dt.date(year, a, b).isoformat(), f"Read '{value}' as month/day/year"
        return dt.date(year, b, a).isoformat(), None

    if re.fullmatch(r"\d{5}(\.\d+)?", s):  # Excel serial date number
        days = int(float(s))
        if 20000 < days < 80000:
            return (dt.date(1899, 12, 30) + dt.timedelta(days=days)).isoformat(), None

    for fmt in DATE_FORMATS:
        try:
            return dt.datetime.strptime(s, fmt).date().isoformat(), None
        except ValueError:
            pass
    raise ValueError


def parse_licence_type(value, allowed):
    key = re.sub(r"[^a-z]", "", str(value).lower())
    for licence_type, words in LICENCE_TYPES.items():
        if key in words and licence_type in allowed:
            return licence_type
    for licence_type in ("Dual", "Hackney Carriage", "Private Hire"):
        stem = {"Dual": "dual", "Hackney Carriage": "hackney", "Private Hire": "private"}[licence_type]
        if stem in key and licence_type in allowed:
            return licence_type
    return None


def parse_status(value):
    key = re.sub(r"[^a-z]", "", str(value).lower())
    for status, words in STATUS_WORDS.items():
        if key in words:
            return status
    return None


def split_make_model(value):
    text = re.sub(r"\s+", " ", str(value).strip())
    for make in MULTI_WORD_MAKES:
        if text.lower().startswith(make + " "):
            return text[:len(make)], text[len(make) + 1:]
    make, _, model = text.partition(" ")
    return make, model


def tidy(value):
    return re.sub(r"\s+", " ", str(value or "")).strip()


def build_values(register, row, mapping, licence_types, default_licence_type=None):
    """Turn one spreadsheet row into register values.
    Returns (values, errors, warnings); empty cells are left out of values."""
    def cell(field):
        i = mapping.get(field)
        if i is None or i >= len(row) or is_empty(row[i]):
            return ""
        return tidy(row[i])

    values, errors, warnings = {}, [], []
    for field, _, _ in IMPORT_FIELDS[register]:
        if field in ("first_name", "last_name", "make_model"):
            continue
        if cell(field):
            values[field] = cell(field)

    if register == "drivers" and "full_name" not in values:
        name = tidy(f"{cell('first_name')} {cell('last_name')}")
        if name:
            values["full_name"] = name
    if register == "vehicles" and cell("make_model"):
        make, model = split_make_model(cell("make_model"))
        values.setdefault("make", make)
        if model:
            values.setdefault("model", model)

    for field in ("expiry_date", "licence_expiry", "test_expiry"):
        if field in values:
            raw = values[field]
            try:
                values[field], warning = parse_date(raw)
                if warning:
                    warnings.append(warning)
            except ValueError:
                errors.append(f"Can't read the date '{raw}'")
                del values[field]

    if "licence_type" in values:
        raw = values["licence_type"]
        parsed = parse_licence_type(raw, licence_types)
        if parsed:
            values["licence_type"] = parsed
        else:
            errors.append(f"Unknown licence type '{raw}'")
            del values["licence_type"]
    elif default_licence_type in licence_types:
        values["licence_type"] = default_licence_type

    if "status" in values:
        raw = values["status"]
        parsed = parse_status(raw)
        if parsed == "_expired":
            values["status"] = "active"
            warnings.append(f"Status '{raw}' imported as Active; the expiry date keeps it off"
                            " the public register")
        elif parsed:
            values["status"] = parsed
        else:
            errors.append(f"Unknown status '{raw}' (use Active, Suspended or Revoked)")
            del values["status"]

    if "email" in values and "@" not in values["email"]:
        errors.append(f"'{values['email']}' doesn't look like an email address")

    return values, errors, warnings


def template_csv(register):
    out = io.StringIO()
    csv.writer(out).writerows(TEMPLATE_ROWS[register])
    return out.getvalue()
