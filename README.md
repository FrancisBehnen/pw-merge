# Password Manager Merger

A Python script for securely merging passwords from different password managers.

## Security First

This project handles sensitive password data. Multiple security layers are in place:

### 1. Git Protection (.gitignore)
The `.gitignore` file prevents password files from being accidentally committed to version control. Protected file types include:
- Password manager exports (.csv, .json, .xml, .1pif, .kdbx, etc.)
- Input/output directories
- Test data directories
- Environment files

### 2. AI Assistant Protection (.claudeignore)
The `.claudeignore` file prevents AI assistants (Claude Code, etc.) from reading password files, ensuring your passwords are never sent to AI services.

### 3. Security Best Practices
- **Never commit password files** - All common password file formats are blocked
- **Keep password files local** - Store them outside the repository when possible
- **Delete after use** - Remove password exports immediately after merging
- **Review before commit** - Always run `git status` before committing
- **Test with dummy data** - Use fake passwords for testing

## Requirements

- Python 3.6 or higher
- No external dependencies (uses only Python standard library)

## Setup

1. Clone or download this repository
2. Ensure Python 3 is installed: `python3 --version`
3. Make the script executable (optional): `chmod +x merge_passwords.py`

## Supported Password Managers

This tool merges password exports from:

1. **macOS Keychain / Passwords app**
   - Export format: CSV with headers `Title,URL,Username,Password,Notes,OTPAuth`
   - Used for deduplication against existing entries

2. **Dashlane**
   - Export credentials as CSV
   - Expected headers: `username,username2,username3,title,password,note,url,category,otpUrl`

3. **LastPass**
   - Export logins and secure notes as CSV
   - Expected headers: `url,username,password,totp,extra,name,grouping,fav`
   - Secure notes are detected by URL: `http://sn`

## How to Export Your Passwords

### macOS Keychain / Passwords App
1. Open Passwords app (macOS Sonoma+) or Keychain Access
2. Select passwords to export
3. File > Export... > Save as CSV
4. Store in a secure location outside this repository

### Dashlane
1. Open Dashlane desktop app
2. Go to File > Export > Unsecured archive (.csv)
3. Select "Credentials" to export
4. Save to secure location

### LastPass
1. Log in to LastPass web vault
2. Go to Advanced Options > Export
3. Save the exported CSV file
4. Store in secure location

## Usage

### Basic Usage

Store your exported CSV files in a secure directory OUTSIDE this repository (e.g., `~/password-exports/`).

```bash
python3 merge_passwords.py \
  --apple-csv ~/password-exports/keychain.csv \
  --dashlane-csv ~/password-exports/dashlane.csv \
  --lastpass-csv ~/password-exports/lastpass.csv \
  --output ~/password-exports/merged.csv \
  --rejected ~/password-exports/rejected.csv
```

### Command Line Options

```
Required:
  --output PATH          Output path for merged CSV (Apple format)
  --rejected PATH        Output path for rejected/uninterpretable entries

Input Files (at least one of Dashlane/LastPass required):
  --apple-csv PATH       Existing Apple/Keychain CSV (for deduplication)
  --dashlane-csv PATH    Dashlane credentials export CSV
  --lastpass-csv PATH    LastPass export CSV

Options:
  --include-existing     Include existing Apple records in output
                         (default: only use for deduplication)
  --case-insensitive-usernames
                         Treat usernames as case-insensitive for deduplication
  --delimiter CHAR       CSV delimiter (default: comma)
  --encoding ENC         CSV encoding (default: utf-8)
  --verbose, -v          Enable detailed logging
  --interactive, -i      Interactive mode: pause on conflicts to review and decide
```

### Example Workflows

#### Merge Dashlane and LastPass into Apple format
```bash
python3 merge_passwords.py \
  --dashlane-csv dashlane.csv \
  --lastpass-csv lastpass.csv \
  --output merged.csv \
  --rejected rejected.csv \
  --verbose
```

#### Merge with deduplication against existing Keychain
```bash
python3 merge_passwords.py \
  --apple-csv existing_keychain.csv \
  --dashlane-csv dashlane.csv \
  --output merged.csv \
  --rejected rejected.csv
```

#### Create complete merged export (including existing)
```bash
python3 merge_passwords.py \
  --apple-csv keychain.csv \
  --dashlane-csv dashlane.csv \
  --lastpass-csv lastpass.csv \
  --output complete_merged.csv \
  --rejected rejected.csv \
  --include-existing
```

#### Interactive mode for reviewing conflicts
```bash
python3 merge_passwords.py \
  --apple-csv keychain.csv \
  --dashlane-csv dashlane.csv \
  --lastpass-csv lastpass.csv \
  --output merged.csv \
  --rejected rejected.csv \
  --interactive
```

**Recommended**: Use interactive mode (`--interactive` or `-i`) when merging for the first time. The script will:
- Pause when it detects a password conflict
- Show both passwords side-by-side with character-by-character comparison
- Highlight any hidden differences (whitespace, special characters)
- Let you choose to skip, add anyway, or keep existing

This helps identify:
- False positives (passwords that look identical but aren't)
- Actual password conflicts that need your attention
- Hidden encoding or whitespace issues

## Understanding the Output

### Merged CSV (`merged.csv`)
- Contains all successfully merged passwords in Apple/Keychain format
- Ready to import into macOS Passwords/Keychain
- Headers: `Title,URL,Username,Password,Notes,OTPAuth`
- Excludes exact duplicates and conflicts

### Rejected CSV (`rejected.csv`)
- Contains entries that need manual review
- Includes rejection reason for each entry
- Common rejection reasons:
  - `missing password`: Entry has no password field
  - `no title, URL, or username`: Cannot identify the entry
  - `conflict: same site + username but different password`: Detected password mismatch
  - `secure note with no name or content`: Empty secure note

**Important**: Always review the rejected file before importing. Conflicts may indicate:
- Updated passwords in one manager
- Duplicate accounts with different passwords
- Data that needs manual reconciliation

## Deduplication and Conflict Detection

### Exact Duplicate Detection
An entry is considered an exact duplicate if all of these match (after normalization):
- URL (normalized hostname and path, case-insensitive)
- Username (trimmed, optionally case-insensitive)
- Password (exact match)

Exact duplicates are automatically skipped.

### Conflict Detection
A conflict is detected when:
- URL hostname matches (e.g., `www.amazon.com` and `amazon.com` are the same)
- Username matches
- Password differs

**Conflicts are automatically rejected** and sent to the rejected file for manual review. This prevents accidentally importing conflicting passwords.

## Testing

Run the included tests:

```bash
# Run unit tests
python3 tests/test_basic.py

# Test with sample fixtures
python3 merge_passwords.py \
  --apple-csv tests/fixtures/apple_existing.csv \
  --dashlane-csv tests/fixtures/dashlane_export.csv \
  --lastpass-csv tests/fixtures/lastpass_export.csv \
  --output tests/test_merged.csv \
  --rejected tests/test_rejected.csv \
  --verbose
```

## Finding Missing Passwords After Import

If macOS Passwords reports that some passwords couldn't be imported, use the `find_missing_passwords.py` script to identify which ones are missing:

```bash
python3 find_missing_passwords.py \
  --apple-csv ~/password-exports/keychain_after_import.csv \
  --dashlane-csv ~/password-exports/dashlane.csv \
  --lastpass-csv ~/password-exports/lastpass.csv \
  --output ~/password-exports/missing.csv
```

### How it works:
1. Export your Keychain/Passwords AFTER the import attempt
2. Compare it against the original LastPass/Dashlane exports
3. Identify which passwords are in the source files but NOT in Keychain
4. Output missing passwords to a CSV file for manual review

This helps you understand:
- Which 49 (or however many) passwords failed to import
- Whether they're from LastPass or Dashlane
- What the actual credentials are so you can manually add them

### Command Line Options

```
Required:
  --apple-csv PATH       Apple Keychain CSV export AFTER import
  --output PATH          Output path for missing passwords CSV

Input Files (at least one required):
  --dashlane-csv PATH    Original Dashlane export
  --lastpass-csv PATH    Original LastPass export

Options:
  --case-insensitive-usernames
                         Treat usernames as case-insensitive when matching
  --delimiter CHAR       CSV delimiter (default: comma)
  --encoding ENC         CSV encoding (default: utf-8)
```

### Example Workflow

1. Import the merged passwords into macOS Passwords
2. Note how many failed to import (e.g., "49 passwords couldn't be imported")
3. Export your Keychain/Passwords to a new CSV file
4. Run the find_missing_passwords.py script to identify what's missing
5. Review the `missing.csv` file and manually add those passwords

## Import into macOS Passwords

1. Review both output files:
   - Check `merged.csv` for correctness
   - Review `rejected.csv` and manually handle conflicts

2. Import into Passwords app:
   - Open Passwords app (macOS Sonoma+)
   - File > Import Passwords...
   - Select `merged.csv`
   - Review and confirm import

3. Verify imported passwords work correctly

4. If some passwords failed to import, use `find_missing_passwords.py` (see above)

5. **SECURELY DELETE ALL CSV FILES**:
   ```bash
   rm ~/password-exports/*.csv
   ```

## Security Checklist

Before using this tool:
- [ ] Ensure `.gitignore` and `.claudeignore` are in place
- [ ] Never share this repository while password files are present
- [ ] Use strong encryption for any backups
- [ ] Delete password export files after merging
- [ ] Verify no sensitive data in git history: `git log --all --full-history --stat`

## License

(To be defined)
