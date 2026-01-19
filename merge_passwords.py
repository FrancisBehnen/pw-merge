#!/usr/bin/env python3
"""
Password Manager Merger
Merges password exports from macOS Keychain, Dashlane, and LastPass into a single
Apple-compatible CSV format.

Security: This script handles plaintext passwords. Ensure input/output files are
stored securely and deleted after use.
"""

import argparse
import csv
import sys
from pathlib import Path
from typing import List, Dict, Optional, Set, Tuple
from urllib.parse import urlparse
import logging
import tty
import termios


# Apple Keychain CSV format (target format)
APPLE_HEADERS = ['Title', 'URL', 'Username', 'Password', 'Notes', 'OTPAuth']

# Dashlane CSV format
DASHLANE_HEADERS = ['username', 'username2', 'username3', 'title', 'password', 'note', 'url', 'category', 'otpUrl']

# LastPass CSV format
LASTPASS_HEADERS = ['url', 'username', 'password', 'totp', 'extra', 'name', 'grouping', 'fav']


class PasswordRecord:
    """Represents a normalized password record in Apple format."""

    def __init__(self, title: str = '', url: str = '', username: str = '',
                 password: str = '', notes: str = '', otpauth: str = '',
                 source: str = ''):
        self.title = title
        self.url = url
        self.username = username
        self.password = password
        self.notes = notes
        self.otpauth = otpauth
        self.source = source

    def to_dict(self) -> Dict[str, str]:
        """Convert to dictionary for CSV writing."""
        return {
            'Title': self.title,
            'URL': self.url,
            'Username': self.username,
            'Password': self.password,
            'Notes': self.notes,
            'OTPAuth': self.otpauth
        }

    def dedup_key(self, case_insensitive_username: bool = False) -> Tuple[str, str, str]:
        """Generate a key for deduplication (hostname or title, username, password).

        For website passwords: uses hostname (not full URL, since Keychain strips URLs to base domain)
        For app passwords (no URL): uses title to differentiate between different apps

        Examples:
        - https://www.linkedin.com/login?redirect=... → linkedin.com
        - https://linkedin.com/ → linkedin.com
        Both match as the same site.
        """
        hostname = extract_hostname(self.url)
        # If no hostname (empty URL), use title instead to differentiate app passwords
        identifier = hostname if hostname else self.title.strip()
        username = self.username.strip()
        if case_insensitive_username:
            username = username.lower()
        # Strip password for comparison (whitespace doesn't matter for matching)
        password = self.password.strip()
        return (identifier, username, password)

    def site_username_key(self, case_insensitive_username: bool = False) -> Tuple[str, str]:
        """Generate a key for conflict detection (normalized hostname or title, username).

        For website passwords: uses hostname
        For app passwords (no URL): uses title to differentiate between different apps
        """
        hostname = extract_hostname(self.url)
        # If no hostname (empty URL), use title instead to differentiate app passwords
        identifier = hostname if hostname else self.title.strip()
        username = self.username.strip()
        if case_insensitive_username:
            username = username.lower()
        return (identifier, username)


def normalize_url(url: str) -> str:
    """Normalize URL for comparison (lowercase host, keep path)."""
    if not url:
        return ''

    url = url.strip()

    # Treat bare scheme URLs (http://, https://, etc.) as empty - these are used for app passwords
    if url.lower() in ('http://', 'https://', 'ftp://'):
        return ''

    # Add scheme if missing and looks like a domain
    if url and not url.startswith(('http://', 'https://', 'ftp://')):
        if '.' in url:
            url = 'https://' + url

    try:
        parsed = urlparse(url)
        # Normalize: lowercase host, keep path
        normalized_host = parsed.hostname.lower() if parsed.hostname else ''
        normalized_path = parsed.path

        # Reconstruct with normalized host
        if normalized_host:
            return f"{parsed.scheme}://{normalized_host}{normalized_path}"
    except:
        pass

    return url.lower()


def extract_hostname(url: str) -> str:
    """Extract and normalize hostname from URL."""
    if not url:
        return ''

    url = url.strip()

    # Treat bare scheme URLs (http://, https://, etc.) as empty - these are used for app passwords
    if url.lower() in ('http://', 'https://', 'ftp://'):
        return ''

    # Add scheme if missing
    if url and not url.startswith(('http://', 'https://', 'ftp://')):
        if '.' in url:
            url = 'https://' + url

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if hostname:
            # Remove www. prefix for broader matching
            hostname = hostname.lower()
            if hostname.startswith('www.'):
                hostname = hostname[4:]
            return hostname
    except:
        pass

    return url.lower()


def read_csv_file(filepath: Path, expected_headers: List[str],
                  delimiter: str = ',', encoding: str = 'utf-8') -> List[Dict[str, str]]:
    """Read CSV file and validate headers."""
    if not filepath.exists():
        raise FileNotFoundError(f"File not found: {filepath}")

    with open(filepath, 'r', encoding=encoding, newline='') as f:
        reader = csv.DictReader(f, delimiter=delimiter)

        # Validate headers
        if reader.fieldnames is None:
            raise ValueError(f"No headers found in {filepath}")

        actual_headers = list(reader.fieldnames)
        if actual_headers != expected_headers:
            raise ValueError(
                f"Header mismatch in {filepath}\n"
                f"Expected: {expected_headers}\n"
                f"Got: {actual_headers}"
            )

        # Read all rows
        rows = []
        for row in reader:
            rows.append(row)

        logging.info(f"Read {len(rows)} rows from {filepath.name}")
        return rows


def parse_apple_title(title: str) -> str:
    """Parse Apple Keychain title format: 'hostname (username)' -> 'hostname'

    Apple Keychain exports titles in the format: hostname (username)
    If no username, it shows: hostname ()

    This function extracts just the hostname/title part.
    """
    if not title:
        return ''

    # Look for the pattern " (" which separates hostname from username
    if ' (' in title:
        # Extract everything before " ("
        return title.split(' (')[0].strip()

    # If no pattern found, return as-is (backwards compatibility)
    return title.strip()


def map_apple_record(row: Dict[str, str]) -> PasswordRecord:
    """Map Apple CSV row to PasswordRecord (already in target format).

    Apple Keychain exports have Title in format: 'hostname (username)'
    We extract just the hostname part for the title.
    """
    raw_title = row.get('Title', '').strip()
    title = parse_apple_title(raw_title)

    return PasswordRecord(
        title=title,
        url=row.get('URL', '').strip(),
        username=row.get('Username', '').strip(),
        password=row.get('Password', '').strip(),
        notes=row.get('Notes', '').strip(),
        otpauth=row.get('OTPAuth', '').strip(),
        source='apple'
    )


def map_dashlane_record(row: Dict[str, str]) -> Tuple[Optional[PasswordRecord], Optional[str]]:
    """
    Map Dashlane CSV row to PasswordRecord.
    Returns (record, rejection_reason). If rejected, record is None.
    """
    # Extract fields
    title = row.get('title', '').strip()
    url = row.get('url', '').strip()
    username = row.get('username', '').strip()
    username2 = row.get('username2', '').strip()
    username3 = row.get('username3', '').strip()
    password = row.get('password', '').strip()
    note = row.get('note', '').strip()
    category = row.get('category', '').strip()
    otp_url = row.get('otpUrl', '').strip()

    # Validation: must have password and at least one of title/URL/username
    if not password:
        return None, "missing password"
    if not any([title, url, username]):
        return None, "no title, URL, or username"

    # Title: prefer title, fallback to URL host or username
    if not title:
        if url:
            title = extract_hostname(url) or url
        elif username:
            title = username

    # Username: prefer username, fallback to username2, then username3
    final_username = username or username2 or username3

    # Notes: combine note, additional usernames, category
    notes_parts = []
    if note:
        notes_parts.append(note)

    additional_usernames = []
    if username2 and username2 != final_username:
        additional_usernames.append(username2)
    if username3 and username3 != final_username:
        additional_usernames.append(username3)

    if additional_usernames:
        notes_parts.append(f"Additional usernames: {', '.join(additional_usernames)}")

    if category:
        notes_parts.append(f"Category: {category}")

    final_notes = '\n'.join(notes_parts)

    # OTPAuth: check if otpUrl is an otpauth:// URL
    otpauth = ''
    if otp_url:
        if otp_url.startswith('otpauth://'):
            otpauth = otp_url
        else:
            # Not a proper otpauth URL, add to notes
            final_notes += f"\nOTP: {otp_url}" if final_notes else f"OTP: {otp_url}"

    record = PasswordRecord(
        title=title,
        url=url,
        username=final_username,
        password=password,
        notes=final_notes,
        otpauth=otpauth,
        source='dashlane'
    )

    return record, None


def map_lastpass_record(row: Dict[str, str]) -> Tuple[Optional[PasswordRecord], Optional[str]]:
    """
    Map LastPass CSV row to PasswordRecord.
    Handles both logins and secure notes.
    Returns (record, rejection_reason). If rejected, record is None.
    """
    url = row.get('url', '').strip()
    username = row.get('username', '').strip()
    password = row.get('password', '').strip()
    totp = row.get('totp', '').strip()
    extra = row.get('extra', '').strip()
    name = row.get('name', '').strip()
    grouping = row.get('grouping', '').strip()
    fav = row.get('fav', '').strip()

    # Detect secure notes
    is_secure_note = url == 'http://sn'

    if is_secure_note:
        # Secure note handling
        if not name and not extra:
            return None, "secure note with no name or content"

        # Build notes from extra, grouping, fav
        notes_parts = []
        if extra:
            notes_parts.append(extra)
        if grouping:
            notes_parts.append(f"Group: {grouping}")
        if fav:
            notes_parts.append(f"Favorite: {fav}")

        final_notes = '\n'.join(notes_parts)

        record = PasswordRecord(
            title=name or 'Untitled Note',
            url='',
            username='',
            password='',
            notes=final_notes,
            otpauth='',
            source='lastpass-note'
        )
        return record, None

    else:
        # Login handling
        if not password:
            return None, "missing password"

        # Title: use name, fallback to URL host
        title = name.strip() if name else ''
        if not title and url:
            title = extract_hostname(url) or url
        if not title:
            title = 'Untitled'

        # Notes: combine extra, grouping, fav
        notes_parts = []
        if extra:
            notes_parts.append(extra)
        if grouping:
            notes_parts.append(f"Group: {grouping}")
        if fav:
            notes_parts.append(f"Favorite: {fav}")

        final_notes = '\n'.join(notes_parts)

        # OTPAuth: check if totp is an otpauth:// URL
        otpauth = ''
        if totp:
            if totp.startswith('otpauth://'):
                otpauth = totp
            else:
                # Not a proper otpauth URL, add to notes
                final_notes += f"\nTOTP: {totp}" if final_notes else f"TOTP: {totp}"

        record = PasswordRecord(
            title=title,
            url=url,
            username=username,
            password=password,
            notes=final_notes,
            otpauth=otpauth,
            source='lastpass'
        )
        return record, None


def getch() -> str:
    """Read a single character from stdin without requiring Enter."""
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(sys.stdin.fileno())
        ch = sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return ch


def compare_passwords_interactive(existing_record: PasswordRecord,
                                  new_record: PasswordRecord) -> str:
    """
    Interactively compare two passwords and let user decide what to do.
    Returns: 'skip', 'add', or 'replace'
    """
    print("\n" + "="*80)
    print("PASSWORD CONFLICT DETECTED")
    print("="*80)
    print(f"\nEntry: {new_record.title}")
    print(f"URL: {new_record.url}")
    print("\n" + "-"*80)

    # Show both usernames and passwords
    print(f"\nEXISTING entry (from {existing_record.source}):")
    print(f"  Username: {existing_record.username}")
    print(f"  Password: {existing_record.password}")
    print(f"  Length: {len(existing_record.password)}")
    print(f"  Repr: {repr(existing_record.password)}")

    print(f"\nNEW entry (from {new_record.source}):")
    print(f"  Username: {new_record.username}")
    print(f"  Password: {new_record.password}")
    print(f"  Length: {len(new_record.password)}")
    print(f"  Repr: {repr(new_record.password)}")

    # Character-by-character comparison
    if existing_record.password != new_record.password:
        print("\nCHARACTER-BY-CHARACTER COMPARISON:")
        max_len = max(len(existing_record.password), len(new_record.password))

        print("\n  Position  | Existing | New     | Match")
        print("  " + "-"*45)

        for i in range(max_len):
            existing_char = existing_record.password[i] if i < len(existing_record.password) else '(none)'
            new_char = new_record.password[i] if i < len(new_record.password) else '(none)'

            # Get repr for special characters
            if i < len(existing_record.password):
                existing_repr = repr(existing_record.password[i])[1:-1]  # Remove quotes
            else:
                existing_repr = ''

            if i < len(new_record.password):
                new_repr = repr(new_record.password[i])[1:-1]
            else:
                new_repr = ''

            match = "✓" if existing_char == new_char else "✗ DIFF"

            print(f"  {i:8d}  | {existing_repr:8s} | {new_repr:8s} | {match}")

            if i >= 10 and max_len > 15:
                print(f"  ... ({max_len - 10} more characters)")
                break
    else:
        print("\n*** PASSWORDS ARE IDENTICAL ***")
        print("This might be a bug in the conflict detection logic!")

    print("\n" + "-"*80)
    print("\nOptions:")
    print("  [s] Skip - Don't include in merged.csv (add to rejected.csv)")
    print("  [a] Add anyway - Include both passwords in merged.csv")
    print("  [k] Keep existing - Same as skip (clearer intent)")
    print("  [q] Quit - Stop processing and exit")

    while True:
        print("\nYour choice [s/a/k/q]: ", end='', flush=True)
        choice = getch().lower()
        print(choice)  # Echo the character

        if choice in ['s']:
            return 'skip'
        elif choice in ['a']:
            return 'add'
        elif choice in ['k']:
            return 'skip'
        elif choice in ['q']:
            print("\nExiting...")
            sys.exit(0)
        else:
            print("Invalid choice. Please press s, a, k, or q.")


def process_records(apple_records: List[PasswordRecord],
                    dashlane_records: List[PasswordRecord],
                    lastpass_records: List[PasswordRecord],
                    case_insensitive_usernames: bool = False,
                    include_existing: bool = False,
                    interactive: bool = False) -> Tuple[List[PasswordRecord], List[Dict]]:
    """
    Process all records: deduplicate and detect conflicts.
    Returns (merged_records, rejected_records).
    """
    merged = []
    rejected = []

    # Build deduplication sets from Apple records
    exact_dupes = set()
    site_username_map = {}  # Maps (site, username) -> password
    site_username_records = {}  # Maps (site, username) -> PasswordRecord for interactive mode

    for record in apple_records:
        dedup_key = record.dedup_key(case_insensitive_usernames)
        exact_dupes.add(dedup_key)

        # Track site+username -> password for conflict detection
        site_key = record.site_username_key(case_insensitive_usernames)
        if site_key not in site_username_map:
            site_username_map[site_key] = set()
            site_username_records[site_key] = []
        # Strip password for comparison (whitespace doesn't matter)
        site_username_map[site_key].add(record.password.strip())
        site_username_records[site_key].append(record)

    # Add existing Apple records if requested
    if include_existing:
        merged.extend(apple_records)
        logging.info(f"Including {len(apple_records)} existing Apple records in output")

    # Process Dashlane and LastPass records
    all_new_records = dashlane_records + lastpass_records

    exact_dupe_count = 0
    conflict_count = 0

    for record in all_new_records:
        dedup_key = record.dedup_key(case_insensitive_usernames)
        site_key = record.site_username_key(case_insensitive_usernames)

        # Check for exact duplicate
        if dedup_key in exact_dupes:
            exact_dupe_count += 1
            continue

        # Check for conflict (same site+username, different password)
        if site_key in site_username_map:
            existing_passwords = site_username_map[site_key]
            # Strip password for comparison (whitespace doesn't matter)
            if record.password.strip() not in existing_passwords:
                # Conflict detected
                conflict_count += 1

                # Get the existing record for comparison
                existing_record = site_username_records[site_key][0]  # Get first existing record

                if interactive:
                    # Interactive mode: let user decide
                    decision = compare_passwords_interactive(existing_record, record)

                    if decision == 'add':
                        # User wants to add this entry anyway
                        merged.append(record)
                        # Update tracking
                        exact_dupes.add(dedup_key)
                        site_username_map[site_key].add(record.password.strip())
                        site_username_records[site_key].append(record)
                        continue
                    elif decision == 'skip':
                        # User wants to skip (same as auto-reject)
                        rejected.append({
                            'source': record.source,
                            'reason': 'conflict: same site + username but different password (user skipped)',
                            'Title': record.title,
                            'URL': record.url,
                            'Username': record.username,
                            'Password': record.password,
                            'Notes': record.notes,
                            'OTPAuth': record.otpauth,
                        })
                        continue
                else:
                    # Non-interactive mode: auto-reject
                    rejected.append({
                        'source': record.source,
                        'reason': 'conflict: same site + username but different password',
                        'Title': record.title,
                        'URL': record.url,
                        'Username': record.username,
                        'Password': record.password,
                        'Notes': record.notes,
                        'OTPAuth': record.otpauth,
                    })
                    continue

        # No duplicate or conflict: add to merged
        merged.append(record)

        # Update tracking sets
        exact_dupes.add(dedup_key)
        if site_key not in site_username_map:
            site_username_map[site_key] = set()
            site_username_records[site_key] = []
        # Strip password for tracking (whitespace doesn't matter)
        site_username_map[site_key].add(record.password.strip())
        site_username_records[site_key].append(record)

    logging.info(f"Skipped {exact_dupe_count} exact duplicates")
    logging.info(f"Detected {conflict_count} conflicts (same site+username, different password)")
    logging.info(f"Merged {len(merged)} total records")

    return merged, rejected


def write_merged_csv(records: List[PasswordRecord], output_path: Path):
    """Write merged records to CSV in Apple format."""
    with open(output_path, 'w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=APPLE_HEADERS)
        writer.writeheader()

        for record in records:
            writer.writerow(record.to_dict())

    logging.info(f"Wrote {len(records)} records to {output_path}")


def write_rejected_csv(rejected: List[Dict], output_path: Path):
    """Write rejected records to CSV for manual review."""
    if not rejected:
        # Write empty file with headers
        with open(output_path, 'w', encoding='utf-8', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['source', 'reason', 'Title', 'URL', 'Username', 'Password', 'Notes'])
            writer.writeheader()
        logging.info(f"No rejected records")
        return

    # Determine all fieldnames from rejected records
    fieldnames = set()
    for record in rejected:
        fieldnames.update(record.keys())

    fieldnames = ['source', 'reason'] + sorted(list(fieldnames - {'source', 'reason'}))

    with open(output_path, 'w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for record in rejected:
            writer.writerow(record)

    logging.info(f"Wrote {len(rejected)} rejected records to {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description='Merge password exports from macOS Keychain, Dashlane, and LastPass',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Security Warning:
  This script handles plaintext passwords. Ensure all input and output files
  are stored securely and deleted after import into your password manager.
  Do not commit these files to version control.
        '''
    )

    parser.add_argument('--apple-csv', type=Path,
                        help='Path to Apple/Keychain CSV export (optional, for deduplication)')
    parser.add_argument('--dashlane-csv', type=Path,
                        help='Path to Dashlane CSV export')
    parser.add_argument('--lastpass-csv', type=Path,
                        help='Path to LastPass CSV export')
    parser.add_argument('--output', type=Path, required=True,
                        help='Output path for merged CSV')
    parser.add_argument('--rejected', type=Path, required=True,
                        help='Output path for rejected/uninterpreted entries')
    parser.add_argument('--include-existing', action='store_true',
                        help='Include existing Apple records in output (not just for dedupe)')
    parser.add_argument('--case-insensitive-usernames', action='store_true',
                        help='Treat usernames as case-insensitive for deduplication')
    parser.add_argument('--delimiter', default=',',
                        help='CSV delimiter (default: comma)')
    parser.add_argument('--encoding', default='utf-8',
                        help='CSV encoding (default: utf-8)')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Enable verbose logging')
    parser.add_argument('--interactive', '-i', action='store_true',
                        help='Interactive mode: pause on conflicts to compare passwords and decide')

    args = parser.parse_args()

    # Setup logging
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format='%(levelname)s: %(message)s'
    )

    # Validate inputs
    if not args.dashlane_csv and not args.lastpass_csv:
        parser.error('At least one of --dashlane-csv or --lastpass-csv must be provided')

    # Interactive mode notice
    if args.interactive:
        print("\n" + "="*80)
        print("INTERACTIVE MODE ENABLED")
        print("="*80)
        print("\nYou will be prompted to review each password conflict.")
        print("The script will pause and show you both passwords side-by-side.")
        print("You can choose to skip, add anyway, or quit.\n")

    # Read input files
    apple_records = []
    if args.apple_csv:
        try:
            apple_rows = read_csv_file(args.apple_csv, APPLE_HEADERS, args.delimiter, args.encoding)
            apple_records = [map_apple_record(row) for row in apple_rows]
        except Exception as e:
            print(f"Error reading Apple CSV: {e}", file=sys.stderr)
            sys.exit(1)

    dashlane_records = []
    dashlane_rejected = []
    if args.dashlane_csv:
        try:
            dashlane_rows = read_csv_file(args.dashlane_csv, DASHLANE_HEADERS, args.delimiter, args.encoding)
            for idx, row in enumerate(dashlane_rows):
                record, reason = map_dashlane_record(row)
                if record:
                    dashlane_records.append(record)
                else:
                    dashlane_rejected.append({
                        'source': 'dashlane',
                        'reason': reason,
                        'row_index': idx,
                        **row
                    })
            logging.info(f"Mapped {len(dashlane_records)} Dashlane records, rejected {len(dashlane_rejected)}")
        except Exception as e:
            print(f"Error reading Dashlane CSV: {e}", file=sys.stderr)
            sys.exit(1)

    lastpass_records = []
    lastpass_rejected = []
    if args.lastpass_csv:
        try:
            lastpass_rows = read_csv_file(args.lastpass_csv, LASTPASS_HEADERS, args.delimiter, args.encoding)
            for idx, row in enumerate(lastpass_rows):
                record, reason = map_lastpass_record(row)
                if record:
                    lastpass_records.append(record)
                else:
                    lastpass_rejected.append({
                        'source': 'lastpass',
                        'reason': reason,
                        'row_index': idx,
                        **row
                    })
            logging.info(f"Mapped {len(lastpass_records)} LastPass records, rejected {len(lastpass_rejected)}")
        except Exception as e:
            print(f"Error reading LastPass CSV: {e}", file=sys.stderr)
            sys.exit(1)

    # Process: deduplicate and detect conflicts
    merged_records, conflict_rejected = process_records(
        apple_records,
        dashlane_records,
        lastpass_records,
        args.case_insensitive_usernames,
        args.include_existing,
        args.interactive
    )

    # Combine all rejected records
    all_rejected = dashlane_rejected + lastpass_rejected + conflict_rejected

    # Write outputs
    try:
        write_merged_csv(merged_records, args.output)
        write_rejected_csv(all_rejected, args.rejected)
    except Exception as e:
        print(f"Error writing output files: {e}", file=sys.stderr)
        sys.exit(1)

    # Summary
    print(f"\nMerge complete!")
    print(f"  Merged records: {len(merged_records)} -> {args.output}")
    print(f"  Rejected records: {len(all_rejected)} -> {args.rejected}")
    print(f"\nNext steps:")
    print(f"  1. Review rejected records in {args.rejected}")
    print(f"  2. Import {args.output} into macOS Passwords/Keychain")
    print(f"  3. Securely delete all CSV files after successful import")

    return 0


if __name__ == '__main__':
    sys.exit(main())
