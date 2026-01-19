#!/usr/bin/env python3
"""
Find Missing Passwords

Identifies passwords from LastPass/Dashlane exports that are NOT in the Keychain export.
This helps identify which passwords failed to import into macOS Passwords.

Security: This script handles plaintext passwords. Ensure input/output files are
stored securely and deleted after use.
"""

import argparse
import csv
import sys
from pathlib import Path
from typing import List, Dict, Set, Tuple
from urllib.parse import urlparse


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
            'Source': self.source,
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
    """Read and validate CSV file."""
    if not filepath.exists():
        raise FileNotFoundError(f"File not found: {filepath}")

    with open(filepath, 'r', encoding=encoding, newline='') as f:
        reader = csv.DictReader(f, delimiter=delimiter)

        # Validate headers
        if reader.fieldnames is None:
            raise ValueError(f"No headers found in {filepath}")

        # Check if expected headers are present (allow extra headers)
        missing_headers = set(expected_headers) - set(reader.fieldnames)
        if missing_headers:
            raise ValueError(
                f"Missing required headers in {filepath}: {missing_headers}\n"
                f"Found headers: {reader.fieldnames}"
            )

        return list(reader)


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


def map_apple_record(row: Dict[str, str], row_index: int) -> Tuple[PasswordRecord, str]:
    """Map Apple Keychain CSV row to PasswordRecord.

    Apple Keychain exports have Title in format: 'hostname (username)'
    We extract just the hostname part for the title.
    """
    raw_title = row.get('Title', '').strip()
    title = parse_apple_title(raw_title)
    url = row.get('URL', '').strip()
    username = row.get('Username', '').strip()
    password = row.get('Password', '').strip()
    notes = row.get('Notes', '').strip()
    otpauth = row.get('OTPAuth', '').strip()

    # Skip if no password
    if not password:
        return None, 'missing password'

    return PasswordRecord(
        title=title,
        url=url,
        username=username,
        password=password,
        notes=notes,
        otpauth=otpauth,
        source='apple'
    ), None


def map_dashlane_record(row: Dict[str, str]) -> Tuple[PasswordRecord, str]:
    """Map Dashlane CSV row to PasswordRecord."""
    title = row.get('title', '').strip()
    url = row.get('url', '').strip()
    username = row.get('username', '').strip()
    password = row.get('password', '').strip()
    note = row.get('note', '').strip()
    category = row.get('category', '').strip()
    otpauth = row.get('otpUrl', '').strip()

    # Skip if no password
    if not password:
        return None, 'missing password'

    # Add category to notes if present
    notes = note
    if category:
        if notes:
            notes = f"Category: {category}\n{notes}"
        else:
            notes = f"Category: {category}"

    return PasswordRecord(
        title=title,
        url=url,
        username=username,
        password=password,
        notes=notes,
        otpauth=otpauth,
        source='dashlane'
    ), None


def map_lastpass_record(row: Dict[str, str]) -> Tuple[PasswordRecord, str]:
    """Map LastPass CSV row to PasswordRecord."""
    name = row.get('name', '').strip()
    url = row.get('url', '').strip()
    username = row.get('username', '').strip()
    password = row.get('password', '').strip()
    extra = row.get('extra', '').strip()
    grouping = row.get('grouping', '').strip()
    fav = row.get('fav', '').strip()
    totp = row.get('totp', '').strip()

    # LastPass uses 'http://sn' for secure notes
    if url.lower() == 'http://sn':
        # This is a secure note, not a login - skip it
        return None, 'secure note (not a login)'

    # Skip if no password
    if not password:
        return None, 'missing password'

    # Build notes from grouping, fav, and extra
    notes_parts = []
    if grouping:
        notes_parts.append(f"Group: {grouping}")
    if fav == '1':
        notes_parts.append("Favorite: 1")
    elif fav == '0':
        notes_parts.append("Favorite: 0")
    if extra:
        notes_parts.append(extra)

    notes = '\n'.join(notes_parts)

    return PasswordRecord(
        title=name,
        url=url,
        username=username,
        password=password,
        notes=notes,
        otpauth=totp,
        source='lastpass'
    ), None


def find_missing_passwords(
    apple_records: List[PasswordRecord],
    dashlane_records: List[PasswordRecord],
    lastpass_records: List[PasswordRecord],
    case_insensitive_usernames: bool = False
) -> List[PasswordRecord]:
    """Find records from dashlane/lastpass that are NOT in apple."""

    # Build set of all dedup keys from Apple Keychain (what we have)
    apple_keys = set()
    for record in apple_records:
        key = record.dedup_key(case_insensitive_usernames)
        apple_keys.add(key)

    print(f"Found {len(apple_keys)} unique passwords in Keychain export")

    # Find missing passwords
    missing = []

    # Check Dashlane records
    for record in dashlane_records:
        key = record.dedup_key(case_insensitive_usernames)
        if key not in apple_keys:
            missing.append(record)

    # Check LastPass records
    for record in lastpass_records:
        key = record.dedup_key(case_insensitive_usernames)
        if key not in apple_keys:
            missing.append(record)

    return missing


def write_missing_passwords(records: List[PasswordRecord], output_path: Path):
    """Write missing passwords to CSV."""
    if not records:
        print("No missing passwords found!")
        return

    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['Source', 'Title', 'URL', 'Username', 'Password', 'Notes', 'OTPAuth'])
        writer.writeheader()

        for record in records:
            writer.writerow(record.to_dict())

    print(f"\nMissing passwords written to: {output_path}")
    print(f"Total missing: {len(records)}")


def main():
    parser = argparse.ArgumentParser(
        description='Find passwords from LastPass/Dashlane that are missing from Keychain export'
    )
    parser.add_argument('--apple-csv', type=Path, required=True,
                       help='Path to Apple Keychain CSV export (what was successfully imported)')
    parser.add_argument('--dashlane-csv', type=Path,
                       help='Path to Dashlane CSV export')
    parser.add_argument('--lastpass-csv', type=Path,
                       help='Path to LastPass CSV export')
    parser.add_argument('--output', type=Path, required=True,
                       help='Path to output CSV file for missing passwords')
    parser.add_argument('--case-insensitive-usernames', action='store_true',
                       help='Treat usernames as case-insensitive when matching')
    parser.add_argument('--delimiter', default=',',
                       help='CSV delimiter (default: comma)')
    parser.add_argument('--encoding', default='utf-8',
                       help='CSV file encoding (default: utf-8)')

    args = parser.parse_args()

    # Validate inputs
    if not args.dashlane_csv and not args.lastpass_csv:
        print("ERROR: Must provide at least one of --dashlane-csv or --lastpass-csv")
        sys.exit(1)

    print("Reading files...")

    # Read Apple Keychain (reference - what we have)
    apple_rows = read_csv_file(args.apple_csv, APPLE_HEADERS, args.delimiter, args.encoding)
    print(f"  Keychain: {len(apple_rows)} rows")

    apple_records = []
    for i, row in enumerate(apple_rows):
        record, reason = map_apple_record(row, i)
        if record:
            apple_records.append(record)

    print(f"  Keychain: {len(apple_records)} valid records")

    # Read Dashlane
    dashlane_records = []
    if args.dashlane_csv:
        dashlane_rows = read_csv_file(args.dashlane_csv, DASHLANE_HEADERS, args.delimiter, args.encoding)
        print(f"  Dashlane: {len(dashlane_rows)} rows")

        for row in dashlane_rows:
            record, reason = map_dashlane_record(row)
            if record:
                dashlane_records.append(record)

        print(f"  Dashlane: {len(dashlane_records)} valid records")

    # Read LastPass
    lastpass_records = []
    if args.lastpass_csv:
        lastpass_rows = read_csv_file(args.lastpass_csv, LASTPASS_HEADERS, args.delimiter, args.encoding)
        print(f"  LastPass: {len(lastpass_rows)} rows")

        for row in lastpass_rows:
            record, reason = map_lastpass_record(row)
            if record:
                lastpass_records.append(record)

        print(f"  LastPass: {len(lastpass_records)} valid records")

    print("\nFinding missing passwords...")

    # Find what's missing
    missing = find_missing_passwords(
        apple_records,
        dashlane_records,
        lastpass_records,
        args.case_insensitive_usernames
    )

    # Group by source for summary
    by_source = {}
    for record in missing:
        if record.source not in by_source:
            by_source[record.source] = []
        by_source[record.source].append(record)

    print("\nMissing passwords by source:")
    for source, records in by_source.items():
        print(f"  {source}: {len(records)}")

    # Write output
    write_missing_passwords(missing, args.output)


if __name__ == '__main__':
    main()
