#!/usr/bin/env python3
"""
Basic tests for password merger.
Run from project root: python tests/test_basic.py
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from merge_passwords import (
    map_dashlane_record,
    map_lastpass_record,
    map_apple_record,
    normalize_url,
    extract_hostname,
    parse_apple_title,
    PasswordRecord,
    process_records
)


def test_normalize_url():
    """Test URL normalization."""
    assert normalize_url('https://GitHub.com/user') == 'https://github.com/user'
    assert normalize_url('example.com') == 'https://example.com'
    assert normalize_url('') == ''
    # Bare scheme URLs (app passwords) should be treated as empty
    assert normalize_url('http://') == ''
    assert normalize_url('https://') == ''
    assert normalize_url('HTTP://') == ''
    print("PASS: test_normalize_url")


def test_extract_hostname():
    """Test hostname extraction."""
    assert extract_hostname('https://www.github.com/user') == 'github.com'
    assert extract_hostname('https://login.example.com') == 'login.example.com'
    assert extract_hostname('example.com') == 'example.com'
    # Bare scheme URLs (app passwords) should return empty string
    assert extract_hostname('http://') == ''
    assert extract_hostname('https://') == ''
    assert extract_hostname('HTTP://') == ''
    print("PASS: test_extract_hostname passed")


def test_parse_apple_title():
    """Test Apple Keychain title parsing."""
    # Standard format: hostname (username)
    assert parse_apple_title('github.com (user@example.com)') == 'github.com'
    assert parse_apple_title('login.bol.com (testuser1@example.com)') == 'login.bol.com'
    assert parse_apple_title('rooster.bogerman.nl (997388)') == 'rooster.bogerman.nl'

    # Empty username: hostname ()
    assert parse_apple_title('www.booking.com ()') == 'www.booking.com'
    assert parse_apple_title('username.missing ()') == 'username.missing'

    # Edge cases
    assert parse_apple_title('') == ''
    assert parse_apple_title('   ') == ''

    # Backwards compatibility - titles without the (username) pattern
    assert parse_apple_title('GitHub') == 'GitHub'
    assert parse_apple_title('My App') == 'My App'

    print("PASS: test_parse_apple_title passed")


def test_map_dashlane_record():
    """Test Dashlane record mapping."""
    # Normal login
    row = {
        'username': 'user@example.com',
        'username2': '',
        'username3': '',
        'title': 'GitHub',
        'password': 'pass123',
        'note': 'My note',
        'url': 'https://github.com',
        'category': 'Dev',
        'otpUrl': 'otpauth://totp/GitHub?secret=ABC'
    }
    record, reason = map_dashlane_record(row)
    assert record is not None
    assert reason is None
    assert record.title == 'GitHub'
    assert record.username == 'user@example.com'
    assert record.otpauth == 'otpauth://totp/GitHub?secret=ABC'
    print("PASS: test_map_dashlane_record passed")


def test_map_dashlane_reject():
    """Test Dashlane record rejection."""
    # Missing password
    row = {
        'username': 'user@example.com',
        'username2': '',
        'username3': '',
        'title': 'GitHub',
        'password': '',
        'note': '',
        'url': '',
        'category': '',
        'otpUrl': ''
    }
    record, reason = map_dashlane_record(row)
    assert record is None
    assert reason == 'missing password'
    print("PASS: test_map_dashlane_reject passed")


def test_map_lastpass_login():
    """Test LastPass login mapping."""
    row = {
        'url': 'https://reddit.com',
        'username': 'user@reddit.com',
        'password': 'redditpass',
        'totp': 'otpauth://totp/Reddit?secret=XYZ',
        'extra': 'Extra notes',
        'name': 'Reddit',
        'grouping': 'Social',
        'fav': '1'
    }
    record, reason = map_lastpass_record(row)
    assert record is not None
    assert reason is None
    assert record.title == 'Reddit'
    assert record.username == 'user@reddit.com'
    assert record.source == 'lastpass'
    assert 'Social' in record.notes
    print("PASS: test_map_lastpass_login passed")


def test_map_lastpass_secure_note():
    """Test LastPass secure note mapping."""
    row = {
        'url': 'http://sn',
        'username': '',
        'password': '',
        'totp': '',
        'extra': 'This is my secure note content',
        'name': 'Important Note',
        'grouping': 'Personal',
        'fav': '0'
    }
    record, reason = map_lastpass_record(row)
    assert record is not None
    assert reason is None
    assert record.title == 'Important Note'
    assert record.url == ''
    assert record.username == ''
    assert record.password == ''
    assert 'secure note content' in record.notes
    assert record.source == 'lastpass-note'
    print("PASS: test_map_lastpass_secure_note passed")


def test_deduplication():
    """Test deduplication logic."""
    # Create existing Apple record
    apple_record = PasswordRecord(
        title='GitHub',
        url='https://github.com',
        username='user@example.com',
        password='pass123',
        source='apple'
    )

    # Create duplicate from Dashlane
    dashlane_duplicate = PasswordRecord(
        title='GitHub Clone',
        url='https://github.com',
        username='user@example.com',
        password='pass123',
        source='dashlane'
    )

    # Create non-duplicate
    dashlane_new = PasswordRecord(
        title='Twitter',
        url='https://twitter.com',
        username='user@twitter.com',
        password='twitterpass',
        source='dashlane'
    )

    merged, rejected = process_records(
        [apple_record],
        [dashlane_duplicate, dashlane_new],
        [],
        case_insensitive_usernames=False,
        include_existing=False,
        interactive=False
    )

    # Should only have the new Twitter record (duplicate was skipped)
    assert len(merged) == 1
    assert merged[0].title == 'Twitter'
    print("PASS: test_deduplication passed")


def test_conflict_detection():
    """Test conflict detection (same site+username, different password)."""
    # Create existing Apple record
    apple_record = PasswordRecord(
        title='Amazon',
        url='https://amazon.com',
        username='user@example.com',
        password='oldpass123',
        source='apple'
    )

    # Create conflicting LastPass record (same site+username, different password)
    lastpass_conflict = PasswordRecord(
        title='Amazon',
        url='https://www.amazon.com',  # www. should be normalized to same site
        username='user@example.com',
        password='newpass456',
        source='lastpass'
    )

    merged, rejected = process_records(
        [apple_record],
        [],
        [lastpass_conflict],
        case_insensitive_usernames=False,
        include_existing=False,
        interactive=False
    )

    # Conflict should be rejected
    assert len(merged) == 0
    assert len(rejected) == 1
    assert 'conflict' in rejected[0]['reason']
    print("PASS: test_conflict_detection passed")


def test_multiple_accounts_same_site():
    """Test handling of multiple accounts on same site with different usernames."""
    # Keychain has TWO entries for trello.com with different usernames
    apple_record1 = PasswordRecord(
        title='Trello',
        url='https://trello.com/',
        username='testuser1@example.com',
        password='password123',
        source='apple'
    )

    apple_record2 = PasswordRecord(
        title='Trello Work',
        url='https://trello.com/',
        username='testuser2@example.edu',
        password='differentpass456',
        source='apple'
    )

    # LastPass has ONE entry that matches the FIRST keychain entry exactly
    lastpass_record = PasswordRecord(
        title='Trello Personal',
        url='https://trello.com/',  # Same URL
        username='testuser1@example.com',  # Same username as apple_record1
        password='password123',  # Same password as apple_record1
        source='lastpass'
    )

    merged, rejected = process_records(
        [apple_record1, apple_record2],
        [],
        [lastpass_record],
        case_insensitive_usernames=False,
        include_existing=False,
        interactive=False
    )

    # The LastPass record should be recognized as an exact duplicate of apple_record1
    # and should be skipped (not merged, not rejected)
    assert len(merged) == 0, f"Expected 0 merged, got {len(merged)}"
    assert len(rejected) == 0, f"Expected 0 rejected, got {len(rejected)}"
    print("PASS: test_multiple_accounts_same_site passed")


def test_multiple_accounts_same_site_different_passwords():
    """Test conflict detection with multiple accounts on same site."""
    # Keychain has TWO entries for trello.com with different usernames
    apple_record1 = PasswordRecord(
        title='Trello',
        url='https://trello.com/',
        username='testuser1@example.com',
        password='password123',
        source='apple'
    )

    apple_record2 = PasswordRecord(
        title='Trello Work',
        url='https://trello.com/',
        username='testuser2@example.edu',
        password='differentpass456',
        source='apple'
    )

    # LastPass has ONE entry for the FIRST username but with a DIFFERENT password
    lastpass_record = PasswordRecord(
        title='Trello Personal',
        url='https://trello.com/',
        username='testuser1@example.com',  # Same username as apple_record1
        password='NEWPASSWORD999',  # Different password than apple_record1
        source='lastpass'
    )

    merged, rejected = process_records(
        [apple_record1, apple_record2],
        [],
        [lastpass_record],
        case_insensitive_usernames=False,
        include_existing=False,
        interactive=False
    )

    # Should detect conflict with apple_record1 (same site+username, different password)
    # Should NOT confuse it with apple_record2 (different username)
    assert len(merged) == 0, f"Expected 0 merged, got {len(merged)}"
    assert len(rejected) == 1, f"Expected 1 rejected, got {len(rejected)}"
    assert 'conflict' in rejected[0]['reason']
    print("PASS: test_multiple_accounts_same_site_different_passwords passed")


def test_url_path_matching():
    """Test that different URL paths on same domain are treated as same site.

    Since Keychain strips URLs to base domains, we match by hostname only.
    https://trello.com/ and https://trello.com/login are both just trello.com
    """
    # Keychain entry 1: Base URL
    apple_record1 = PasswordRecord(
        title='Trello',
        url='https://trello.com/',  # Base URL (what Keychain exports)
        username='testuser1@example.com',
        password='correctpass123',
        source='apple'
    )

    # Keychain entry 2: Different username on same site
    apple_record2 = PasswordRecord(
        title='Trello Work',
        url='https://trello.com',
        username='testuser2@example.edu',
        password='workpass456',
        source='apple'
    )

    # LastPass: Same site+user+pass but with login path
    # Since we match by hostname, this is an exact duplicate of apple_record1
    lastpass_record = PasswordRecord(
        title='Trello Personal',
        url='https://trello.com/login',  # Has /login path (what LastPass exports)
        username='testuser1@example.com',  # Same username as entry 1
        password='correctpass123',  # Same password as entry 1
        source='lastpass'
    )

    merged, rejected = process_records(
        [apple_record1, apple_record2],
        [],
        [lastpass_record],
        case_insensitive_usernames=False,
        include_existing=False,
        interactive=False
    )

    print(f"  Debug: merged={len(merged)}, rejected={len(rejected)}")
    if rejected:
        print(f"  Debug: rejected[0]={rejected[0]}")

    # LastPass record matches apple_record1 by hostname+username+password
    # so it's correctly identified as a duplicate and skipped
    assert len(rejected) == 0, f"Expected 0 rejected, got {len(rejected)}: {rejected}"
    assert len(merged) == 0, f"Expected 0 merged (exact duplicate by hostname), got {len(merged)}"
    print("PASS: test_url_path_matching passed")


def test_duplicate_entries_in_keychain_same_username():
    """Test when keychain has duplicate entries with same site+username but different passwords."""
    # Keychain has TWO entries with SAME URL and SAME username but DIFFERENT passwords
    # (This can happen if user changed password and old entry wasn't deleted)
    apple_record1 = PasswordRecord(
        title='Trello Old',
        url='https://trello.com/',
        username='testuser1@example.com',
        password='oldpass123',
        source='apple'
    )

    apple_record2 = PasswordRecord(
        title='Trello New',
        url='https://trello.com/',
        username='testuser1@example.com',  # SAME username
        password='newpass456',  # DIFFERENT password
        source='apple'
    )

    # LastPass has the OLD password
    lastpass_record = PasswordRecord(
        title='Trello',
        url='https://trello.com/',
        username='testuser1@example.com',
        password='oldpass123',  # Matches apple_record1
        source='lastpass'
    )

    merged, rejected = process_records(
        [apple_record1, apple_record2],
        [],
        [lastpass_record],
        case_insensitive_usernames=False,
        include_existing=False,
        interactive=False
    )

    print(f"  Debug: merged={len(merged)}, rejected={len(rejected)}")
    if rejected:
        print(f"  Debug: rejected reasons: {[r['reason'] for r in rejected]}")

    # LastPass password matches one of the keychain passwords (oldpass123)
    # so it should NOT be flagged as a conflict
    assert len(rejected) == 0, f"Expected 0 rejected, got {len(rejected)}: {rejected}"
    # It's an exact duplicate of apple_record1, so should be skipped
    assert len(merged) == 0, f"Expected 0 merged (exact duplicate), got {len(merged)}"
    print("PASS: test_duplicate_entries_in_keychain_same_username passed")


def test_password_with_whitespace():
    """Test password comparison with leading/trailing whitespace."""
    # Keychain has password with trailing whitespace
    apple_record = PasswordRecord(
        title='Trello',
        url='https://trello.com/',
        username='testuser1@example.com',
        password='password123 ',  # Note the trailing space
        source='apple'
    )

    # LastPass has same password without trailing whitespace
    lastpass_record = PasswordRecord(
        title='Trello',
        url='https://trello.com/',
        username='testuser1@example.com',
        password='password123',  # No trailing space
        source='lastpass'
    )

    merged, rejected = process_records(
        [apple_record],
        [],
        [lastpass_record],
        case_insensitive_usernames=False,
        include_existing=False,
        interactive=False
    )

    print(f"  Debug: merged={len(merged)}, rejected={len(rejected)}")

    # After the fix, passwords differing only by whitespace should NOT be flagged as conflicts
    # They should be recognized as exact duplicates and skipped
    assert len(rejected) == 0, f"Expected 0 rejected (whitespace should be ignored), got {len(rejected)}"
    assert len(merged) == 0, f"Expected 0 merged (exact duplicate after stripping), got {len(merged)}"
    print("PASS: test_password_with_whitespace passed")


def test_source_tracking():
    """Test that source attribute is correctly maintained through processing."""
    # Create records from different sources
    dashlane_record1 = PasswordRecord(
        title='Virtual',
        url='',
        username='TestUser123',
        password='Regatta',
        source='dashlane'
    )

    dashlane_record2 = PasswordRecord(
        title='bitbucket',
        url='',
        username='TestUser123',
        password='abc123XYZ456',
        source='dashlane'
    )

    # Both are from Dashlane, same username but different titles and passwords
    # These are app passwords (no URL), so they should be treated as different apps
    # and both should be merged (not flagged as conflict)
    merged, rejected = process_records(
        [],
        [dashlane_record1, dashlane_record2],
        [],
        case_insensitive_usernames=False,
        include_existing=False,
        interactive=False
    )

    print(f"  Debug: merged={len(merged)}, rejected={len(rejected)}")

    # Should have 2 merged (both are different apps)
    assert len(merged) == 2, f"Expected 2 merged (different apps), got {len(merged)}"
    assert len(rejected) == 0, f"Expected 0 rejected, got {len(rejected)}"

    # Verify both records have correct source
    assert merged[0].source == 'dashlane', f"Expected merged[0] source='dashlane', got {merged[0].source}"
    assert merged[1].source == 'dashlane', f"Expected merged[1] source='dashlane', got {merged[1].source}"
    print("PASS: test_source_tracking passed")


def test_app_passwords_with_same_username():
    """Test that app passwords (no URL) with same username but different titles are not treated as conflicts."""
    # Create app password entries with no URL but different app names
    dashlane_record1 = PasswordRecord(
        title='Virtual Regatta',
        url='',
        username='TestUser123',
        password='pass9W0rd!',
        source='dashlane'
    )

    dashlane_record2 = PasswordRecord(
        title='bitbucket',
        url='',
        username='TestUser123',
        password='abc123XYZ456',
        source='dashlane'
    )

    merged, rejected = process_records(
        [],
        [dashlane_record1, dashlane_record2],
        [],
        case_insensitive_usernames=False,
        include_existing=False,
        interactive=False
    )

    print(f"  Debug: merged={len(merged)}, rejected={len(rejected)}")

    # Both should be merged (they're different apps even though same username)
    assert len(merged) == 2, f"Expected 2 merged, got {len(merged)}"
    assert len(rejected) == 0, f"Expected 0 rejected, got {len(rejected)}"

    # Verify titles are preserved
    titles = {r.title for r in merged}
    assert 'Virtual Regatta' in titles
    assert 'bitbucket' in titles
    print("PASS: test_app_passwords_with_same_username passed")


def test_app_passwords_lastpass_http_scheme():
    """Test that LastPass app passwords (url='http://') are treated the same as empty URLs."""
    # Dashlane uses empty string for app passwords
    dashlane_record = PasswordRecord(
        title='Spotify',
        url='',
        username='user@example.com',
        password='spotifypass123',
        source='dashlane'
    )

    # LastPass uses 'http://' for app passwords
    lastpass_record1 = PasswordRecord(
        title='Discord',
        url='http://',
        username='user@example.com',
        password='discordpass456',
        source='lastpass'
    )

    lastpass_record2 = PasswordRecord(
        title='Steam',
        url='http://',
        username='user@example.com',
        password='steampass789',
        source='lastpass'
    )

    merged, rejected = process_records(
        [],
        [dashlane_record],
        [lastpass_record1, lastpass_record2],
        case_insensitive_usernames=False,
        include_existing=False,
        interactive=False
    )

    print(f"  Debug: merged={len(merged)}, rejected={len(rejected)}")

    # All three should be merged (different apps despite same username)
    # They should NOT be flagged as conflicts just because they all have same username
    assert len(merged) == 3, f"Expected 3 merged (different apps), got {len(merged)}"
    assert len(rejected) == 0, f"Expected 0 rejected, got {len(rejected)}"

    # Verify all titles are preserved
    titles = {r.title for r in merged}
    assert 'Spotify' in titles
    assert 'Discord' in titles
    assert 'Steam' in titles
    print("PASS: test_app_passwords_lastpass_http_scheme passed")


def run_all_tests():
    """Run all tests."""
    print("Running tests...\n")

    test_normalize_url()
    test_extract_hostname()
    test_parse_apple_title()
    test_map_dashlane_record()
    test_map_dashlane_reject()
    test_map_lastpass_login()
    test_map_lastpass_secure_note()
    test_deduplication()
    test_conflict_detection()
    test_multiple_accounts_same_site()
    test_multiple_accounts_same_site_different_passwords()
    test_url_path_matching()
    test_duplicate_entries_in_keychain_same_username()
    test_password_with_whitespace()
    test_source_tracking()
    test_app_passwords_with_same_username()
    test_app_passwords_lastpass_http_scheme()

    print("\nAll tests passed!")


if __name__ == '__main__':
    run_all_tests()
