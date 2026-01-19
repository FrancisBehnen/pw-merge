1. Goal and Scope
* Goal: Create a Python script that merges password data exported from macOS Keychain, Dashlane, and LastPass into a single CSV compatible with macOS Keychain’s import format: Title,URL,Username,Password,Notes,OTPAuth. 
* In scope:
    * Read CSV exports from:
        * macOS Keychain (or Safari/Passwords app export) in Apple’s CSV format. 
        * Dashlane credentials CSV (logins) using the Dashlane header format. 
        * LastPass CSV export (logins + secure notes) using the LastPass header format. 
    * Normalize and merge into one Apple-format CSV. 
    * Deduplicate against existing Keychain entries. 
    * Produce:
        * A “clean” importable CSV. 
        * A “rejected/uninterpretable” CSV for manual inspection. 

2. Input Formats
2.1 Apple / Keychain input
* CSV with headers: Title,URL,Username,Password,Notes,OTPAuth. 
* Used as:
    * Source of existing items for deduplication. 
    * Optional: also included in the final merged output (if desired) to have a “full” merged view. 
2.2 Dashlane CSV
* Expected headers (logins/credentials export): username,username2,username3,title,password,note,url,category,otpUrl (as you provided; PRD assumes this exact set). 
* Notes:
    * otpUrl or otpSecret might encode a TOTP secret; script should attempt to translate into OTPAuth if possible (e.g., use the URL as-is if it is an otpauth URL; otherwise, keep in Notes). 
2.3 LastPass CSV
* Expected headers: url,username,password,totp,extra,name,grouping,fav. 
* Notes:
    * Secure notes:
        * Special URL: http://sn. 
        * name is the title. 
        * extra contains the body/content. 
    * Regular logins:
        * url is the website URL. 
        * totp may contain an otpauth URL or secret. 
2.4 Configurability
* Script should accept:
    * Paths for each input CSV:
        * --apple-csv (existing keychain export, optional but recommended). 
        * --dashlane-csv. 
        * --lastpass-csv. 
    * Optional flags:
        * --include-existing (include Apple rows in final output vs. only use for dedupe). 
        * --delimiter (fallback if non‑standard CSV, default ,). 
        * --encoding (default utf-8). 

3. Output Files
3.1 Main merged CSV (for import)
* Headers exactly: Title,URL,Username,Password,Notes,OTPAuth. 
* Contains:
    * All interpretable entries from Dashlane and LastPass that are not exact duplicates of existing Apple entries. 
    * Optionally: existing Apple entries (depending on configuration). 
3.2 “Uninterpreted” / rejected CSV
* Purpose: any Dashlane/LastPass row that cannot be mapped into the Apple format with minimal confidence. 
* Headers should include:
    * source (e.g., dashlane, lastpass). 
    * Original columns from that source. 
    * reason (free text: e.g., “missing password”, “no title or URL”, “ambiguous secure note with no content”, “invalid CSV row parse error”). 
* This file will be used for manual cleanup and possible re‑import later. 

4. Field Mapping Rules
4.1 Apple/Keychain → Apple/Keychain
* Already in target format; if included:
    * Copy fields verbatim. 
    * Normalize URL and username for deduplication (e.g., lowercase host, trim spaces). 
4.2 Dashlane → Apple
For each Dashlane row:
* Title:
    * Prefer title. 
    * Fallback: if missing, derive from url host (e.g., example.com) or from a non‑empty username. 
* URL:
    * Use url if non‑empty. 
    * Normalize (trim, ensure scheme if obviously a domain). 
* Username:
    * Prefer username; if empty, use username2, then username3 if needed. 
* Password:
    * Use password. 
* Notes:
    * Primary: note. 
    * Optionally append extra usernames (username2, username3) and category in a structured way, e.g.:
        * Additional usernames: ...; Category: ... 
* OTPAuth:
    * If otpUrl is an otpauth:// URL, copy into OTPAuth. 
    * Otherwise, leave OTPAuth empty and append original otpUrl into Notes. 
If critical fields (Password and at least one of Title/URL/Username) are missing, send row to “uninterpreted” with a reason.
4.3 LastPass → Apple
For each LastPass row:
* Detect secure notes vs logins:
    * If url == "http://sn" → treat as secure note. 
    * Else → treat as login. 
4.3.1 Login entries
* Title:
    * Use name. 
    * If empty, derive from url host. 
* URL:
    * Use url, normalize host and scheme. 
* Username:
    * Use username. 
* Password:
    * Use password. 
* Notes:
    * Use extra. 
    * Optionally append grouping and fav (e.g., “Group: X; Favorite: 1”) for context. 
* OTPAuth:
    * If totp is an otpauth:// URL, use it directly. 
    * If totp looks like a TOTP secret but not a full URL, consider leaving OTPAuth empty and appending it to Notes with a label (so user can reconstruct manually). 
4.3.2 Secure note entries (url == "http://sn")
* Title:
    * Use name. 
* URL:
    * Leave empty (or set to ""). 
* Username:
    * Leave empty. 
* Password:
    * Leave empty. 
* Notes:
    * Use extra as the full note body (possibly truncated if Keychain has limits; PRD can mention an optional limit). 
    * Append grouping and fav as metadata if helpful. 
* OTPAuth:
    * Leave empty. 
If name and extra are both empty for a secure note, send to “uninterpreted”.

The PRD can be updated so that “same site + username but different password” is always diverted to the manual‑review file instead of being imported automatically.
Here is the adjusted section with your requested behavior.

5. Deduplication Logic (Updated)
5.1 Definition of “exact duplicate” (unchanged)
* A record from Dashlane/LastPass is considered an exact duplicate of an existing Apple item if, after normalization, all of the following match:
    * URL (normalized host and path, case‑insensitive for host). 
    * Username (trimmed, configurable case‑sensitivity). 
    * Password (exact string match). 
* Optional: also treat entries with same Title + Username + Password and very similar or empty URLs as duplicates. 
5.2 Duplicate and conflict handling (updated)
* Exact duplicate (URL + Username + Password match):
    * Do not add to main output CSV. 
    * Optionally increment an “exact duplicates skipped” counter. 
* Conflict: same site + username but different password:
    * “Same site” is defined as:
        * Same normalized hostname; subdomain differences (e.g. www.example.com vs login.example.com) are considered the same site. 
    * If URL host and Username match an existing Apple record, but Password differs:
        * Do not include this row in the main merged/importable CSV. 
        * Instead, write the row to the “uninterpreted/rejected” CSV with a reason like:
            * reason = "conflict: same site + username but different password" 
        * Include enough context in the rejected row (source, URL, username, title) so the password can be manually reviewed and reconciled later. 
* Non‑duplicate, non‑conflict:
    * Process normally and include in the main output CSV. 
This change ensures that potential password conflicts never get imported silently and are always surfaced for manual review.


6. Error Handling and Validation
* CSV parsing:
    * Detect missing header row; if headers don’t match expected ones, abort with a clear error explaining expected headers. 
    * Handle different line endings and quoting. 
* Per‑row validation:
    * Log and skip rows that:
        * Have fewer columns than expected. 
        * Cannot be decoded in the given encoding. 
* Output integrity:
    * Always write the header row to output CSVs. 
    * Ensure no formulas or dangerous constructs are generated in fields (e.g., don’t prepend =). 

7. Security and Safety Requirements
* The script deals entirely with plaintext passwords and TOTP secrets. 
* Requirements:
    * Do not log actual passwords, TOTP secrets, or secure note contents. 
    * Logs (if any) should only include:
        * Row indices. 
        * Source filenames. 
        * Field names and error codes, not field values. 
    * Clearly state in README/usage:
        * Files are unencrypted and must be securely deleted after import. 
* Optional:
    * Warn if the working directory is synced to cloud drives (e.g., Dropbox, iCloud) in documentation. 

8. CLI and UX Requirements
* Command‑line interface:
    * Example usage:
        * python merge_passwords.py --apple-csv apple.csv --dashlane-csv dashlane.csv --lastpass-csv lastpass.csv --output merged.csv --rejected rejected.csv 
    * Parameters:
        * --apple-csv (optional). 
        * --dashlane-csv (optional but at least one of Dashlane/LastPass must be provided). 
        * --lastpass-csv (optional). 
        * --output (required). 
        * --rejected (required). 
        * --include-existing (flag). 
        * --case-insensitive-usernames (flag for dedupe). 
* Exit codes:
    * 0 on success (even if some rows ended in “uninterpreted”). 
    * Non‑zero on:
        * Missing input files. 
        * Header mismatch. 
        * Unhandled exceptions. 

9. Testing Criteria
* Provide small sample CSV fixtures for:
    * Simple login from Dashlane and LastPass each, correctly mapped. 
    * LastPass secure note mapping. 
    * Entries with OTP from Dashlane and LastPass. 
    * Duplicate entries vs existing Apple CSV:
        * Confirm duplicates are removed. 
    * Corrupt/bad rows:
        * Confirm they appear in rejected CSV with a reason. 
* Manual test:
    * Import merged.csv into macOS Passwords/Keychain and verify:
        * All expected entries show. 
        * Fields are correctly filled (title, URL, username, password, notes, OTP). 

