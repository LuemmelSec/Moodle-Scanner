import requests
import hashlib
import os
import re
import csv
import argparse
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
from collections import Counter

# Constants

MOODLE_REPO_API = "https://api.github.com/repos/moodle/moodle/tags"
FILE_LIST = [
    "/admin/environment.xml", "/composer.lock", "/lib/upgrade.txt",
    "/privacy/export_files/general.js", "/composer.json",
    "/question/upgrade.txt", "/admin/tool/lp/tests/behat/course_competencies.feature"
]
LOCAL_HASH_FILE = "moodle_hashes.txt"
base_url = "https://moodle.org/security/index.php"
LOCAL_VULN_FILE = "moodle_vulnerabilities.csv"

# Moodle Stuff
def fetch_moodle_versions():
    versions = []
    page = 1
    while True:
        response = requests.get(MOODLE_REPO_API, params={'page': page, 'per_page': 100})
        if response.status_code != 200:
            raise Exception(f"Failed to fetch Moodle tags: {response.status_code}")
        
        tags = [item['name'] for item in response.json()]
        versions.extend(tags)

        if 'Link' in response.headers and 'rel="next"' in response.headers['Link']:
            page += 1
        else:
            break

    # print("Fetched versions:", versions)  
    return versions

def fetch_file_for_version(file, version):
    # Skip specific files based on version
    if version <= "v3.6.10" and file == "/admin/tool/lp/tests/behat/course_competencies.feature":
        return None
    if version <= "v3.5.2" and file == "/privacy/export_files/general.js":
        return None
    if version <= "v2.9.0-beta" and file == "/composer.lock":
        return None
    if version <= "v2.5.9" and file == "/question/upgrade.txt":
        return None
    if version <= "v2.4.0-beta" and file == "/composer.json":
        return None        
    if version <= "v2.1.10" and file == "/lib/upgrade.txt":
        return None
    if version <= "v1.4.5" and file == "/admin/environment.xml":
        return None

    file_url = f"https://raw.githubusercontent.com/moodle/moodle/{version}{file}"
    response = requests.get(file_url)
    if response.status_code == 200:
        file_hash = hashlib.md5(response.content).hexdigest()
        return f"{file}:{file_hash}:{version}"
    else:
        print(f"Failed to fetch {file} for version {version} (HTTP {response.status_code})")
        return None

def hash_files_for_version(version):
    with ThreadPoolExecutor() as executor:
        results = list(executor.map(lambda file: fetch_file_for_version(file, version), FILE_LIST))
    return [result for result in results if result]

def compare_versions(version1, version2):
    """
    Compare two Moodle versions in the format 'major.minor.patch'.

    Args:
    version1 (str): The first version to compare.
    version2 (str): The second version to compare.

    Returns:
    int: -1 if version1 < version2, 0 if equal, 1 if version1 > version2.
    """
    # Handle version range (e.g., "4 to 4")
    if ' to ' in version2:
        version2 = version2.split(' to ')[0]  # Take the first part of the range
        print(f"Handling version range, using {version2} for comparison.")
    
    # Remove any leading 'v' and split by '.'
    try:
        parts1 = [int(part) for part in version1.lstrip('v').split('.')]
        parts2 = [int(part) for part in version2.lstrip('v').split('.')]
    except ValueError as e:
        print(f"Error processing versions: {version1}, {version2}. Error: {e}")
        return 0  # Return 0 if versions cannot be compared
    
    # Compare version parts
    for p1, p2 in zip(parts1, parts2):
        if p1 < p2:
            return -1
        elif p1 > p2:
            return 1
    
    # Handle case where one version has more parts than the other
    return 0 if len(parts1) == len(parts2) else (1 if len(parts1) > len(parts2) else -1)

def update_moodle_hashes():
    existing_hashes = set()
    first_version = None
    
    if os.path.exists(LOCAL_HASH_FILE):
        with open(LOCAL_HASH_FILE, "r") as f:
            # Read the first line and extract the version
            first_line = f.readline().strip()  # Read only the first line
            if first_line:
                first_version = first_line.split(":")[-1]  # Extract the version from the first line
    
    # Fetch the latest Moodle tags
    new_versions = fetch_moodle_versions()

    # Print the versions for debugging purposes
    print(f"Newest version from fetched tags: {new_versions[0]}")
    if first_version:
        print(f"First version from local hash file: {first_version}")

    # Check if the fetched version is greater than the stored version
    if first_version and new_versions and new_versions[0] > first_version:
        print("A new version is available. Starting the update process.")
        new_hashes = []
        os.remove(LOCAL_HASH_FILE)
        # Only fetch new hashes if the version is greater
        for version in new_versions:
            version_hashes = hash_files_for_version(version)
            for line in version_hashes:
                if line not in existing_hashes:
                    new_hashes.append(line)

        if new_hashes:
            with open(LOCAL_HASH_FILE, "a") as f:
                f.write("\n".join(new_hashes) + "\n")
            print("Hash file updated with new versions.")
        else:
            print("No new hashes to add.")
    else:
        print("The latest version is already recorded or is not newer.")






def compare_versions(version1, version2):
    """
    Compare two Moodle versions in the format 'major.minor.patch'.

    Args:
    version1 (str): The first version to compare.
    version2 (str): The second version to compare.

    Returns:
    int: -1 if version1 < version2, 0 if equal, 1 if version1 > version2.
    """
    # Handle version range (e.g., "4 to 4" or "4 and 4")
    if ' to ' in version2:
        version2 = version2.split(' to ')[0]  # Take the first part of the range
    elif ' and ' in version2:
        version2 = version2.split(' and ')[0]  # Handle "4 and 4" style ranges

    try:
        # Remove any leading 'v' and split by '.'
        parts1 = [int(part) for part in version1.lstrip('v').split('.')]
        parts2 = [int(part) for part in version2.lstrip('v').split('.')]
    except ValueError as e:
        print(f"Error processing versions: {version1}, {version2}. Error: {e}")
        return 0  # Return 0 if versions cannot be compared
    
    # Compare version parts
    for p1, p2 in zip(parts1, parts2):
        if p1 < p2:
            return -1
        elif p1 > p2:
            return 1
    
    # Handle case where one version has more parts than the other
    return 0 if len(parts1) == len(parts2) else (1 if len(parts1) > len(parts2) else -1)


def compare_file_with_local_hash(file_url, file_path):
    file_hash = hashlib.md5(requests.get(file_url).content).hexdigest()
    
    with open(LOCAL_HASH_FILE, "r") as f:
        for line in f:
            stored_file, stored_hash, stored_version = line.strip().split(":")
            if stored_file == file_path and stored_hash == file_hash:
                return stored_version
    return None

# Updated check_moodle_version function that includes --scan flag handling
def check_moodle_version(url, scan_vulns=False):
    if not os.path.exists(LOCAL_HASH_FILE):
        print("Local hash file not found. Please run --update first.")
        return

    latest_versions = {}  # Use a dictionary to store file paths and versions
    file_hash_matches = []

    # Step 1: Compare hashes for each file
    for file_path in FILE_LIST:
        file_url = f"{url.rstrip('/')}{file_path}"
        version = compare_file_with_local_hash(file_url, file_path)
        if version:
            latest_versions[file_path] = version  # Assign version to file_path in dictionary
        else:
            print(f"File: {file_path}, No version found")
        file_hash_matches.append(version)
    
    versions_found = [version for version in latest_versions.values() if version]

    if len(set(versions_found)) == 1:
        print(f"\033[92mIdentified version matches for all files and is {versions_found[0]}\033[0m")
    else:
        print("\033[93mThere is a mismatch in the versions.\033[0m")
        
        sorted_versions = sorted(versions_found, key=lambda v: [int(part) for part in v.lstrip('v').split('.')])
        min_version = sorted_versions[0]
        max_version = sorted_versions[-1]
        print(f"Version is between {min_version} and {max_version}")

    # Optionally, print the versions for each file
    print("Latest versions found for each file:")
    for file_path, version in latest_versions.items():
        if version:
            print(f"File: {file_path}, Latest Version: {version}")
        else:
            print(f"File: {file_path}, No version found")
    
    
    # Step 2: Identify unique or conflicting versions
    if len(set(latest_versions)) == 1 and latest_versions[0] is not None:
        confirmed_version = latest_versions[0]
        print(f"\033[92mIdentified version matches for all files: {confirmed_version}\033[0m")
        if scan_vulns:
            print("Scanning for vulnerabilities...")
            scan_for_vulnerabilities(confirmed_version)
        return

    # Step 3: Fallback to identifying most likely version
    print("\033[93mAttempting to determine the most likely version...\033[0m")
    with open(LOCAL_HASH_FILE, 'r') as f:
        hash_data = f.read()

    possible_versions = {}
    for hash_version in filter(None, file_hash_matches):
        # Find all lines containing the hash
        candidates = re.findall(rf".*{hash_version}.*", hash_data)
    
        for candidate in candidates:
            try:
                # Split candidate line into components using the correct delimiter
                file_path, file_hash, version = candidate.split(":")
            
                # Add to possible_versions
                if file_path not in possible_versions:
                    possible_versions[file_path] = version
            except ValueError:
                print(f"Error: Candidate does not match expected format: {candidate}")

    # Step 4: Evaluate the closest match
    if possible_versions:
        version_values = list(possible_versions.values())
        most_common_version = max(set(version_values), key=version_values.count)
        print(f"\033[92mMost likely Moodle version: {most_common_version}\033[0m")
        if scan_vulns:
            print("Scanning for vulnerabilities...")
            scan_for_vulnerabilities(most_common_version)
    else:
        print("\033[91mUnable to determine Moodle version.\033[0m")

    print("Finished analysis.")

# Vuln Stuff


# Function to parse and extract the relevant vulnerability information from a <table>
def extract_vulnerability_info_from_table(table):
    # Initialize default values
    severity = ""
    versions_affected = ""
    versions_fixed = ""
    cve = ""
    tracker_issue = ""
    
    # Extract rows and map data
    rows = table.find_all('tr')
    for row in rows:
        cols = row.find_all('td')
        if len(cols) == 2:  # Each row should have two columns
            label = cols[0].get_text(strip=True)
            value = cols[1].get_text(strip=True)
            
            # Match labels and extract the corresponding value
            if "Severity/Risk" in label:
                severity = value
            elif "Versions affected" in label:
                versions_affected = value
            elif "Versions fixed" in label:
                versions_fixed = value
            elif "CVE identifier" in label:
                cve = value
            elif "Tracker issue" in label:
                tracker_issue = value

    return [severity, versions_affected, versions_fixed, cve, tracker_issue]

# Function to scrape vulnerabilities from a given page URL
def scrape_vulnerabilities(page_url):
    response = requests.get(page_url)
    vulnerabilities = []
    
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Find all <table> elements containing vulnerability data
        tables = soup.find_all('table')
        for table in tables:
            vuln_info = extract_vulnerability_info_from_table(table)
            if any(vuln_info):  # Ensure the table had relevant data
                vulnerabilities.append(vuln_info)
    else:
        print(f"Failed to fetch page: {page_url}, Status code: {response.status_code}")
    
    return vulnerabilities

# Function to follow pagination and scrape data from all pages
def scrape_all_pages(base_url, start_page=0):
    all_vulnerabilities = []
    current_page = start_page
    while True:
        # Construct the URL for the current page
        page_url = f"{base_url}?o=3&s=10&p={current_page}"
        print(f"Scraping page {current_page + 1}: {page_url}")
        
        vulnerabilities = scrape_vulnerabilities(page_url)
        if not vulnerabilities:
            print(f"No vulnerabilities found on page {current_page + 1}. Stopping.")
            break
        
        all_vulnerabilities.extend(vulnerabilities)
        current_page += 1  # Move to the next page
    
    return all_vulnerabilities

# Save the vulnerabilities to a CSV file
def save_to_csv(vulnerabilities, filename='moodle_vulnerabilities.csv'):
    with open(filename, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(['Severity/Risk', 'Versions Affected', 'Versions Fixed', 'CVE Identifier', 'Tracker Issue'])
        writer.writerows(vulnerabilities)
    print(f"Vulnerabilities have been saved to {filename}")
    
def fetch_latest_vulnerability_id():
    """
    Fetch the latest vulnerability ID (e.g., MDL-xyz) from the Moodle security page.
    """
    response = requests.get(base_url)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        tables = soup.find_all('table')
        for table in tables:
            vuln_info = extract_vulnerability_info_from_table(table)
            if vuln_info and vuln_info[4]:  # Tracker Issue is in the 5th column
                return vuln_info[4]  # Return the first found Tracker Issue (MDL-xyz)
    else:
        print(f"Failed to fetch Moodle security page: {response.status_code}")
        return None

def read_local_vulnerability_id():
    """
    Read the first vulnerability ID (e.g., MDL-xyz) from the local file.
    """
    if not os.path.exists(LOCAL_VULN_FILE):
        return None

    with open(LOCAL_VULN_FILE, "r", encoding='utf-8') as f:
        reader = csv.reader(f)
        next(reader, None)  # Skip the header
        first_row = next(reader, None)
        if first_row and len(first_row) >= 5:  # Ensure the row has enough columns
            return first_row[4]  # Tracker Issue column
    return None

def update_vulnerabilities():
    """
    Update the local vulnerabilities file if new vulnerabilities are found.
    """
    local_id = read_local_vulnerability_id()
    latest_id = fetch_latest_vulnerability_id()

    print(f"Latest Tracker Issue from Moodle: {latest_id}")
    print(f"First Tracker Issue from local file: {local_id}")

    if local_id == latest_id:
        print("The latest vulnerabilities are already recorded. No update needed.")
        return

    # Scrape all vulnerabilities and update the file
    all_vulnerabilities = scrape_all_pages(base_url)

    if all_vulnerabilities:
        save_to_csv(all_vulnerabilities, filename=LOCAL_VULN_FILE)
        print("Vulnerability file updated with new data.")
    else:
        print("No vulnerabilities found to update.")


def severity_to_value(severity):
    """Convert severity string to a numeric value for sorting purposes."""
    severity = severity.lower().strip()  # Ensure the severity is in lowercase and stripped of whitespace
    if 'serious' in severity:
        return 1  # High severity (Serious)
    elif 'minor' in severity:
        return 2  # Medium severity (Minor)
    return 3  # Unknown or unclassified severity (lower priority)

def color_code_severity(severity):
    """Assign a color code to a severity level."""
    severity = severity.lower().strip()  # Normalize severity to lowercase
    if 'serious' in severity:
        return "\033[91m"  # Red for serious (high severity)
    elif 'minor' in severity:
        return "\033[94m"  # Blue for minor (medium severity)
    return "\033[0m"  # Default color (no coloring for unknown severity)

def scan_for_vulnerabilities(moodle_version):
    """
    Scan the identified Moodle version against known vulnerabilities.

    Args:
    moodle_version (str): The identified Moodle version.

    Returns:
    None
    """
    if not os.path.exists(LOCAL_VULN_FILE):
        print("Local vulnerabilities file not found. Please run --vuln first.")
        return

    # Parse the moodle_vulnerabilities.csv file
    vulnerabilities = []
    with open(LOCAL_VULN_FILE, "r", encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            versions_affected = row['Versions Affected']
            versions_fixed = row['Versions Fixed']
            cve = row['CVE Identifier']
            severity = row['Severity/Risk']
            tracker_issue = row['Tracker Issue']

            # Compare the Moodle version with affected and fixed ranges
            affected_versions = [v.strip() for v in versions_affected.split(',')]
            fixed_versions = [v.strip() for v in versions_fixed.split(',')]

            is_vulnerable = False
            for affected_version in affected_versions:
                if compare_version_range(moodle_version, affected_version):
                    for fixed_version in fixed_versions:
                        if compare_versions(moodle_version, fixed_version) < 0:
                            is_vulnerable = True
                            break

            if is_vulnerable:
                vulnerabilities.append({
                    "CVE": cve,
                    "Severity": severity,
                    "Tracker": tracker_issue,
                    "Affected Versions": versions_affected,
                    "Fixed Versions": versions_fixed,
                })

    # Sort vulnerabilities by severity (Serious first, Minor second)
    vulnerabilities.sort(key=lambda x: severity_to_value(x['Severity']))

    # Print the results
    if vulnerabilities:
        print(f"\n\033[91mThe site (version: {moodle_version}) is affected by the following vulnerabilities:\033[0m")
        for vuln in vulnerabilities:
            severity_color = color_code_severity(vuln['Severity'])
            print(f"{severity_color}- CVE: {vuln['CVE']} | Severity: {vuln['Severity']} | Tracker: {vuln['Tracker']}")
            print(f"  Affected Versions: {vuln['Affected Versions']}")
            print(f"  Fixed Versions: {vuln['Fixed Versions']}\n\033[0m")
    else:
        print(f"\n\033[92mThe site (version: {moodle_version}) is not affected by any known vulnerabilities.\033[0m")

def is_valid_version(version_str):
    """Check if the version string is valid (i.e., a numeric version)."""
    return bool(re.match(r'^\d+(\.\d+)+$', version_str))

def clean_version_string(version_str):
    """Clean up version string by removing the '+' symbol and extra spaces."""
    return version_str.replace('+', '').strip()

def compare_version_range(moodle_version, affected_version):
    """
    Compare Moodle version with a range or multiple ranges.
    Args:
    moodle_version (str): The current Moodle version.
    affected_version (str): The version range or list of ranges that are affected.
    
    Returns:
    bool: True if the version is affected by the vulnerability.
    """
    # Remove any occurrence of "earlier unsupported versions" from the affected_version
    affected_version = affected_version.lower().replace("earlier unsupported versions", "")
    
    # Split by 'and' to handle multiple version ranges (e.g., '3.9 to 3.9.6 and 3.8 to 3.8.8')
    affected_ranges = affected_version.split(' and ')
    
    for affected_range in affected_ranges:
        affected_range = affected_range.strip()  # Remove leading/trailing spaces
        
        if not affected_range:  # If the range is empty after cleaning, skip it
            continue
        
        # Clean up version string by removing any '+' signs
        affected_range = clean_version_string(affected_range)

        # Handle the case where the affected range has a 'to' separator
        if ' to ' in affected_range:
            try:
                start_version, end_version = affected_range.split(' to ')
                
                # Ensure that both versions are valid before comparing
                if not is_valid_version(start_version) or not is_valid_version(end_version):
                    # print(f"Skipping invalid version range: {affected_range}")
                    continue  # Skip invalid ranges

            except ValueError:
                # print(f"Error parsing version range: {affected_range}")
                continue  # Skip invalid ranges

            # Now compare the Moodle version against this range
            if compare_versions(moodle_version, start_version) >= 0 and compare_versions(moodle_version, end_version) <= 0:
                return True  # This version is affected
        else:
            # If there is no 'to' separator, treat it as a single version
            if is_valid_version(affected_range) and compare_versions(moodle_version, affected_range) == 0:
                return True  # This version is affected
    
    return False  # If no range matches, the version is not affected


banner = '''
___  ___                _ _             _____                                 
|  \/  |               | | |           /  ___|                                
| .  . | ___   ___   __| | | ___ ______\ `--.  ___ __ _ _ __  _ __   ___ _ __ 
| |\/| |/ _ \ / _ \ / _` | |/ _ \______|`--. \/ __/ _` | '_ \| '_ \ / _ \ '__|
| |  | | (_) | (_) | (_| | |  __/      /\__/ / (_| (_| | | | | | | |  __/ |   
\_|  |_/\___/ \___/ \__,_|_|\___|      \____/ \___\__,_|_| |_|_| |_|\___|_|       
 '''

# Main Functionprint(banner)  # Print the ASCII art banner
if __name__ == "__main__":
    print(banner)  # Print the ASCII art banner
    import argparse

    parser = argparse.ArgumentParser(description="Moodle Version and Vulnerability Scanner")
    parser.add_argument("--url", type=str, help="URL of the Moodle site to check versions.")
    parser.add_argument("--update", action="store_true", help="Update local Moodle hashes.")
    parser.add_argument("--vuln", action="store_true", help="Update local Moodle vulns.")
    parser.add_argument("--scan", action="store_true", help="Scan for vulnerabilities.")
    args = parser.parse_args()

    if args.update:
        update_moodle_hashes()
    elif args.url:
        check_moodle_version(args.url, scan_vulns=args.scan)
    elif args.vuln:
         update_vulnerabilities()  
    else:
        parser.print_help()
