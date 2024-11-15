import requests
import hashlib
import os
import re
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

    print("Fetched versions:", versions)  
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
    Compare two version strings in the format vX.Y.Z.
    Returns:
    -1 if version1 < version2,
     0 if version1 == version2,
     1 if version1 > version2.
    """
    version1_parts = version1.lstrip('v').split('.')
    version2_parts = version2.lstrip('v').split('.')
    
    # Pad the shorter version to the right with 0s if necessary (to handle cases like v4.5 vs v4.5.0)
    length = max(len(version1_parts), len(version2_parts))
    version1_parts += ['0'] * (length - len(version1_parts))
    version2_parts += ['0'] * (length - len(version2_parts))

    # Compare each part of the version number
    for v1, v2 in zip(version1_parts, version2_parts):
        if int(v1) < int(v2):
            return -1
        elif int(v1) > int(v2):
            return 1

    return 0  # Versions are equal

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
    parts1 = [int(part) for part in version1.lstrip('v').split('.')]
    parts2 = [int(part) for part in version2.lstrip('v').split('.')]
    
    for part1, part2 in zip(parts1, parts2):
        if part1 > part2:
            return 1
        elif part1 < part2:
            return -1
    
    if len(parts1) > len(parts2):
        return 1
    elif len(parts1) < len(parts2):
        return -1
    
    return 0

def compare_file_with_local_hash(file_url, file_path):
    file_hash = hashlib.md5(requests.get(file_url).content).hexdigest()
    
    with open(LOCAL_HASH_FILE, "r") as f:
        for line in f:
            stored_file, stored_hash, stored_version = line.strip().split(":")
            if stored_file == file_path and stored_hash == file_hash:
                return stored_version
    return None

def check_moodle_version(url):
    if not os.path.exists(LOCAL_HASH_FILE):
        print("Local hash file not found. Please run --update first.")
        return

    latest_versions = {file: None for file in FILE_LIST}
    
    for file_path in FILE_LIST:
        file_url = f"{url}{file_path}"
        version = compare_file_with_local_hash(file_url, file_path)
        if version:
            latest_versions[file_path] = version
    
    versions_found = [version for version in latest_versions.values() if version]

    if len(set(versions_found)) == 1:
        print(f"\033[92mIdentified version matches for all files and is {versions_found[0]}\033[0m")
    else:
        print("\033[93mThere is a mismatch in the versions.\033[0m")
        
        sorted_versions = sorted(versions_found, key=lambda v: [int(part) for part in v.lstrip('v').split('.')])
        min_version = sorted_versions[0]
        max_version = sorted_versions[-1]
        print(f"Version is between {min_version} and {max_version}")
    
    print("Latest versions found for each file:")
    for file_path, version in latest_versions.items():
        if version:
            print(f"File: {file_path}, Latest Version: {version}")
        else:
            print(f"File: {file_path}, No version found")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Moodle Version Scanner")
    parser.add_argument("--url", type=str, help="URL of the Moodle site to check versions.")
    parser.add_argument("--update", action="store_true", help="Update local Moodle hashes.")
    args = parser.parse_args()

    if args.update:
        update_moodle_hashes()
    elif args.url:
        check_moodle_version(args.url)
    else:
        parser.print_help()
