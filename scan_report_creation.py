import json
import re
import csv
from functools import cmp_to_key

# Load the JSON data
with open('/Users/athiran/Documents/scripts/trivy_results_scan.json', 'r') as file:
    data = json.load(file)

# Define a custom version parsing function
def parse_version(v):
    if not isinstance(v, str):
        raise ValueError(f"Expected a string but got {type(v).__name__}")
    return list(map(int, re.findall(r'\d+', v)))

# Define a custom version comparison function
def custom_version_compare(v1, v2):
    p1, p2 = parse_version(v1), parse_version(v2)
    for part1, part2 in zip(p1, p2):
        if part1 != part2:
            return part1 - part2
    return len(p1) - len(p2)

# Define the function to get version info
def get_version_info(current_version, fix_versions):
    fix_versions_list = [v.strip() for v in fix_versions.split(',') if v.strip()]
    
    # Check for minor upgrades and valid upgrade options
    valid_upgrades = []
    minor_upgrade_exists = False

    for fix_version in fix_versions_list:
        comparison = custom_version_compare(fix_version, current_version)
        if comparison > 0:
            valid_upgrades.append(fix_version)
            if len(parse_version(fix_version)) >= len(parse_version(current_version)):
                minor_upgrade_exists = True

    # Sort valid upgrades
    sorted_upgrades = sorted(valid_upgrades, key=cmp_to_key(custom_version_compare))
    next_best_version = sorted_upgrades[0] if sorted_upgrades else None

    return minor_upgrade_exists, next_best_version

# Prepare scan list
scan_list = []
Image = data.get('Image')
Tag = data.get('RepoTags', [None])[0].split(':')[1]
Digest = data.get('RepoDigests', [None])[0].split('@')[1] if data.get('RepoDigests') else None

for item in data.get('Vulnerabilities', []):
    current_version = item.get('Package Version')
    fix_versions = item.get('FixedVersion') or ""
    scores = [sc for sc in item.get('CVSS Scores', []) if sc is not None]
    
    minor_upgrade_exists, next_best_version = get_version_info(current_version, fix_versions)
    item['isMinor'] = minor_upgrade_exists
    item['Score'] = sum(scores) / len(scores) if scores else 0
    item['hasFix'] = 'Y' if next_best_version else 'N'
    item['Fixed Version'] = next_best_version
    item['Image'] = 'shopizer-admin'
    item['Tag'] = Tag
    item['Digest'] = Digest

    # Clean up unnecessary fields
    item.pop('FixedVersion', None)
    item.pop('CVSS Scores', None)
    
    scan_list.append(item)

# Print results
for item in scan_list:
    print(item)

# JSON to CSV
with open('/Users/athiran/Documents/scripts/trivy_results_scan.csv', 'w', encoding='utf-8') as data_file:
    csv_writer = csv.writer(data_file)
    csv_writer.writerow(scan_list[0].keys())  # Write header
    for data in scan_list:
        csv_writer.writerow(data.values())
