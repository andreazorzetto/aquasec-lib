"""
Common utility functions for Andrea library
"""

import csv
import json
from os.path import exists


def write_content_to_file(file, content):
    """Write content to file"""
    with open(file, 'w') as f:
        f.write(content)


def write_json_to_file(file, content):
    """Write JSON content to file, appending if exists"""
    if exists(file):
        with open(file, "a") as file:
            json.dump(content, file)
            file.write('\n')
    else:
        with open(file, "w") as file:
            json.dump(content, file)
            file.write('\n')


def generate_csv_for_license_breakdown(license_breakdown, filename):
    """Generate CSV file for license breakdown data"""
    columns = ['scope', 'images', 'code', 'agents', 'kube', 'host', 'micro', 'nano', 'pod']

    with open(filename, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=columns)
        writer.writeheader()

        for key, value in license_breakdown.items():
            row = {
                'scope': value['scope name'],
                'images': value['repos'],
                'code': value.get('code_repos', 0),
                'agents': value['agent']['connected'],
                'kube': value['kube_enforcer']['connected'],
                'host': value['host_enforcer']['connected'],
                'micro': value['micro_enforcer']['connected'],
                'nano': value['nano_enforcer']['connected'],
                'pod': value['pod_enforcer']['connected']
            }
            writer.writerow(row)