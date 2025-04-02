import json
import csv
import sys

#!/usr/bin/env python3

def json_to_csv(json_file, csv_file):
    # Read JSON data
    with open(json_file, 'r') as f:
        data = json.load(f)
    
    # Write CSV data
    with open(csv_file, 'w', newline='') as f:
        writer = csv.writer(f)
        # Write header
        writer.writerow(['OSV ID', 'Base', 'Buggy'])
        # Write rows
        for osv_id, values in data.items():
            writer.writerow([osv_id, values.get('base', ''), values.get('buggy', '')])

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input_json> <output_csv>")
        sys.exit(1)
    
    json_file = sys.argv[1]
    csv_file = sys.argv[2]
    
    json_to_csv(json_file, csv_file)
    print(f"Converted {json_file} to {csv_file}")

if __name__ == "__main__":
    main()