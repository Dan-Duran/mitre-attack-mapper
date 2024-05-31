import json
import os
import re
import requests
from fuzzywuzzy import process
from mitreattack.stix20 import MitreAttackData
from datetime import datetime

# URL to the latest MITRE ATT&CK STIX data
stix_url = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json'
stix_file_path = 'enterprise-attack.json'

def download_stix_file(url, filepath):
    """Download the STIX file if it doesn't exist or is outdated."""
    response = requests.get(url)
    response.raise_for_status()  # Ensure we notice bad responses
    new_stix_data = response.json()
    
    if os.path.exists(filepath):
        with open(filepath, 'r') as file:
            current_stix_data = json.load(file)
        if current_stix_data == new_stix_data:
            print("STIX data is up-to-date. No download needed.")
            return False

    # Write the new data to the file
    with open(filepath, 'w') as file:
        json.dump(new_stix_data, file)
    print("Downloaded and updated the STIX data.")
    return True

# Download the STIX file if necessary
stix_updated = download_stix_file(stix_url, stix_file_path)

attack = None

def initialize_attack_data():
    global attack
    if attack is None:
        attack = MitreAttackData(stix_filepath=stix_file_path)

# Example mapping of signatures to MITRE ATT&CK techniques
# This dictionary should be maintained separately and updated as needed
signature_to_mitre = {
    "ATTACK [PTsecurity] log4j RCE aka Log4Shell attempt (CVE-2021-44228)": ["T1210", "T1190"],
    "TGI HUNT PowerShell Execution String Base64 Encoded New-Object (V3LU9)": ["T1086"],
    # Add more mappings here as needed
}

def extract_signature_from_input():
    """Prompt the user to enter the signature manually and clean it."""
    print("Enter the alert signature:")
    signature = input().strip()
    # Correctly remove content inside square brackets including the brackets
    signature = re.sub(r'\[.*?\]', '', signature)
    return signature.strip()

def clean_signature(signature):
    """Remove special characters from a signature."""
    return re.sub(r'[^\w\s]', '', signature)

def find_mitre_techniques(signature, techniques_db):
    """Find corresponding MITRE techniques using fuzzy matching."""
    cleaned_techniques_db = {clean_signature(k): v for k, v in techniques_db.items()}
    best_match = process.extractOne(signature, cleaned_techniques_db.keys(), score_cutoff=75)
    if best_match:
        return cleaned_techniques_db[best_match[0]]
    else:
        return []

def fetch_technique_details(technique_ids):
    """Fetch detailed information for each MITRE technique."""
    initialize_attack_data()
    techniques = []
    for technique_id in technique_ids:
        technique = attack.get_object_by_attack_id(technique_id, stix_type='attack-pattern')
        if technique:
            techniques.append(technique)
    return techniques

def write_output_to_file(output):
    """Write the output to a timestamped text file in the output directory."""
    if not os.path.exists('output'):
        os.makedirs('output')
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f'output/result_{timestamp}.txt'
    with open(filename, 'w') as file:
        file.write(output)
    print(f"Results written to {filename}")

def main_menu():
    while True:
        print("\nMain Menu")
        print("1. Enter the alert signature")
        print("2. Exit")
        choice = input("Enter your choice: ").strip()
        
        if choice == '1':
            process_alert_signature()
        elif choice == '2':
            print("Exiting the application.")
            break
        else:
            print("Invalid choice. Please enter 1 or 2.")

def process_alert_signature():
    # Prompt the user to enter the signature manually
    signature = extract_signature_from_input()
    if signature:
        output = ""
        output += f"Entered Signature: {signature}\n"
        # Find the corresponding MITRE techniques
        technique_ids = find_mitre_techniques(signature, signature_to_mitre)
        if not technique_ids:
            output += "No matching MITRE techniques found.\n"
            print(output)
            write_output_to_file(output)
            return

        # Fetch detailed information for each matched technique
        techniques = fetch_technique_details(technique_ids)
        
        if techniques:
            output += "Matched MITRE Techniques:\n"
            for technique in techniques:
                output += f"\nTechnique ID: {technique['external_references'][0]['external_id']}\n"
                output += f"Name: {technique['name']}\n"
                description = technique.get('description', 'No description available')
                output += f"Description: {description[:400]}\n"  # Truncate description to 400 characters
                output += f"URL: {technique['external_references'][0]['url']}\n"
                if 'x_mitre_platforms' in technique:
                    output += f"Platforms: {', '.join(technique['x_mitre_platforms'])}\n"
                if 'x_mitre_tactic_type' in technique:
                    output += f"Tactic: {', '.join(technique['x_mitre_tactic_type'])}\n"
                if 'created' in technique:
                    output += f"Created: {technique['created']}\n"
                if 'modified' in technique:
                    output += f"Last Modified: {technique['modified']}\n"
            print(output)
            write_output_to_file(output)
        else:
            output += "No detailed information found for the matched techniques.\n"
            print(output)
            write_output_to_file(output)

if __name__ == "__main__":
    main_menu()
