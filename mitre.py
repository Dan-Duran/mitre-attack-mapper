import json
import os
import requests
from fuzzywuzzy import process
from mitreattack.stix20 import MitreAttackData

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
    """Prompt the user to enter the signature manually."""
    print("Enter the alert signature:")
    signature = input().strip().lower()
    return signature

def find_mitre_techniques(signature, techniques_db):
    """Find corresponding MITRE techniques using fuzzy matching."""
    best_match = process.extractOne(signature, techniques_db.keys(), score_cutoff=75)
    if best_match:
        return techniques_db[best_match[0]]
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

def main():
    # Prompt the user to enter the signature manually
    signature = extract_signature_from_input()
    if signature:
        print(f"Entered Signature: {signature}")
        # Find the corresponding MITRE techniques
        technique_ids = find_mitre_techniques(signature, signature_to_mitre)
        if not technique_ids:
            print("No matching MITRE techniques found.")
            return

        # Fetch detailed information for each matched technique
        techniques = fetch_technique_details(technique_ids)
        
        if techniques:
            print("Matched MITRE Techniques:")
            for technique in techniques:
                print(f"\nTechnique ID: {technique['external_references'][0]['external_id']}")
                print(f"Name: {technique['name']}")
                description = technique.get('description', 'No description available')
                print(f"Description: {description[:400]}")  # Truncate description to 400 characters
                print(f"URL: {technique['external_references'][0]['url']}")
                if 'x_mitre_platforms' in technique:
                    print(f"Platforms: {', '.join(technique['x_mitre_platforms'])}")
                if 'x_mitre_tactic_type' in technique:
                    print(f"Tactic: {', '.join(technique['x_mitre_tactic_type'])}")
                if 'created' in technique:
                    print(f"Created: {technique['created']}")
                if 'modified' in technique:
                    print(f"Last Modified: {technique['modified']}")
        else:
            print("No detailed information found for the matched techniques.")

if __name__ == "__main__":
    main()
