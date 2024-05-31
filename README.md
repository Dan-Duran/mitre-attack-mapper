# MITRE ATT&CK Mapper

This project provides a Python script to map alert signatures to MITRE ATT&CK techniques. It uses the `mitreattack-python` library to fetch detailed information about MITRE ATT&CK techniques dynamically from the latest STIX data.

## Table of Contents

- [MITRE ATT&CK Mapper](#mitre-attck-mapper)
  - [Table of Contents](#table-of-contents)
  - [Features](#features)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Usage](#usage)
  - [File Structure](#file-structure)
  - [Example Output](#example-output)
  - [Contributing](#contributing)
  - [License](#license)

## Features

- Downloads and uses the latest MITRE ATT&CK STIX data.
- Maps alert signatures to MITRE ATT&CK techniques.
- Provides detailed information about matched techniques including description, platforms, tactics, and more.

## Prerequisites

- Python 3.6 or higher
- Internet connection to download the latest MITRE ATT&CK STIX data.

## Installation

1. **Clone the repository**:
   ```sh
   git clone https://github.com/Dan-Duran/mitre-attack-mapper.git
   cd mitre-attack-mapper
   ```
   - This will clone the repository from GitHub and navigate into the project directory.

2. **Create and activate a virtual environment**:

   ### Linux/Mac
   ```sh
   python3 -m venv venv
   source venv/bin/activate
   ```
   - This will create a virtual environment and activate it on Linux or Mac.

   ### Windows
   ```sh
   py<or python> -m venv venv 
   venv\Scripts\activate
   ```
   - This will create a virtual environment and activate it on Windows.

3. **Install the required packages**:
   ```sh
   pip install -r requirements.txt
   ```
   - This will install the necessary packages listed in `requirements.txt`.

## Usage

1. **Run the script**:
   ```sh
   python mitre.py
   ```
   - This command starts the script.

2. **Enter the alert signature when prompted**:
   ```
   Enter the alert signature:
   ```
   - The user is prompted to input an alert signature.

3. **View the detailed information about the matched MITRE ATT&CK techniques**.
   - The script will output the matched techniques to the console and also save them to a file in the `output` directory.

## File Structure

```
MITRE-ATTACK-MAPPER/
│
├── mitre.py                Main entry point for the script
├── requirements.txt        List of dependencies
├── README.md               Project documentation
├── venv/                   Virtual environment directory (created during installation)
└── output/                 Directory for output files (will be created by the script if it doesn't exist)
```

## Example Output

```
STIX data is up-to-date. No download needed.
Enter the alert signature:
ATTACK [PTsecurity] log4j RCE aka Log4Shell attempt (CVE-2021-44228)
Entered Signature: attack [ptsecurity] log4j rce aka log4shell attempt (cve-2021-44228)
Matched MITRE Techniques:

Technique ID: T1210
Name: Exploit Public-Facing Application
Description: Adversaries may attempt to exploit public-facing applications.
URL: https://attack.mitre.org/techniques/T1210/

Technique ID: T1190
Name: Exploit Public-Facing Application
Description: Adversaries may attempt to exploit public-facing applications.
URL: https://attack.mitre.org/techniques/T1190/

Results written to output/result_20240531_090117.txt
```

## Contributing

We welcome contributions!

## License

This project is licensed under the MIT License.
