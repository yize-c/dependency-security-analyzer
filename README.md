# Dependency Security Analyzer

Developing a lightweight CLI tool that analyzes software dependencies, identifies outdated packages, and assesses potential security risks.


## Setup

```bash
pip install -r requirements-dev.txt
```

## Usage

```bash
python main.py --file requirements.txt --output text   # or json / csv
```

## Running tests

```bash
pytest
```

Unit tests cover the requirements parser, CVSS parsing and severity bands (boundary values), risk scoring, recommendations and CSV export. The OSV API is mocked, so tests run offline.
