# net2008-pa2: Fleet Compliance Auditor

Audits an XML device inventory against a YAML compliance policy.

1. Install the one dependency: `pip install pyyaml`
2. Run: `python pa2.py DEVICES.xml POLICY.yaml`
3. On Linux or macOS use `python3` if `python` is not found.
4. The report is written to `audit.json` in the current folder.
5. Exit codes: 0 ok, 1 bad input file, 2 wrong number of arguments.