# Startup and Usage Guide: Running a Partial Scan

This guide explains how to use the Firewall Compliance Analyzer CLI to run a "partial scan" on the provided `panos-random-100rules.xml` file. The partial scan is designed to quickly test the analysis pipeline by parsing the file but only processing the **first 20 rules**.

## Prerequisites

1. **Python Environment**: Ensure you have Python installed and your virtual environment activated.
2. **Dependencies**: Make sure you have installed all required dependencies for the project (e.g., `fastapi`, `click`, `sqlalchemy`, and any vendor-specific parsers).
   ```bash
   pip install -r requirements.txt
   ```
3. **Environment Variables**: Depending on your LLM configuration for the `analyze_rules_intent` module, ensure you have exported any required API keys (e.g., `OPENAI_API_KEY`).
   ```bash
   # Example for Windows (PowerShell)
   $env:OPENAI_API_KEY="your-api-key-here"
   ```

## Running the Partial Scan

The CLI is located in `src/main.py`. Since `click` automatically converts function names with underscores (`partial_scan`) to hyphens, the command you will use is `partial-scan`.

To run the partial scan on the `panos-random-100rules.xml` file with default settings, run the following command from the root of your workspace:

```bash
python src/main.py partial-scan --file panos-random-100rules.xml
```

### What happens during the scan?
1. **Parsing**: The tool reads the `panos-random-100rules.xml` using the Palo Alto parser.
2. **Truncation**: It limits the dataset to exactly the first 20 rules.
3. **Analysis**:
   - **Comprehensive Analysis**: Checks for SMT & path violations.
   - **Anomaly Detection**: Looks for shadowing, redundancy, and collisions.
   - **Intent Analysis**: Analyzes rule intent and risk using LLM.
4. **Persistence**: Saves the 20 rules and any found issues to the local database.
5. **Reporting**: Generates a structured JSON report and saves it to the `reports/` directory.

## Optional Parameters

You can customize the partial scan using several optional flags:

- `--vendor`: Specifies the firewall vendor parser to use. Defaults to `paloalto`.
  ```bash
  python src/main.py partial-scan --file panos-random-100rules.xml --vendor paloalto
  ```

- `--top`: The number of top rules to include in the policy hardening plan. Defaults to `10`.
  ```bash
  python src/main.py partial-scan --file panos-random-100rules.xml --top 5
  ```

- `--threshold`: The risk score threshold (0-100) for identifying "high-risk" rules. Defaults to `70`.
  ```bash
  python src/main.py partial-scan --file panos-random-100rules.xml --threshold 80
  ```

- `--output`: The directory where the JSON report will be saved. Defaults to `reports`.
  ```bash
  python src/main.py partial-scan --file panos-random-100rules.xml --output custom_reports_dir
  ```

### Example: Custom Scan

To run a scan that flags rules with a risk score over 85, generates a top-5 hardening plan, and saves it to a custom folder:

```bash
python src/main.py partial-scan --file panos-random-100rules.xml --threshold 85 --top 5 --output my_test_reports
```

## Expected Output

Once the scan completes successfully, you will see output similar to this in your terminal:

```text
Success! Partial scan JSON report saved to: reports\partial_scan_report_20260521_123456.json

--- Report Preview ---
{
  "timestamp": "2026-05-21T12:34:56.789012",
  "target_file": "panos-random-100rules.xml",
  "vendor": "paloalto",
  "total_rules_parsed": 20,
  "scan_type": "partial_scan"
}
```

You can then open the generated JSON file in the `reports/` directory to view the detailed findings, including basic anomalies, comprehensive issues, and the suggested hardening plan.
