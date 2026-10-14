# CyberScope V4 - Authorized Web Security Assessment Tool

A desktop (PySide6) tool that runs **safe, passive, non-destructive** checks against websites you own or have
explicit permission to test, and produces evidence-based findings with severity, confidence, remediation and
JSON/Markdown reports. No cloud services, API keys or web server needed.

> **Only scan systems you are authorized to test.** The app enforces an allowlist, but the legal responsibility is yours.

## Requirements
* Python **3.11+** (3.12 tested), pip, internet access only for the initial `pip install`.
* Windows 10/11 or Kali Linux (any recent Debian-based Linux works).

## Install and launch

### Windows (PowerShell or Command Prompt)
```bat
:: 1. Right-click CyberScope_V4.zip > Extract All...  then:
cd C:\path\to\CyberScope_V4
python -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python main.py
```
Shortcut: double-click `scripts\run_windows.bat` (creates the venv on first run).
PowerShell blocks activation? Run once: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, or use Command Prompt.

### Kali Linux
```bash
sudo apt update && sudo apt install -y python3 python3-venv python3-pip libegl1 libxkbcommon-x11-0 libxcb-cursor0
unzip CyberScope_V4.zip && cd CyberScope_V4
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
python main.py
```
Shortcut: `chmod +x scripts/run_kali.sh && ./scripts/run_kali.sh`

## Using CyberScope
1. **Authorize a target** - open *New Scan*, type `example.com` (or an https URL). The *Final target* line shows exactly what will
   be scanned. Click *Add this target to authorized list* and confirm. Matching is **exact**: `example.com` does not
   authorize `www.example.com`; add each host separately.
2. **Run a scan** - tick the authorization checkbox, keep the default checks (safe profile), press *Start scan*. Progress,
   the current check and messages are shown live; *Cancel scan* stops it after the in-flight request.
3. **Read findings** - the *Findings* page lists results. Click a row for details. Each finding is labelled:
   * **Observation** - a fact (e.g. "resolved to 1.2.3.4").
   * **Confirmed misconfiguration** - directly observed setting that deviates from best practice (e.g. cookie without `Secure`).
   * **Potential concern** - needs human judgment; the evidence does not prove exploitability.

   *Severity* (Informational-Critical) is impact-based; *Confidence* (High/Medium/Low) is how sure the tool is that the observation is accurate.
   They are independent. High/Critical are never assigned automatically because passive checks cannot demonstrate exploitation.
4. **Triage** - set a *Validation* state (Observed, Needs Review, Not Reproduced, False Positive, Accepted Risk) and a note, then *Save validation*.
5. **Export** - *Export JSON* / *Export Markdown*, choose a destination. Cookie values and secrets are never included.

Headless option: `python main.py --cli example.com --confirm-authorized --json out.json --markdown out.md`

## Automated tests
```bash
python -m unittest discover -s tests -t . -v      # standard library only
pytest                                            # optional, if pytest is installed
```
Tests use mocked responses and a throw-away server on `127.0.0.1`; they never contact external sites.
The PySide6 GUI itself is not covered by automated tests.

## Where data lives
`%APPDATA%\CyberScope` (Windows) or `~/.cyberscope` (Linux): `cyberscope.db`, `settings.json`, `logs/cyberscope.log`.
Override with the `CYBERSCOPE_HOME` environment variable.

## Troubleshooting
| Problem | Fix |
|---|---|
| `ModuleNotFoundError: PySide6` | Activate the venv, then `pip install -r requirements.txt`. |
| Kali: `qt.qpa.plugin: Could not load the Qt platform plugin "xcb"` | `sudo apt install libxcb-cursor0 libxkbcommon-x11-0 libegl1` |
| Python too old | Install Python 3.11+ (python.org on Windows; `sudo apt install python3` on Kali). |
| Every HTTPS site shows "chain not trusted" | Your OS trust store/corporate TLS inspection; certificate verification is never disabled. |
| "Target not authorized" | Add the exact host to the allowlist on *New Scan*. |
| Many "check incomplete" notes | Timeouts/blocking; raise the timeout in *Settings* or retry later. Timeouts are not findings. |
| Database damaged | The app moves the bad file aside (`*.corrupt-*`) and creates a new one. |
| Details of an error | See `logs/cyberscope.log` (secrets are redacted). |

## Optional Windows executable
`scripts\build_windows_exe.bat` (needs PyInstaller; must be run on Windows). Not required to use the source project.

See `docs/USER_GUIDE.md` and `docs/SECURITY.md`.

## CyberScope V5 additions

See `V5_README.md` for the conservative SQLi signal-check module, scope requirements, and JSON/Markdown reporting.


## V5 expanded checks
See `V5_EXPANDED_README.md` for added conservative recon modules and manual review templates.
