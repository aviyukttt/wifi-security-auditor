# Wi-Fi Security Auditor

> A local, read-only companion for checking Wi-Fi security posture—without guessing passwords or touching network authentication.

[![Tests](https://github.com/aviyukttt/wifi-security-auditor/actions/workflows/test.yml/badge.svg)](https://github.com/aviyukttt/wifi-security-auditor/actions/workflows/test.yml)

Wi-Fi Security Auditor helps owners perform two safe checks from one lightweight desktop app: inspect nearby networks using NetworkManager's read-only listing and review a passphrase locally for common weakness signals.

## What it does

- Lists nearby networks with SSID, advertised security mode, signal, and channel.
- Assesses a passphrase locally for length, character variety, common-password patterns, and repetition.
- Keeps password input in memory only; it is not logged, saved, hashed, or transmitted.
- Uses a bounded scan with a clear Stop button.
- Ships with unit tests and a GitHub Actions test workflow.

## Safety boundary

This is a defensive auditing tool for networks you own or are explicitly authorized to assess. It intentionally does **not** brute-force passwords, guess credentials, submit passwords to Wi-Fi dialogs, attempt authentication, alter network state, or run an unbounded attack.

## Quick start

### Requirements

- Python 3.10+
- Tkinter (`python3-tk` on Debian/Ubuntu)
- NetworkManager / `nmcli` for optional nearby-network discovery

### Run

```bash
python3 wifi_auditor.py
```

On Ubuntu/Debian:

```bash
sudo apt install python3-tk network-manager
```

### Test

```bash
python3 -m unittest -v
```

## Recommended hardening

Prefer WPA3-Personal or WPA2-AES, disable WPS, keep router firmware current, change default router-admin credentials, use a unique 16+ character passphrase, and review the router's connected-device list regularly.

## Project layout

| File | Purpose |
| --- | --- |
| `wifi_auditor.py` | Tkinter desktop interface and read-only `nmcli` scan |
| `wifi_core.py` | Dependency-free local passphrase assessment logic |
| `test_wifi_auditor.py` | Unit tests |
| `.github/workflows/test.yml` | Continuous integration |

## Related project

Built alongside [Legal Sathi](https://github.com/aviyukttt/legalsaathi), a plain-language legal document assistant.

## License

MIT. See [LICENSE](LICENSE).
