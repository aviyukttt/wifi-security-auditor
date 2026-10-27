# Wi-Fi Security Auditor

A small, local, defensive Wi-Fi auditing tool for networks you own or are explicitly authorized to assess.

## What it does

- Performs a **read-only** nearby Wi-Fi listing through NetworkManager's `nmcli` when available.
- Shows SSID, advertised security mode, signal, and channel.
- Checks a passphrase locally for length, character variety, common-password patterns, and repetition.
- Provides a bounded scan (20 seconds) and a Stop button.

## What it intentionally does not do

This project does not brute-force passwords, guess credentials, submit passwords to a Wi-Fi dialog, attempt authentication, alter network state, or run an unbounded attack. It does not save or transmit passphrases.

## Requirements

- Python 3.10+
- Tkinter (`python3-tk` on Debian/Ubuntu)
- NetworkManager / `nmcli` for the optional read-only network listing

## Run locally

```bash
python3 wifi_auditor.py
```

On Ubuntu/Debian, if Tkinter is missing:

```bash
sudo apt install python3-tk network-manager
```

## Defensive guidance

Prefer WPA3-Personal or WPA2-AES, disable WPS, update router firmware, change default router admin credentials, use a unique 16+ character passphrase, and review connected devices in the router's admin interface.

## License

MIT. See [LICENSE](LICENSE).
