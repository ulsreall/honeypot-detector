---
name: honeypot-detector
description: "Check token safety before you swap — detect honeypots, hidden mints, high tax, blacklist functions, and rug pull risks using GoPlus Security API."
version: 1.0.0
metadata:
  openclaw:
    tags:
    - security
    - defi
    - token-safety
    source: "https://github.com/ulsreall/honeypot-detector"
---

# Honeypot Detector

Check token safety before you swap — detect honeypots, hidden mints, high tax, blacklist functions, and rug pull risks.

## What It Does

Analyzes any ERC-20/BEP-20 token contract and returns a safety report:

- **Honeypot Detection** — Can you sell after buying?
- **Hidden Mint** — Can the owner create unlimited tokens?
- **Buy/Sell Tax** — Is the tax abnormally high (>10%)?
- **Blacklist Function** — Can the owner block your wallet?
- **Ownership Renounced** — Is the contract still owned?
- **Holder Distribution** — Are top holders too concentrated?
- **Liquidity Analysis** — Is liquidity locked? How much?

## API

Uses [GoPlus Security API](https://docs.gopluslabs.io/) (free, no key required).

### Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/token_security/{chain_id}?contract_addresses={address}` | Full token security check |

### Supported Chains

| Chain | ID |
|-------|-----|
| Ethereum | 1 |
| BSC | 56 |
| Polygon | 137 |
| Arbitrum | 42161 |
| Optimism | 10 |
| Base | 8453 |
| Avalanche | 43114 |
| Fantom | 250 |
| Solana | 900 |

## Usage

### CLI

```bash
# Check a token on Ethereum
python src/honeypot_detector.py --chain ethereum --token 0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984

# Check a token on BSC
python src/honeypot_detector.py --chain bsc --token 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c

# JSON output
python src/honeypot_detector.py --chain ethereum --token 0x... --json
```

### Python

```python
from src.honeypot_detector import HoneypotDetector

detector = HoneypotDetector()
report = detector.check("ethereum", "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984")

print(report.is_safe)        # True/False
print(report.risk_score)      # 0-100
print(report.warnings)        # List of warnings
print(report.details)         # Full API response
```

### MCP Server

```bash
# Run as MCP server
python src/mcp_server.py
```

## Risk Score

| Score | Level | Action |
|-------|-------|--------|
| 0-20 | 🟢 Safe | Likely safe to trade |
| 21-50 | 🟡 Caution | Do your own research |
| 51-80 | 🔴 High Risk | Be very careful |
| 81-100 | ☠️ Danger | Likely scam/honeypot |

## Examples

### Safe Token (UNI)
```
Token: Uniswap (UNI)
Chain: Ethereum
Risk Score: 12/100 🟢

✅ Honeypot: No
✅ Hidden Mint: No
✅ Buy Tax: 0%
✅ Sell Tax: 0%
✅ Blacklist: No
✅ Ownership: Renounced
✅ Liquidity: Sufficient
```

### Honeypot Detected
```
Token: SafeMoon2.0 (SCAM)
Chain: BSC
Risk Score: 95/100 ☠️

🚨 HONEYPOT DETECTED — Cannot sell after buy
🚨 Hidden Mint: Yes — Owner can create tokens
🚨 Buy Tax: 15%
🚨 Sell Tax: 99%
🚨 Blacklist: Yes — Owner can block wallets
🚨 Ownership: Not renounced
🚨 Liquidity: Not locked
```

## Installation

```bash
pip install -r requirements.txt
```

## License

MIT
