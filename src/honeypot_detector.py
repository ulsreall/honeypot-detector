"""
Honeypot Detector — Check token safety before you swap.

Uses GoPlus Security API to detect:
- Honeypot (can't sell after buy)
- Hidden mint functions
- Abnormal buy/sell tax
- Blacklist functions
- Ownership status
- Holder concentration
- Liquidity analysis
"""

import argparse
import json
import sys
from dataclasses import dataclass, field
from typing import Optional

import requests

# GoPlus Security API
GOPLUS_API = "https://api.gopluslabs.io/api/v1/token_security/{chain_id}"

# Chain name to ID mapping
CHAIN_IDS = {
    "ethereum": 1,
    "eth": 1,
    "bsc": 56,
    "bnb": 56,
    "polygon": 137,
    "matic": 137,
    "arbitrum": 42161,
    "arb": 42161,
    "optimism": 10,
    "op": 10,
    "base": 8453,
    "avalanche": 43114,
    "avax": 43114,
    "fantom": 250,
    "ftm": 250,
    "solana": 900,
    "sol": 900,
}


@dataclass
class TokenReport:
    """Token safety analysis report."""

    token_address: str
    chain: str
    chain_id: int
    token_name: str = ""
    token_symbol: str = ""
    is_safe: bool = True
    risk_score: int = 0
    warnings: list = field(default_factory=list)
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "token_address": self.token_address,
            "chain": self.chain,
            "chain_id": self.chain_id,
            "token_name": self.token_name,
            "token_symbol": self.token_symbol,
            "is_safe": self.is_safe,
            "risk_score": self.risk_score,
            "warnings": self.warnings,
            "details": self.details,
        }


class HoneypotDetector:
    """Token safety checker using GoPlus Security API."""

    def __init__(self, timeout: int = 15):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "HoneypotDetector/1.0",
        })

    def check(self, chain: str, token_address: str) -> TokenReport:
        """
        Check token safety.

        Args:
            chain: Chain name (ethereum, bsc, polygon, etc.)
            token_address: Token contract address

        Returns:
            TokenReport with safety analysis
        """
        chain = chain.lower().strip()
        chain_id = CHAIN_IDS.get(chain)
        if not chain_id:
            return TokenReport(
                token_address=token_address,
                chain=chain,
                chain_id=0,
                is_safe=False,
                risk_score=100,
                warnings=[f"Unsupported chain: {chain}"],
            )

        # Query GoPlus API
        try:
            url = GOPLUS_API.format(chain_id=chain_id)
            resp = self.session.get(
                url,
                params={
                    "contract_addresses": token_address.lower(),
                },
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as e:
            return TokenReport(
                token_address=token_address,
                chain=chain,
                chain_id=chain_id,
                is_safe=False,
                risk_score=100,
                warnings=[f"API error: {str(e)}"],
            )

        # Parse response
        if data.get("code") != 1 or not data.get("result"):
            return TokenReport(
                token_address=token_address,
                chain=chain,
                chain_id=chain_id,
                is_safe=False,
                risk_score=100,
                warnings=["Token not found or API error"],
                details=data,
            )

        result = data["result"]
        token_data = result.get(token_address.lower(), result.get(list(result.keys())[0], {}))

        if not token_data:
            return TokenReport(
                token_address=token_address,
                chain=chain,
                chain_id=chain_id,
                is_safe=False,
                risk_score=100,
                warnings=["No data returned for this token"],
                details=data,
            )

        # Build report
        report = TokenReport(
            token_address=token_address,
            chain=chain,
            chain_id=chain_id,
            token_name=token_data.get("token_name", "Unknown"),
            token_symbol=token_data.get("token_symbol", "???"),
            details=token_data,
        )

        # Analyze risks
        self._analyze_honeypot(report, token_data)
        self._analyze_mint(report, token_data)
        self._analyze_tax(report, token_data)
        self._analyze_blacklist(report, token_data)
        self._analyze_ownership(report, token_data)
        self._analyze_holders(report, token_data)
        self._analyze_liquidity(report, token_data)
        self._analyze_contract(report, token_data)

        # Calculate final risk score
        report.is_safe = report.risk_score < 50

        return report

    def _analyze_honeypot(self, report: TokenReport, data: dict):
        """Check for honeypot indicators."""
        is_honeypot = data.get("is_honeypot")
        if is_honeypot == "1":
            report.risk_score += 50
            report.warnings.append("🚨 HONEYPOT DETECTED — Cannot sell after buy")

        # Check buy/sell simulation
        buy_tax = data.get("buy_tax")
        sell_tax = data.get("sell_tax")
        if buy_tax == "1" and sell_tax == "1":
            report.risk_score += 30
            report.warnings.append("🚨 Both buy and sell tax are 100% — Likely honeypot")

    def _analyze_mint(self, report: TokenReport, data: dict):
        """Check for hidden mint functions."""
        is_mintable = data.get("is_mintable")
        if is_mintable == "1":
            report.risk_score += 25
            report.warnings.append("⚠️ HIDDEN MINT — Owner can create unlimited tokens")

    def _analyze_tax(self, report: TokenReport, data: dict):
        """Check buy/sell tax."""
        buy_tax = data.get("buy_tax", "0")
        sell_tax = data.get("sell_tax", "0")

        try:
            buy_tax_pct = float(buy_tax) * 100
            sell_tax_pct = float(sell_tax) * 100
        except (ValueError, TypeError):
            buy_tax_pct = 0
            sell_tax_pct = 0

        if buy_tax_pct > 10:
            report.risk_score += 15
            report.warnings.append(f"⚠️ HIGH BUY TAX — {buy_tax_pct:.1f}%")
        elif buy_tax_pct > 5:
            report.risk_score += 5
            report.warnings.append(f"⚠️ Elevated buy tax: {buy_tax_pct:.1f}%")

        if sell_tax_pct > 10:
            report.risk_score += 20
            report.warnings.append(f"🚨 HIGH SELL TAX — {sell_tax_pct:.1f}%")
        elif sell_tax_pct > 5:
            report.risk_score += 8
            report.warnings.append(f"⚠️ Elevated sell tax: {sell_tax_pct:.1f}%")

    def _analyze_blacklist(self, report: TokenReport, data: dict):
        """Check for blacklist functions."""
        is_blacklisted = data.get("is_blacklisted")
        if is_blacklisted == "1":
            report.risk_score += 20
            report.warnings.append("🚨 BLACKLIST — Owner can block specific wallets")

        # Check trading cooldown
        trading_cooldown = data.get("trading_cooldown")
        if trading_cooldown == "1":
            report.risk_score += 10
            report.warnings.append("⚠️ TRADING COOLDOWN — Forced delay between trades")

    def _analyze_ownership(self, report: TokenReport, data: dict):
        """Check contract ownership."""
        owner = data.get("owner_address")
        renounced = data.get("owner_change_balance")

        if owner and owner != "0x0000000000000000000000000000000000000000":
            if renounced == "1":
                report.risk_score += 5
                report.warnings.append("⚠️ Owner can change balance")

        # Check if self-destruct is possible
        selfdestruct = data.get("selfdestruct")
        if selfdestruct == "1":
            report.risk_score += 15
            report.warnings.append("⚠️ SELF-DESTRUCT — Contract can be destroyed")

    def _analyze_holders(self, report: TokenReport, data: dict):
        """Check holder distribution."""
        holder_count = data.get("holder_count", "0")
        top_10_rate = data.get("top_10_holder_rate", "0")

        try:
            holders = int(holder_count)
            top_10_pct = float(top_10_rate) * 100
        except (ValueError, TypeError):
            holders = 0
            top_10_pct = 0

        if holders < 100:
            report.risk_score += 10
            report.warnings.append(f"⚠️ Low holder count: {holders}")

        if top_10_pct > 80:
            report.risk_score += 15
            report.warnings.append(f"🚨 WHALE CONCENTRATION — Top 10 hold {top_10_pct:.1f}%")
        elif top_10_pct > 50:
            report.risk_score += 5
            report.warnings.append(f"⚠️ Top 10 holders own {top_10_pct:.1f}%")

    def _analyze_liquidity(self, report: TokenReport, data: dict):
        """Check liquidity."""
        lp_total_supply = data.get("lp_total_supply", "0")
        lp_holders = data.get("lp_holder_count", "0")

        try:
            lp_supply = float(lp_total_supply)
        except (ValueError, TypeError):
            lp_supply = 0

        if lp_supply == 0:
            report.risk_score += 15
            report.warnings.append("⚠️ No liquidity pool found")

        # Check if LP is locked
        lp_locked = data.get("is_lp_token_lock")
        if lp_locked == "0" and lp_supply > 0:
            report.risk_score += 10
            report.warnings.append("⚠️ LP tokens not locked — Rug pull risk")

    def _analyze_contract(self, report: TokenReport, data: dict):
        """Check contract code."""
        is_proxy = data.get("is_proxy")
        if is_proxy == "1":
            report.risk_score += 5
            report.warnings.append("ℹ️ Proxy contract — Logic can be upgraded")

        is_open_source = data.get("is_open_source")
        if is_open_source == "0":
            report.risk_score += 10
            report.warnings.append("⚠️ Contract NOT open source — Cannot verify logic")


def format_report(report: TokenReport) -> str:
    """Format report for terminal output."""
    lines = []

    # Header
    risk_emoji = "🟢" if report.risk_score < 20 else "🟡" if report.risk_score < 50 else "🔴" if report.risk_score < 80 else "☠️"
    lines.append(f"Token: {report.token_name} ({report.token_symbol})")
    lines.append(f"Chain: {report.chain.title()} (ID: {report.chain_id})")
    lines.append(f"Contract: {report.token_address}")
    lines.append(f"Risk Score: {report.risk_score}/100 {risk_emoji}")
    lines.append("")

    # Tax info
    buy_tax = report.details.get("buy_tax", "0")
    sell_tax = report.details.get("sell_tax", "0")
    try:
        buy_pct = float(buy_tax) * 100
        sell_pct = float(sell_tax) * 100
    except (ValueError, TypeError):
        buy_pct = sell_pct = 0

    lines.append(f"Buy Tax: {buy_pct:.1f}%")
    lines.append(f"Sell Tax: {sell_pct:.1f}%")
    lines.append("")

    # Warnings
    if report.warnings:
        lines.append("Warnings:")
        for w in report.warnings:
            lines.append(f"  {w}")
    else:
        lines.append("✅ No warnings — Token appears safe")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Check token safety before you swap — detect honeypots, hidden mints, high tax, and more."
    )
    parser.add_argument(
        "--chain", "-c",
        required=True,
        help="Chain name (ethereum, bsc, polygon, arbitrum, optimism, base, etc.)",
    )
    parser.add_argument(
        "--token", "-t",
        required=True,
        help="Token contract address",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output as JSON",
    )

    args = parser.parse_args()

    detector = HoneypotDetector()
    report = detector.check(args.chain, args.token)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(format_report(report))

    # Exit code based on risk
    sys.exit(0 if report.is_safe else 1)


if __name__ == "__main__":
    main()
