"""
MCP Server for Honeypot Detector.

Exposes token safety checking as MCP tools for AI agents.
"""

import json
from mcp.server.fastmcp import FastMCP
from honeypot_detector import HoneypotDetector, format_report

mcp = FastMCP("honeypot-detector", description="Token safety checker — detect honeypots, hidden mints, high tax, and rug pull risks")
detector = HoneypotDetector()


@mcp.tool()
def check_token_safety(chain: str, token_address: str) -> str:
    """
    Check token safety before swapping.

    Analyzes any ERC-20/BEP-20 token contract for:
    - Honeypot detection (can't sell after buy)
    - Hidden mint functions
    - Abnormal buy/sell tax
    - Blacklist functions
    - Ownership status
    - Holder distribution
    - Liquidity analysis

    Args:
        chain: Chain name (ethereum, bsc, polygon, arbitrum, optimism, base, avalanche, fantom)
        token_address: Token contract address to check

    Returns:
        Safety report with risk score and warnings
    """
    report = detector.check(chain, token_address)
    return format_report(report)


@mcp.tool()
def check_token_safety_json(chain: str, token_address: str) -> str:
    """
    Check token safety and return structured JSON data.

    Same as check_token_safety but returns JSON for programmatic use.

    Args:
        chain: Chain name (ethereum, bsc, polygon, arbitrum, optimism, base, avalanche, fantom)
        token_address: Token contract address to check

    Returns:
        JSON object with risk score, warnings, and full token data
    """
    report = detector.check(chain, token_address)
    return json.dumps(report.to_dict(), indent=2)


@mcp.tool()
def is_honeypot(chain: str, token_address: str) -> str:
    """
    Quick check: Is this token a honeypot?

    Returns a simple yes/no answer with brief explanation.

    Args:
        chain: Chain name
        token_address: Token contract address

    Returns:
        "YES" or "NO" with brief explanation
    """
    report = detector.check(chain, token_address)

    honeypot = report.details.get("is_honeypot")
    if honeypot == "1":
        return f"YES — {report.token_name} ({report.token_symbol}) is a HONEYPOT. You cannot sell after buying."

    if report.risk_score >= 80:
        return f"LIKELY YES — {report.token_name} ({report.token_symbol}) has risk score {report.risk_score}/100. Very dangerous."

    if report.risk_score >= 50:
        return f"POSSIBLY — {report.token_name} ({report.token_symbol}) has risk score {report.risk_score}/100. Be careful."

    return f"NO — {report.token_name} ({report.token_symbol}) appears safe with risk score {report.risk_score}/100."


@mcp.tool()
def get_token_tax(chain: str, token_address: str) -> str:
    """
    Get buy and sell tax for a token.

    Args:
        chain: Chain name
        token_address: Token contract address

    Returns:
        Buy and sell tax percentages
    """
    report = detector.check(chain, token_address)

    buy_tax = report.details.get("buy_tax", "0")
    sell_tax = report.details.get("sell_tax", "0")

    try:
        buy_pct = float(buy_tax) * 100
        sell_pct = float(sell_tax) * 100
    except (ValueError, TypeError):
        buy_pct = sell_pct = 0

    return f"{report.token_name} ({report.token_symbol}):\nBuy Tax: {buy_pct:.1f}%\nSell Tax: {sell_pct:.1f}%"


if __name__ == "__main__":
    mcp.run()
