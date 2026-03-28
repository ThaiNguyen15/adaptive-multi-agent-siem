"""
Domains package - domain-specific implementations.

Available domains:
- login: Login authentication logs
- cicids2018: Network anomaly detection (CICIDS 2018)
- brute_force_https: CESNET HTTPS brute-force detection
- api_traffic: API request/response security classification
- agent_logs: Agent logs (template for future)
"""

__all__ = [
    "login",
    "cicids2018",
    "brute_force_https",
    "api_traffic",
    "agent_logs",
]
