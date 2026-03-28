"""
Domains package - domain-specific implementations.

Available domains:
- login: Login authentication logs
- cicids2018: Network anomaly detection (CICIDS 2018)
- api_traffic: API request/response security classification
- agent_logs: Agent logs (template for future)
"""

__all__ = [
    "login",
    "cicids2018",
    "api_traffic",
    "agent_logs",
]
