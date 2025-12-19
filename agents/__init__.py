"""
Agents package for Salesforce Security Analyzer
Contains core logic for API interactions and analysis
"""

from .salesforce_client import SalesforceOAuthClient
from .codegen_analyzer import CodeGenSecurityAnalyzer, HybridAnalyzer

__all__ = [
    'SalesforceClient',
    'CodeGenSecurityAnalyzer',
    'HybridAnalyzer'
]

__version__ = '1.0.0'