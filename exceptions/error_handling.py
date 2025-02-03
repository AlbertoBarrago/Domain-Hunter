"""
Custom exceptions for the project
Provides specific exceptions for the different error scenarios.
"""


class DomainAnalysisError(Exception):
    """
    Exception raised when domain resolution fails.
    """

    def __init__(self, message, error_code):
        self.message = message
        self.error = error_code
        super().__init__(self.message)


class NetworkError(DomainAnalysisError):
    """Raised when network operations fail"""


class DomainResolutionError(DomainAnalysisError):
    """Raised when domain resolution fails"""


class WhoisError(DomainAnalysisError):
    """Raised when WHOIS queries fail"""


class APIError(DomainAnalysisError):
    """Raised when API calls fail"""


class ValidationError(DomainAnalysisError):
    """Raised when input validation fails"""

class FetchError(DomainAnalysisError):
    """Raised when fetching fails"""
