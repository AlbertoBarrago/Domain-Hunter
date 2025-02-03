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
    def __init__(self, message, error_code):
        super().__init__(message, error_code)
        self.whois_server = None

    def set_whois_server(self, server):
        """Set the WHOIS server for the error"""
        self.whois_server = server

    def get_error_details(self):
        """Get error details"""
        return {
            'message': self.message,
            'code': self.error,
            'whois_server': self.whois_server
        }


class APIError(DomainAnalysisError):
    """Raised when API calls fail"""


class ValidationError(DomainAnalysisError):
    """Raised when input validation fails"""

class FetchError(DomainAnalysisError):
    """Raised when fetching fails"""
