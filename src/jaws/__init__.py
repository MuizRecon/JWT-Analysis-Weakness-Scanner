"""J.A.W.S. - JWT Analysis & Weakness Scanner."""

__version__ = "1.0.0"

from .decoder import decode_token, is_token_valid_structure
from .auditor import JWTAuditor
from .cracker import HMACCracker
from .models import DecodedToken, Finding, Severity, AnalysisResult
