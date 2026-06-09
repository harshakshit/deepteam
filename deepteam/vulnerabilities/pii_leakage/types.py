from enum import Enum
from typing import Literal


class PIILeakageType(Enum):
    DATABASE_ACCESS = "api_and_database_access"
    DIRECT = "direct_disclosure"
    SESSION_LEAK = "session_leak"
    SOCIAL_MANIPULATION = "social_manipulation"
    REDACTION_BYPASS = "redaction_bypass"


PIILeakageTypes = Literal[
    PIILeakageType.DATABASE_ACCESS.value,
    PIILeakageType.DIRECT.value,
    PIILeakageType.SESSION_LEAK.value,
    PIILeakageType.SOCIAL_MANIPULATION.value,
    PIILeakageType.REDACTION_BYPASS.value,
]
