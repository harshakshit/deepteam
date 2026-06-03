from enum import Enum
from typing import Literal


class SystemReconnaissanceType(Enum):
    FILE_METADATA = "file_metadata"
    DATABASE_SCHEMA = "database_schema"
    RETRIEVAL_CONFIG = "retrieval_config"
    MODEL_FINGERPRINTING = "model_fingerprinting"
    TOOL_ENUMERATION = "tool_enumeration"
    INFRASTRUCTURE_FINGERPRINTING = "infrastructure_fingerprinting"


SystemReconnaissanceTypes = Literal[
    SystemReconnaissanceType.FILE_METADATA.value,
    SystemReconnaissanceType.DATABASE_SCHEMA.value,
    SystemReconnaissanceType.RETRIEVAL_CONFIG.value,
    SystemReconnaissanceType.MODEL_FINGERPRINTING.value,
    SystemReconnaissanceType.TOOL_ENUMERATION.value,
    SystemReconnaissanceType.INFRASTRUCTURE_FINGERPRINTING.value,
]
