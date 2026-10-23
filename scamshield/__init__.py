"""Core, framework-independent message analysis for ScamShield AI."""

from .message_analyzer import (
    AnalysisResult,
    Finding,
    IndicatorType,
    MessageAnalyzer,
    OverallStatus,
    Severity,
    analyze_message,
)
from .reputation import ReputationResult, ReputationStatus, UrlReputationService
from .guidance import SafetyGuidance, SituationCategory, get_safety_guidance
from .bedrock_service import (
    BedrockConfig,
    BedrockConfigurationError,
    BedrockExplanationService,
    BedrockOutputError,
    BedrockServiceError,
    Explanation,
)

__all__ = [
    "AnalysisResult",
    "Finding",
    "IndicatorType",
    "MessageAnalyzer",
    "OverallStatus",
    "Severity",
    "analyze_message",
    "ReputationResult",
    "ReputationStatus",
    "UrlReputationService",
    "SafetyGuidance",
    "SituationCategory",
    "get_safety_guidance",
    "BedrockConfig",
    "BedrockConfigurationError",
    "BedrockExplanationService",
    "BedrockOutputError",
    "BedrockServiceError",
    "Explanation",
]
