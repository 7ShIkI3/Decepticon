"""Decepticon middleware — custom AgentMiddleware implementations."""

from decepticon.middleware.budget import BudgetEnforcementMiddleware
from decepticon.middleware.engagement import EngagementContextMiddleware
from decepticon.middleware.filesystem import FilesystemMiddleware
from decepticon.middleware.hitl import (
    DEFAULT_HIGH_IMPACT_POLICY,
    ApprovalDecision,
    ApprovalPolicyRule,
    ApprovalRequest,
    ApprovalTransport,
    FileBackedApprovalTransport,
    HITLApprovalMiddleware,
    InProcessApprovalTransport,
)
from decepticon.middleware.notifications import (
    SandboxNotificationMiddleware,
)
from decepticon.middleware.opplan import OPPLANMiddleware
from decepticon.middleware.prompt_injection_shield import (
    PromptInjectionShieldMiddleware,
)
from decepticon.middleware.skills import SkillsMiddleware

__all__ = [
    "ApprovalDecision",
    "ApprovalPolicyRule",
    "ApprovalRequest",
    "ApprovalTransport",
    "BudgetEnforcementMiddleware",
    "DEFAULT_HIGH_IMPACT_POLICY",
    "EngagementContextMiddleware",
    "FileBackedApprovalTransport",
    "FilesystemMiddleware",
    "HITLApprovalMiddleware",
    "InProcessApprovalTransport",
    "OPPLANMiddleware",
    "PromptInjectionShieldMiddleware",
    "SandboxNotificationMiddleware",
    "SkillsMiddleware",
]
