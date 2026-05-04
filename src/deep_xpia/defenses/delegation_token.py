"""Defense P3.3: Scope-Bound Delegation Tokens

Each delegation hop carries a token that narrows scope.
Append-only attenuation: tokens can narrow permissions, never widen them.

Expected performance:
  - Strong against: DXPIA-005 (scope escalation blocked at token boundary)
  - Strong against: DXPIA-004 (re-routing blocked: new agents must be in scope)
  - Weak against: DXPIA-001 (session smuggling happens within authorized scope;
    research agent is permitted to return text, and the smuggled instruction
    IS text -- scope tokens can't distinguish intent from payload)

HONEST LIMITATION:
  Scope tokens prevent privilege escalation but not intent drift within
  authorized scope. An agent authorized to return {text} can smuggle action
  instructions as text. Scope enforcement is necessary but not sufficient.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field


@dataclass
class DelegationToken:
    """Immutable delegation token for one hop.

    Permissions are additive-only attenuation: a hop can only keep or
    remove permissions from the parent token, never add new ones.
    """

    issuer: str
    recipient: str
    permissions: frozenset[str]
    parent_token_id: str | None
    token_id: str = field(init=False)
    issued_at: float = field(default_factory=time.time)
    depth: int = 0

    def __post_init__(self) -> None:
        payload = f"{self.issuer}:{self.recipient}:{sorted(self.permissions)}:{self.issued_at}"
        self.token_id = hashlib.sha256(payload.encode()).hexdigest()[:16]

    def attenuate(self, new_recipient: str, allowed_permissions: set[str]) -> DelegationToken:
        """Create a child token for a sub-delegation.

        The child token can only have a subset of this token's permissions.
        Attempting to add permissions raises PermissionError.
        """
        requested = frozenset(allowed_permissions)
        narrowed = self.permissions & requested
        if requested - self.permissions:
            raise PermissionError(
                f"Attempted scope widening: {requested - self.permissions} "
                f"are not in parent token permissions {self.permissions}"
            )
        return DelegationToken(
            issuer=self.recipient,
            recipient=new_recipient,
            permissions=narrowed,
            parent_token_id=self.token_id,
            depth=self.depth + 1,
        )

    def has_permission(self, action: str) -> bool:
        return action in self.permissions

    def verify_recipient(self, agent: str) -> bool:
        return self.recipient == agent


@dataclass
class TokenViolation:
    hop: int
    agent: str
    action: str
    token: DelegationToken
    reason: str


class ScopeTokenEnforcer:
    """Enforces scope-bound delegation tokens at each hop.

    Usage:
        enforcer = ScopeTokenEnforcer()
        root = enforcer.issue_root("orchestrator", {"read_data", "summarize", "delegate"})
        child = enforcer.delegate(root, "research_agent", {"read_data", "summarize"})
        violation = enforcer.check_action(1, child, "research_agent", "execute_trade")
    """

    def __init__(self) -> None:
        self.violations: list[TokenViolation] = []

    def issue_root(self, issuer: str, permissions: set[str]) -> DelegationToken:
        """Issue a root token for the user -> orchestrator delegation."""
        return DelegationToken(
            issuer="user",
            recipient=issuer,
            permissions=frozenset(permissions),
            parent_token_id=None,
        )

    def delegate(
        self,
        parent: DelegationToken,
        recipient: str,
        permissions: set[str],
    ) -> DelegationToken:
        """Attenuate parent token for a sub-delegation.

        Raises PermissionError if permissions exceed parent scope.
        """
        return parent.attenuate(recipient, permissions)

    def check_action(
        self,
        hop: int,
        token: DelegationToken,
        agent: str,
        action: str,
    ) -> TokenViolation | None:
        """Check whether an agent is trying to perform an action outside its token scope."""
        if not token.verify_recipient(agent):
            v = TokenViolation(
                hop=hop,
                agent=agent,
                action=action,
                token=token,
                reason=f"Token recipient mismatch: token for '{token.recipient}', agent is '{agent}'",
            )
            self.violations.append(v)
            return v

        if not token.has_permission(action):
            v = TokenViolation(
                hop=hop,
                agent=agent,
                action=action,
                token=token,
                reason=(
                    f"Action '{action}' not in token permissions "
                    f"{set(token.permissions)} for agent '{agent}'"
                ),
            )
            self.violations.append(v)
            return v
        return None

    @property
    def blocked(self) -> bool:
        return len(self.violations) > 0
