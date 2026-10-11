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

INTEGRITY:
  token_id is an unkeyed hash of public fields, so anyone can mint or edit a
  token. With a key, ScopeTokenEnforcer signs each token with HMAC-SHA256
  over its fields and its parent's signature (a chain, in the spirit of
  attenuated credentials; cf. Authenticated Delegation, arXiv:2501.09674) and
  rejects tokens whose signature does not verify. Without a key it behaves as
  before (unsigned; simulation only).
"""

from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass, field, replace


@dataclass(frozen=True)
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
    parent_signature: str = ""
    signature: str = ""  # HMAC-SHA256 hex when issued by a keyed enforcer; "" = unsigned

    def signing_payload(self) -> bytes:
        return "|".join([
            self.issuer, self.recipient, ",".join(sorted(self.permissions)), self.parent_token_id or "",
            repr(self.issued_at), str(self.depth), self.parent_signature,
        ]).encode()

    def __post_init__(self) -> None:
        payload = f"{self.issuer}:{self.recipient}:{sorted(self.permissions)}:{self.issued_at}"
        object.__setattr__(self, "token_id", hashlib.sha256(payload.encode()).hexdigest()[:16])

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

    def __init__(self, key: bytes | None = None) -> None:
        self.violations: list[TokenViolation] = []
        self._key = key

    def _sign(self, token: DelegationToken) -> DelegationToken:
        if self._key is None:
            return token
        mac = hmac.new(self._key, token.signing_payload(), hashlib.sha256).hexdigest()
        return replace(token, signature=mac)

    def verify(self, token: DelegationToken) -> bool:
        """True if the token was signed with this enforcer's key and not modified (always True unkeyed)."""
        if self._key is None:
            return True
        expected = hmac.new(self._key, token.signing_payload(), hashlib.sha256).hexdigest()
        return bool(token.signature) and hmac.compare_digest(expected, token.signature)

    def issue_root(self, issuer: str, permissions: set[str]) -> DelegationToken:
        """Issue a root token for the user -> orchestrator delegation."""
        return self._sign(DelegationToken(
            issuer="user",
            recipient=issuer,
            permissions=frozenset(permissions),
            parent_token_id=None,
        ))

    def delegate(
        self,
        parent: DelegationToken,
        recipient: str,
        permissions: set[str],
    ) -> DelegationToken:
        """Attenuate parent token for a sub-delegation.

        Raises PermissionError if permissions exceed parent scope or, with a
        key, if the parent token does not verify.
        """
        if not self.verify(parent):
            raise PermissionError("parent token signature does not verify")
        child = parent.attenuate(recipient, permissions)
        return self._sign(replace(child, parent_signature=parent.signature))

    def check_action(
        self,
        hop: int,
        token: DelegationToken,
        agent: str,
        action: str,
    ) -> TokenViolation | None:
        """Check whether an agent is trying to perform an action outside its token scope."""
        if not self.verify(token):
            v = TokenViolation(hop=hop, agent=agent, action=action, token=token,
                               reason="Token signature does not verify (forged or modified)")
            self.violations.append(v)
            return v
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
