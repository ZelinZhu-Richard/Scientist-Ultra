"""Typed failures for Scientist-One's fail-closed control plane."""

from __future__ import annotations


class ScientistOneError(Exception):
    """Base class for failures raised by Scientist-One."""


class ValidationError(ScientistOneError, ValueError):
    """Untrusted or internally inconsistent data failed validation."""


class SecurityError(ValidationError):
    """A security boundary would be crossed or cannot be verified."""


class PathSecurityError(SecurityError):
    """A path is not canonically confined to the project root."""


class CommandSecurityError(SecurityError):
    """An untrusted command is not an explicitly permitted argv vector."""


class UnsafeSerializationError(SecurityError):
    """Serialized input is unsafe, ambiguous, or exceeds its limits."""


class AuthorizationError(ValidationError):
    """An actor lacks the authority required for an operation."""


class ApprovalForgeryError(AuthorizationError):
    """A decision purports to have authority that cannot be self-issued."""


class TransitionError(ValidationError):
    """A state transition request is invalid."""


class InvalidTransitionError(TransitionError):
    """The requested source/destination edge does not exist."""


class IncompleteTransitionError(TransitionError):
    """Required typed evidence for a transition is missing or failing."""


class UnauthorizedTransitionError(AuthorizationError, TransitionError):
    """The transition requester or approver is unauthorized."""


class IdempotencyConflictError(TransitionError):
    """An idempotency key was reused for a different request."""


class IntegrityError(ScientistOneError):
    """Stored evidence does not match its integrity metadata."""


class LedgerError(IntegrityError):
    """The append-only event ledger could not be safely used."""


class LedgerCorruptionError(LedgerError):
    """The ledger is malformed or its hash chain is invalid."""


class ArtifactError(IntegrityError):
    """The content-addressed artifact store could not be safely used."""


class ArtifactCorruptionError(ArtifactError):
    """Artifact bytes or metadata do not match their recorded digest."""


class FrozenArtifactError(ArtifactError):
    """An operation attempted to mutate frozen evidence."""


class ArtifactCollisionError(ArtifactError):
    """A digest or metadata identity already names different content."""


# Compatibility aliases with deliberately narrow meanings.
PathViolation = PathSecurityError
SecurityViolation = SecurityError
HashChainError = LedgerCorruptionError
MissingEvidenceError = IncompleteTransitionError
UnauthorizedTransition = UnauthorizedTransitionError
IdempotencyConflict = IdempotencyConflictError

