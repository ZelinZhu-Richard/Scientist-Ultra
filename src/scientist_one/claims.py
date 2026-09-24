"""Typed claim-evidence graph and authoritative paper-writer view.

Material claims are not strings with an ``ELIGIBLE`` label.  They become
eligible only after a claim-verifier role checks every required typed edge,
frozen/verified evidence, local citation verification, contradictions, and
confirmatory custody validity.  The writer view is derived from those
decisions and cannot include pending, unsupported, contradicted, or invalidated
claims.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
import hashlib
import json
import math
import re
from typing import Any, Callable, Iterable, Mapping

from .errors import AuthorizationError, ValidationError
from .roles import Role
from .security import canonical_json_bytes, safe_json_loads


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class ClaimValidationError(ValidationError):
    """A claim graph or eligibility request is invalid."""


class ClaimNotEligibleError(ClaimValidationError):
    """The paper writer requested a claim that did not pass verification."""


class EvidenceKind(StrEnum):
    HYPOTHESIS = "hypothesis"
    ESTIMAND = "estimand"
    DATASET_OR_FIXTURE = "dataset_or_fixture"
    PROTOCOL_VERSION = "protocol_version"
    CODE = "code"
    RESULT = "result_artifact"
    STATISTICAL_ANALYSIS = "statistical_analysis"
    ROBUSTNESS = "robustness_evidence"
    FIGURE_OR_TABLE = "figure_or_table"
    SOURCE_CITATION = "source_citation"
    SCOPE_QUALIFIER = "scope_qualifier"
    LIMITATION = "limitation"


REQUIRED_EVIDENCE_KINDS = frozenset(EvidenceKind)


class ClaimDecision(StrEnum):
    PENDING = "PENDING"
    ELIGIBLE = "ELIGIBLE"
    UNSUPPORTED = "UNSUPPORTED"
    CONTRADICTED = "CONTRADICTED"
    INVALIDATED = "INVALIDATED"


@dataclass(frozen=True, slots=True)
class EvidenceVerificationReceipt:
    """Independent, content-bound verification of one evidence node.

    The graph never treats a node's SHA-shaped string or boolean assertions as
    proof that an artifact exists.  A trusted resolver must produce this
    receipt after resolving the bytes and their immutable registry metadata.
    """

    evidence_id: str
    evidence_kind: EvidenceKind
    artifact_hash: str
    content_sha256: str
    registry_record_hash: str
    support_receipt_hash: str
    support_receipt_record_hash: str
    support_verifier_id: str
    support_verifier_role: Role
    resolver_id: str
    validation_result: str
    frozen: bool
    supports_claim: bool
    contradicts_claim: bool
    locally_verifiable: bool

    def __post_init__(self) -> None:
        _identifier(self.evidence_id, "receipt evidence ID")
        if not isinstance(self.evidence_kind, EvidenceKind):
            try:
                object.__setattr__(self, "evidence_kind", EvidenceKind(self.evidence_kind))
            except (TypeError, ValueError) as exc:
                raise ClaimValidationError("unknown receipt evidence kind") from exc
        for name in (
            "artifact_hash",
            "content_sha256",
            "registry_record_hash",
            "support_receipt_hash",
            "support_receipt_record_hash",
        ):
            _sha256(getattr(self, name), name)
        _identifier(self.resolver_id, "evidence resolver ID")
        _identifier(self.support_verifier_id, "support receipt verifier ID")
        if self.support_verifier_role is not Role.CLAIM_VERIFIER:
            raise AuthorizationError(
                "resolved support receipt must be issued by claim-verifier"
            )
        if self.validation_result not in {"PASS", "FAIL"}:
            raise ClaimValidationError("receipt validation_result must be PASS or FAIL")
        for name in (
            "frozen",
            "supports_claim",
            "contradicts_claim",
            "locally_verifiable",
        ):
            if not isinstance(getattr(self, name), bool):
                raise ClaimValidationError(f"receipt {name} must be boolean")
        if self.supports_claim and self.contradicts_claim:
            raise ClaimValidationError(
                "verified evidence cannot both support and contradict the same claim"
            )

    @property
    def sha256(self) -> str:
        payload = asdict(self)
        payload["evidence_kind"] = self.evidence_kind.value
        payload["support_verifier_role"] = self.support_verifier_role.value
        return _canonical_hash(payload)


def _identifier(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ClaimValidationError(f"invalid {field_name}")
    return value


def _nonempty(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ClaimValidationError(f"{field_name} must be a non-empty string")
    return value.strip()


def _sha256(value: str, field_name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ClaimValidationError(f"{field_name} must be lowercase SHA-256 hex")
    return value


def _canonical_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class _FrozenJSONObject:
    items: tuple[tuple[str, Any], ...]


def _freeze_json(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ClaimValidationError("evidence metadata cannot contain non-finite numbers")
        return value
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) or not key for key in value):
            raise ClaimValidationError("evidence metadata keys must be non-empty strings")
        return _FrozenJSONObject(
            tuple(sorted((key, _freeze_json(child)) for key, child in value.items()))
        )
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json(child) for child in value)
    raise ClaimValidationError("evidence metadata must contain only JSON-safe values")


def _thaw_json(value: Any) -> Any:
    if isinstance(value, _FrozenJSONObject):
        return {key: _thaw_json(child) for key, child in value.items}
    if isinstance(value, tuple):
        return [_thaw_json(child) for child in value]
    return value


def _freeze_metadata(metadata: Mapping[str, Any] | tuple[tuple[str, Any], ...]) -> tuple[tuple[str, Any], ...]:
    if isinstance(metadata, Mapping):
        items = tuple(sorted(metadata.items()))
    elif isinstance(metadata, tuple):
        items = metadata
    else:
        raise ClaimValidationError("evidence metadata must be a mapping or key/value tuple")
    if any(not isinstance(key, str) or not key for key, _ in items):
        raise ClaimValidationError("evidence metadata keys must be non-empty strings")
    return tuple((key, _freeze_json(value)) for key, value in items)


@dataclass(frozen=True, slots=True)
class EvidenceNode:
    evidence_id: str
    kind: EvidenceKind
    artifact_hash: str
    description: str
    verified: bool = False
    frozen: bool = False
    supports_claim: bool = False
    contradicts_claim: bool = False
    locally_verifiable: bool = False
    verification_receipt_hash: str | None = None
    metadata: tuple[tuple[str, Any], ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        _identifier(self.evidence_id, "evidence ID")
        if not isinstance(self.kind, EvidenceKind):
            try:
                object.__setattr__(self, "kind", EvidenceKind(self.kind))
            except (TypeError, ValueError) as exc:
                raise ClaimValidationError("unknown evidence kind") from exc
        _sha256(self.artifact_hash, "evidence artifact hash")
        _nonempty(self.description, "evidence description")
        for name in (
            "verified",
            "frozen",
            "supports_claim",
            "contradicts_claim",
            "locally_verifiable",
        ):
            if not isinstance(getattr(self, name), bool):
                raise ClaimValidationError(f"{name} must be boolean")
        if self.supports_claim and self.contradicts_claim:
            raise ClaimValidationError("evidence cannot both support and contradict the same claim")
        if self.verification_receipt_hash is not None:
            _sha256(self.verification_receipt_hash, "verification_receipt_hash")
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))

    @property
    def metadata_dict(self) -> dict[str, Any]:
        return {key: _thaw_json(value) for key, value in self.metadata}

    @property
    def support_binding_sha256(self) -> str:
        """Bind every writer-visible semantic field without the receipt cycle."""

        return _canonical_hash(
            {
                "evidence_id": self.evidence_id,
                "kind": self.kind.value,
                "artifact_hash": self.artifact_hash,
                "description": self.description,
                "verified": self.verified,
                "frozen": self.frozen,
                "supports_claim": self.supports_claim,
                "contradicts_claim": self.contradicts_claim,
                "locally_verifiable": self.locally_verifiable,
                "metadata": self.metadata_dict,
            }
        )

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["kind"] = self.kind.value
        value["metadata"] = self.metadata_dict
        return value


def text_evidence(
    evidence_id: str,
    kind: EvidenceKind,
    text: str,
    **properties: Any,
) -> EvidenceNode:
    """Create a content-addressed node for a local text artifact."""

    normalized = _nonempty(text, "evidence text")
    return EvidenceNode(
        evidence_id=evidence_id,
        kind=kind,
        artifact_hash=hashlib.sha256(normalized.encode()).hexdigest(),
        description=normalized,
        **properties,
    )


@dataclass(frozen=True, slots=True)
class EvidenceLink:
    evidence_id: str
    kind: EvidenceKind

    def __post_init__(self) -> None:
        _identifier(self.evidence_id, "evidence link ID")
        if not isinstance(self.kind, EvidenceKind):
            try:
                object.__setattr__(self, "kind", EvidenceKind(self.kind))
            except (TypeError, ValueError) as exc:
                raise ClaimValidationError("unknown linked evidence kind") from exc


@dataclass(frozen=True, slots=True)
class MaterialClaim:
    claim_id: str
    text: str
    evidence_links: tuple[EvidenceLink, ...]
    producer_role: Role
    confirmatory: bool = True

    def __post_init__(self) -> None:
        _identifier(self.claim_id, "claim ID")
        _nonempty(self.text, "claim text")
        if not isinstance(self.evidence_links, tuple):
            raise ClaimValidationError("evidence_links must be a tuple")
        if not all(isinstance(link, EvidenceLink) for link in self.evidence_links):
            raise ClaimValidationError("evidence_links must contain EvidenceLink values")
        pairs = tuple((link.kind, link.evidence_id) for link in self.evidence_links)
        if len(set(pairs)) != len(pairs):
            raise ClaimValidationError("claim contains duplicate evidence links")
        if not isinstance(self.producer_role, Role):
            try:
                object.__setattr__(self, "producer_role", Role(self.producer_role))
            except (TypeError, ValueError) as exc:
                raise ClaimValidationError("producer_role must be a Role") from exc
        if self.producer_role is Role.CLAIM_VERIFIER:
            raise AuthorizationError("claim verifier cannot produce the claim it authoritatively verifies")
        if not isinstance(self.confirmatory, bool):
            raise ClaimValidationError("confirmatory must be boolean")


@dataclass(frozen=True, slots=True)
class EvidenceSupportReceipt:
    """Frozen claim-verifier judgment bound to one claim/evidence pair."""

    claim_id: str
    claim_text_sha256: str
    evidence_id: str
    evidence_kind: EvidenceKind
    evidence_artifact_hash: str
    evidence_node_sha256: str
    verifier_id: str
    verifier_role: Role
    verification_result: str
    supports_claim: bool
    contradicts_claim: bool
    locally_verifiable: bool
    rationale: str
    schema_version: str = "1.0"

    def __post_init__(self) -> None:
        _identifier(self.claim_id, "support receipt claim ID")
        _sha256(self.claim_text_sha256, "support receipt claim text hash")
        _identifier(self.evidence_id, "support receipt evidence ID")
        if not isinstance(self.evidence_kind, EvidenceKind):
            try:
                object.__setattr__(self, "evidence_kind", EvidenceKind(self.evidence_kind))
            except (TypeError, ValueError) as exc:
                raise ClaimValidationError("unknown support receipt evidence kind") from exc
        _sha256(self.evidence_artifact_hash, "support receipt evidence artifact hash")
        _sha256(self.evidence_node_sha256, "support receipt evidence node hash")
        _identifier(self.verifier_id, "support receipt verifier ID")
        if not isinstance(self.verifier_role, Role):
            raise AuthorizationError("support receipt verifier role must be typed")
        if self.verifier_role is not Role.CLAIM_VERIFIER:
            raise AuthorizationError(
                "only the claim-verifier role may issue evidence support receipts"
            )
        if self.verification_result not in {"PASS", "FAIL"}:
            raise ClaimValidationError(
                "support receipt verification_result must be PASS or FAIL"
            )
        for name in (
            "supports_claim",
            "contradicts_claim",
            "locally_verifiable",
        ):
            if not isinstance(getattr(self, name), bool):
                raise ClaimValidationError(f"support receipt {name} must be boolean")
        if self.supports_claim and self.contradicts_claim:
            raise ClaimValidationError(
                "support receipt cannot both support and contradict the claim"
            )
        _nonempty(self.rationale, "support receipt rationale")
        if self.schema_version != "1.0":
            raise ClaimValidationError("unsupported evidence support receipt schema")

    @classmethod
    def for_claim(
        cls,
        claim: MaterialClaim,
        node: EvidenceNode,
        *,
        verifier_id: str,
        verification_result: str,
        supports_claim: bool,
        contradicts_claim: bool,
        locally_verifiable: bool,
        rationale: str,
    ) -> "EvidenceSupportReceipt":
        if not isinstance(claim, MaterialClaim) or not isinstance(node, EvidenceNode):
            raise ClaimValidationError("support receipt requires a typed claim and evidence node")
        return cls(
            claim_id=claim.claim_id,
            claim_text_sha256=hashlib.sha256(claim.text.encode("utf-8")).hexdigest(),
            evidence_id=node.evidence_id,
            evidence_kind=node.kind,
            evidence_artifact_hash=node.artifact_hash,
            evidence_node_sha256=node.support_binding_sha256,
            verifier_id=verifier_id,
            verifier_role=Role.CLAIM_VERIFIER,
            verification_result=verification_result,
            supports_claim=supports_claim,
            contradicts_claim=contradicts_claim,
            locally_verifiable=locally_verifiable,
            rationale=rationale,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "claim_id": self.claim_id,
            "claim_text_sha256": self.claim_text_sha256,
            "evidence_id": self.evidence_id,
            "evidence_kind": self.evidence_kind.value,
            "evidence_artifact_hash": self.evidence_artifact_hash,
            "evidence_node_sha256": self.evidence_node_sha256,
            "verifier_id": self.verifier_id,
            "verifier_role": self.verifier_role.value,
            "verification_result": self.verification_result,
            "supports_claim": self.supports_claim,
            "contradicts_claim": self.contradicts_claim,
            "locally_verifiable": self.locally_verifiable,
            "rationale": self.rationale,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EvidenceSupportReceipt":
        expected = {
            "schema_version",
            "claim_id",
            "claim_text_sha256",
            "evidence_id",
            "evidence_kind",
            "evidence_artifact_hash",
            "evidence_node_sha256",
            "verifier_id",
            "verifier_role",
            "verification_result",
            "supports_claim",
            "contradicts_claim",
            "locally_verifiable",
            "rationale",
        }
        if not isinstance(value, Mapping) or set(value) != expected:
            raise ClaimValidationError("evidence support receipt schema is invalid")
        try:
            return cls(
                schema_version=value["schema_version"],
                claim_id=value["claim_id"],
                claim_text_sha256=value["claim_text_sha256"],
                evidence_id=value["evidence_id"],
                evidence_kind=EvidenceKind(value["evidence_kind"]),
                evidence_artifact_hash=value["evidence_artifact_hash"],
                evidence_node_sha256=value["evidence_node_sha256"],
                verifier_id=value["verifier_id"],
                verifier_role=Role(value["verifier_role"]),
                verification_result=value["verification_result"],
                supports_claim=value["supports_claim"],
                contradicts_claim=value["contradicts_claim"],
                locally_verifiable=value["locally_verifiable"],
                rationale=value["rationale"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ClaimValidationError("evidence support receipt is malformed") from exc

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes + b"\n").hexdigest()


EvidenceResolver = Callable[
    [MaterialClaim, EvidenceNode],
    EvidenceVerificationReceipt,
]


def artifact_registry_resolver(
    registry: Any,
    *,
    resolver_id: str = "artifact-registry",
) -> EvidenceResolver:
    """Adapt an immutable artifact registry into a strict evidence resolver.

    The adapter deliberately uses only the registry's public verification,
    metadata, and byte-reading methods.  Corruption, absence, unsafe paths, or
    a forged digest therefore surface as a failed resolver call and can never
    produce claim eligibility.
    """

    _identifier(resolver_id, "evidence resolver ID")
    for method_name in ("verify", "get_metadata", "get_bytes"):
        if not callable(getattr(registry, method_name, None)):
            raise ClaimValidationError(
                "artifact registry resolver requires verify, get_metadata, and get_bytes"
            )

    def resolve(
        claim: MaterialClaim,
        node: EvidenceNode,
    ) -> EvidenceVerificationReceipt:
        if not isinstance(claim, MaterialClaim) or not isinstance(node, EvidenceNode):
            raise ClaimValidationError("evidence resolver received invalid graph values")
        if registry.verify(node.artifact_hash, raise_on_error=True) is not True:
            raise ClaimValidationError("artifact registry did not verify evidence")
        record = registry.get_metadata(node.artifact_hash)
        content = registry.get_bytes(node.artifact_hash)
        content_sha256 = hashlib.sha256(content).hexdigest()
        if (
            getattr(record, "sha256", None) != node.artifact_hash
            or content_sha256 != node.artifact_hash
        ):
            raise ClaimValidationError("artifact registry evidence identity mismatch")
        expected_logical_type = f"claim_evidence.{node.kind.value}"
        if getattr(record, "logical_type", None) != expected_logical_type:
            raise ClaimValidationError("artifact registry evidence kind mismatch")
        if node.kind is EvidenceKind.FIGURE_OR_TABLE:
            parent_hashes = getattr(record, "parent_artifacts", None)
            if not isinstance(parent_hashes, tuple) or not parent_hashes:
                raise ClaimValidationError(
                    "figure/table evidence lacks a materialized output parent"
                )
            expected_parent_mime = {
                "results_table": "text/csv",
                "results_figure": "image/svg+xml",
            }
            materialized = False
            for parent_hash in parent_hashes:
                if registry.verify(parent_hash, raise_on_error=True) is not True:
                    raise ClaimValidationError(
                        "artifact registry did not verify figure/table output"
                    )
                parent_record = registry.get_metadata(parent_hash)
                parent_type = getattr(parent_record, "logical_type", None)
                if parent_type not in expected_parent_mime:
                    continue
                if (
                    getattr(parent_record, "validation_result", None) != "PASS"
                    or getattr(parent_record, "frozen", None) is not True
                    or getattr(parent_record, "mime_type", None)
                    != expected_parent_mime[parent_type]
                ):
                    raise ClaimValidationError(
                        "materialized figure/table output contract is invalid"
                    )
                materialized = True
            if not materialized:
                raise ClaimValidationError(
                    "figure/table evidence lacks a materialized output parent"
                )
        receipt_hash = node.verification_receipt_hash
        if receipt_hash is None:
            raise ClaimValidationError("evidence lacks a claim-support receipt")
        if registry.verify(receipt_hash, raise_on_error=True) is not True:
            raise ClaimValidationError("artifact registry did not verify support receipt")
        receipt_record = registry.get_metadata(receipt_hash)
        receipt_content = registry.get_bytes(receipt_hash)
        if (
            getattr(receipt_record, "sha256", None) != receipt_hash
            or hashlib.sha256(receipt_content).hexdigest() != receipt_hash
            or getattr(receipt_record, "logical_type", None)
            != f"claim_support_receipt.{node.kind.value}"
            or getattr(receipt_record, "creator_role", None) is not Role.CLAIM_VERIFIER
            or getattr(receipt_record, "validation_result", None) != "PASS"
            or getattr(receipt_record, "frozen", None) is not True
            or getattr(receipt_record, "parent_artifacts", None)
            != (node.artifact_hash,)
        ):
            raise ClaimValidationError("claim-support receipt registry contract is invalid")
        try:
            receipt_value = safe_json_loads(receipt_content)
            support_receipt = EvidenceSupportReceipt.from_dict(receipt_value)
        except Exception as exc:
            raise ClaimValidationError("claim-support receipt payload is invalid") from exc
        if receipt_content != support_receipt.canonical_bytes + b"\n":
            raise ClaimValidationError("claim-support receipt is not canonical")
        if support_receipt.sha256 != receipt_hash:
            raise ClaimValidationError("claim-support receipt content hash mismatch")
        if (
            support_receipt.claim_id != claim.claim_id
            or support_receipt.claim_text_sha256
            != hashlib.sha256(claim.text.encode("utf-8")).hexdigest()
            or support_receipt.evidence_id != node.evidence_id
            or support_receipt.evidence_kind is not node.kind
            or support_receipt.evidence_artifact_hash != node.artifact_hash
            or support_receipt.evidence_node_sha256 != node.support_binding_sha256
        ):
            raise ClaimValidationError("claim-support receipt binding mismatch")
        record_hash = getattr(record, "record_hash", None)
        return EvidenceVerificationReceipt(
            evidence_id=node.evidence_id,
            evidence_kind=node.kind,
            artifact_hash=node.artifact_hash,
            content_sha256=content_sha256,
            registry_record_hash=record_hash,
            support_receipt_hash=receipt_hash,
            support_receipt_record_hash=getattr(receipt_record, "record_hash", None),
            support_verifier_id=support_receipt.verifier_id,
            support_verifier_role=support_receipt.verifier_role,
            resolver_id=resolver_id,
            validation_result=(
                "PASS"
                if getattr(record, "validation_result", None) == "PASS"
                and support_receipt.verification_result == "PASS"
                else "FAIL"
            ),
            frozen=getattr(record, "frozen", False),
            supports_claim=support_receipt.supports_claim,
            contradicts_claim=support_receipt.contradicts_claim,
            locally_verifiable=support_receipt.locally_verifiable,
        )

    return resolve


@dataclass(frozen=True, slots=True)
class Contradiction:
    claim_id: str
    evidence_id: str
    reason: str

    def __post_init__(self) -> None:
        _identifier(self.claim_id, "contradiction claim ID")
        _identifier(self.evidence_id, "contradiction evidence ID")
        _nonempty(self.reason, "contradiction reason")


@dataclass(frozen=True, slots=True)
class VerifierDecision:
    claim_id: str
    decision: ClaimDecision
    verifier_id: str
    verifier_role: Role
    reason: str
    checked_evidence_hashes: tuple[str, ...]
    evidence_receipt_hashes: tuple[str, ...]
    missing_kinds: tuple[EvidenceKind, ...] = ()
    contradictions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _identifier(self.claim_id, "decision claim ID")
        _identifier(self.verifier_id, "verifier ID")
        if not isinstance(self.decision, ClaimDecision):
            raise ClaimValidationError("decision must be ClaimDecision")
        if not isinstance(self.verifier_role, Role):
            raise AuthorizationError("verifier role must be typed")
        if self.verifier_role is not Role.CLAIM_VERIFIER:
            raise AuthorizationError("only the claim-verifier role may issue eligibility decisions")
        _nonempty(self.reason, "verifier reason")
        if not isinstance(self.checked_evidence_hashes, tuple):
            raise ClaimValidationError("checked evidence hashes must be a tuple")
        for value in self.checked_evidence_hashes:
            _sha256(value, "checked evidence hash")
        if len(set(self.checked_evidence_hashes)) != len(self.checked_evidence_hashes):
            raise ClaimValidationError("checked evidence hashes must be unique")
        if not isinstance(self.evidence_receipt_hashes, tuple):
            raise ClaimValidationError("evidence receipt hashes must be a tuple")
        for value in self.evidence_receipt_hashes:
            _sha256(value, "evidence verification receipt hash")
        if len(set(self.evidence_receipt_hashes)) != len(self.evidence_receipt_hashes):
            raise ClaimValidationError("evidence receipt hashes must be unique")
        if not isinstance(self.missing_kinds, tuple) or not all(
            isinstance(kind, EvidenceKind) for kind in self.missing_kinds
        ):
            raise ClaimValidationError("missing evidence kinds must be a typed tuple")
        if len(set(self.missing_kinds)) != len(self.missing_kinds):
            raise ClaimValidationError("missing evidence kinds must be unique")
        if not isinstance(self.contradictions, tuple) or any(
            not isinstance(value, str) or not value.strip()
            for value in self.contradictions
        ):
            raise ClaimValidationError("decision contradictions must be non-empty strings")
        if self.decision is ClaimDecision.ELIGIBLE and (
            not self.evidence_receipt_hashes
            or len(self.evidence_receipt_hashes) != len(self.checked_evidence_hashes)
        ):
            raise ClaimValidationError(
                "eligible decisions require one verification receipt per evidence artifact"
            )

    @property
    def status(self) -> ClaimDecision:
        return self.decision

    @property
    def verifier_decision(self) -> str:
        return self.decision.value

    @property
    def sha256(self) -> str:
        payload = asdict(self)
        payload["decision"] = self.decision.value
        payload["verifier_role"] = self.verifier_role.value
        payload["missing_kinds"] = [kind.value for kind in self.missing_kinds]
        return _canonical_hash(payload)


class ClaimEvidenceGraph:
    """Append-only evidence/claim registry with replaceable verifier outcomes."""

    def __init__(self, *, evidence_resolver: EvidenceResolver | None = None) -> None:
        if evidence_resolver is not None and not callable(evidence_resolver):
            raise ClaimValidationError("evidence_resolver must be callable")
        self._evidence: dict[str, EvidenceNode] = {}
        self._claims: dict[str, MaterialClaim] = {}
        self._contradictions: list[Contradiction] = []
        self._decisions: dict[str, VerifierDecision] = {}
        self._decision_history: list[VerifierDecision] = []
        self._evidence_resolver = evidence_resolver

    @property
    def evidence(self) -> tuple[EvidenceNode, ...]:
        return tuple(self._evidence[key] for key in sorted(self._evidence))

    @property
    def claims(self) -> tuple[MaterialClaim, ...]:
        return tuple(self._claims[key] for key in sorted(self._claims))

    @property
    def decisions(self) -> tuple[VerifierDecision, ...]:
        return tuple(self._decisions[key] for key in sorted(self._decisions))

    @property
    def decision_history(self) -> tuple[VerifierDecision, ...]:
        return tuple(self._decision_history)

    def add_evidence(self, evidence: EvidenceNode) -> None:
        if not isinstance(evidence, EvidenceNode):
            raise ClaimValidationError("add_evidence requires EvidenceNode")
        existing = self._evidence.get(evidence.evidence_id)
        if existing is not None and existing != evidence:
            raise ClaimValidationError("evidence ID already names different immutable evidence")
        self._evidence[evidence.evidence_id] = evidence

    def add_claim(self, claim: MaterialClaim) -> None:
        if not isinstance(claim, MaterialClaim):
            raise ClaimValidationError("add_claim requires MaterialClaim")
        existing = self._claims.get(claim.claim_id)
        if existing is not None and existing != claim:
            raise ClaimValidationError("claim ID already names a different immutable claim")
        self._claims[claim.claim_id] = claim

    def add_contradiction(self, contradiction: Contradiction) -> None:
        if not isinstance(contradiction, Contradiction):
            raise ClaimValidationError("add_contradiction requires Contradiction")
        if contradiction.claim_id not in self._claims:
            raise ClaimValidationError("contradiction references an unknown claim")
        if contradiction.evidence_id not in self._evidence:
            raise ClaimValidationError("contradiction references unknown evidence")
        if contradiction not in self._contradictions:
            self._contradictions.append(contradiction)

    def _record_decision(self, decision: VerifierDecision) -> None:
        self._decisions[decision.claim_id] = decision
        if not self._decision_history or self._decision_history[-1] != decision:
            self._decision_history.append(decision)

    def _select_resolver(
        self,
        supplied: EvidenceResolver | None,
    ) -> EvidenceResolver | None:
        if supplied is not None and not callable(supplied):
            raise ClaimValidationError("evidence_resolver must be callable")
        if supplied is None:
            return self._evidence_resolver
        if self._evidence_resolver is not None and supplied is not self._evidence_resolver:
            raise ClaimValidationError("claim graph evidence resolver cannot be replaced")
        if self._decisions and self._evidence_resolver is None:
            raise ClaimValidationError("claim graph evidence resolver cannot change after decisions")
        self._evidence_resolver = supplied
        return supplied

    @staticmethod
    def _receipt_issues(
        node: EvidenceNode,
        receipt: EvidenceVerificationReceipt,
    ) -> tuple[tuple[str, ...], tuple[str, ...]]:
        issues: list[str] = []
        contradictions: list[str] = []
        if receipt.evidence_id != node.evidence_id:
            issues.append(f"resolver receipt ID mismatch for {node.evidence_id}")
        if receipt.evidence_kind is not node.kind:
            issues.append(f"resolver receipt kind mismatch for {node.evidence_id}")
        if receipt.artifact_hash != node.artifact_hash:
            issues.append(f"resolver receipt artifact mismatch for {node.evidence_id}")
        if receipt.content_sha256 != node.artifact_hash:
            issues.append(f"resolved bytes do not match {node.evidence_id}")
        if receipt.validation_result != "PASS":
            issues.append(f"registry validation failed for {node.evidence_id}")
        if receipt.frozen is not node.frozen:
            issues.append(f"resolver frozen status conflicts for {node.evidence_id}")
        if not receipt.frozen:
            issues.append(f"registry artifact {node.evidence_id} is not frozen")
        if receipt.supports_claim is not node.supports_claim:
            issues.append(f"resolver support status conflicts for {node.evidence_id}")
        if not receipt.supports_claim:
            issues.append(f"resolver found {node.evidence_id} does not support the claim")
        if receipt.contradicts_claim is not node.contradicts_claim:
            issues.append(f"resolver contradiction status conflicts for {node.evidence_id}")
        if receipt.contradicts_claim:
            contradictions.append(f"resolver found {node.evidence_id} contradicts the claim")
        if receipt.locally_verifiable is not node.locally_verifiable:
            issues.append(f"resolver local-verification status conflicts for {node.evidence_id}")
        if not receipt.locally_verifiable:
            issues.append(f"resolver could not locally verify {node.evidence_id}")
        return tuple(issues), tuple(contradictions)

    def _linked_nodes(
        self,
        claim: MaterialClaim,
        resolver: EvidenceResolver | None = None,
    ) -> tuple[
        tuple[EvidenceNode, ...],
        tuple[EvidenceVerificationReceipt, ...],
        tuple[str, ...],
        tuple[EvidenceKind, ...],
        tuple[str, ...],
    ]:
        nodes: list[EvidenceNode] = []
        receipts: list[EvidenceVerificationReceipt] = []
        issues: list[str] = []
        linked_kinds: set[EvidenceKind] = set()
        contradiction_reasons: list[str] = []
        for link in claim.evidence_links:
            node = self._evidence.get(link.evidence_id)
            if node is None:
                issues.append(f"missing evidence node {link.evidence_id}")
                continue
            if node.kind is not link.kind:
                issues.append(
                    f"evidence {node.evidence_id} has kind {node.kind.value}, not {link.kind.value}"
                )
                continue
            linked_kinds.add(node.kind)
            nodes.append(node)
            if not node.frozen:
                issues.append(f"evidence {node.evidence_id} is not frozen")
            if not node.verified:
                issues.append(f"evidence {node.evidence_id} is not verified")
            if not node.supports_claim:
                issues.append(f"evidence {node.evidence_id} does not support the claim")
            if node.contradicts_claim:
                contradiction_reasons.append(f"evidence {node.evidence_id} contradicts the claim")
            if node.kind is EvidenceKind.SOURCE_CITATION and not node.locally_verifiable:
                issues.append(f"source citation {node.evidence_id} is not locally verifiable")
            if resolver is None:
                issues.append(f"no trusted evidence resolver for {node.evidence_id}")
                continue
            try:
                receipt = resolver(claim, node)
            except Exception:
                issues.append(f"trusted resolver failed for {node.evidence_id}")
                continue
            if not isinstance(receipt, EvidenceVerificationReceipt):
                issues.append(f"trusted resolver returned no valid receipt for {node.evidence_id}")
                continue
            receipts.append(receipt)
            receipt_issues, receipt_contradictions = self._receipt_issues(node, receipt)
            issues.extend(receipt_issues)
            contradiction_reasons.extend(receipt_contradictions)
        missing_kinds = tuple(sorted(REQUIRED_EVIDENCE_KINDS - linked_kinds, key=lambda item: item.value))
        for contradiction in self._contradictions:
            if contradiction.claim_id == claim.claim_id:
                contradiction_reasons.append(contradiction.reason)
        return (
            tuple(nodes),
            tuple(receipts),
            tuple(issues),
            missing_kinds,
            tuple(contradiction_reasons),
        )

    def verify_claim(
        self,
        claim_id: str,
        *,
        verifier_id: str,
        verifier_role: Role = Role.CLAIM_VERIFIER,
        confirmatory_evidence_valid: bool = True,
        evidence_resolver: EvidenceResolver | None = None,
        raise_on_rejection: bool = False,
    ) -> VerifierDecision:
        """Issue an evidence-derived decision; never accept a supplied status."""

        _identifier(claim_id, "claim ID")
        _identifier(verifier_id, "verifier ID")
        if verifier_role is not Role.CLAIM_VERIFIER:
            raise AuthorizationError("only the claim-verifier role may verify claims")
        if not isinstance(confirmatory_evidence_valid, bool):
            raise ClaimValidationError("confirmatory_evidence_valid must be boolean")
        claim = self._claims.get(claim_id)
        if claim is None:
            raise ClaimValidationError("unknown claim")
        resolver = self._select_resolver(evidence_resolver)
        nodes, receipts, issues, missing_kinds, contradictions = self._linked_nodes(
            claim,
            resolver,
        )
        verifier_receipt_issues = tuple(
            f"support receipt verifier mismatch for {receipt.evidence_id}"
            for receipt in receipts
            if receipt.support_verifier_id != verifier_id
        )
        issues = issues + verifier_receipt_issues
        if claim.confirmatory and not confirmatory_evidence_valid:
            decision = ClaimDecision.INVALIDATED
            reason = "confirmatory custody or protocol validity is invalid"
        elif contradictions:
            decision = ClaimDecision.CONTRADICTED
            reason = "claim is contradicted: " + "; ".join(contradictions)
        elif missing_kinds or issues:
            decision = ClaimDecision.UNSUPPORTED
            details = list(issues)
            if missing_kinds:
                details.append("missing typed links: " + ", ".join(kind.value for kind in missing_kinds))
            reason = "claim lacks eligible evidence: " + "; ".join(details)
        else:
            decision = ClaimDecision.ELIGIBLE
            reason = (
                "all required typed evidence links have independent, content-bound, "
                "frozen verification receipts and are supportive and consistent"
            )
        result = VerifierDecision(
            claim_id=claim_id,
            decision=decision,
            verifier_id=verifier_id,
            verifier_role=verifier_role,
            reason=reason,
            checked_evidence_hashes=tuple(sorted(node.artifact_hash for node in nodes)),
            evidence_receipt_hashes=tuple(sorted(receipt.sha256 for receipt in receipts)),
            missing_kinds=missing_kinds,
            contradictions=contradictions,
        )
        self._record_decision(result)
        if raise_on_rejection and decision is not ClaimDecision.ELIGIBLE:
            raise ClaimNotEligibleError(reason)
        return result

    def require_eligible(self, claim_id: str) -> VerifierDecision:
        decision = self._decisions.get(claim_id)
        if decision is None or decision.decision is not ClaimDecision.ELIGIBLE:
            status = decision.decision.value if decision else ClaimDecision.PENDING.value
            raise ClaimNotEligibleError(f"claim {claim_id!r} is {status}, not ELIGIBLE")
        claim = self._claims.get(claim_id)
        if claim is None:
            raise ClaimNotEligibleError(f"claim {claim_id!r} no longer exists")
        nodes, receipts, issues, missing, contradictions = self._linked_nodes(
            claim,
            self._evidence_resolver,
        )
        verifier_receipt_issues = tuple(
            f"support receipt verifier mismatch for {receipt.evidence_id}"
            for receipt in receipts
            if receipt.support_verifier_id != decision.verifier_id
        )
        issues = issues + verifier_receipt_issues
        current_receipts = tuple(sorted(receipt.sha256 for receipt in receipts))
        if (
            issues
            or missing
            or contradictions
            or tuple(sorted(node.artifact_hash for node in nodes))
            != decision.checked_evidence_hashes
            or current_receipts != decision.evidence_receipt_hashes
        ):
            raise ClaimNotEligibleError(f"claim {claim_id!r} has stale eligibility")
        return decision

    def invalidate_confirmatory_claims(
        self,
        *,
        reason: str,
        verifier_id: str = "custody-invalidation",
    ) -> tuple[VerifierDecision, ...]:
        """Replace prior eligibility when a holdout violation is discovered."""

        reason = _nonempty(reason, "invalidation reason")
        decisions: list[VerifierDecision] = []
        for claim in self.claims:
            if not claim.confirmatory:
                continue
            nodes, receipts, _, missing, contradictions = self._linked_nodes(
                claim,
                self._evidence_resolver,
            )
            decision = VerifierDecision(
                claim_id=claim.claim_id,
                decision=ClaimDecision.INVALIDATED,
                verifier_id=verifier_id,
                verifier_role=Role.CLAIM_VERIFIER,
                reason=reason,
                checked_evidence_hashes=tuple(sorted(node.artifact_hash for node in nodes)),
                evidence_receipt_hashes=tuple(sorted(receipt.sha256 for receipt in receipts)),
                missing_kinds=missing,
                contradictions=contradictions,
            )
            self._record_decision(decision)
            decisions.append(decision)
        return tuple(decisions)

    def apply_custody_status(self, status: Any) -> tuple[VerifierDecision, ...]:
        """Invalidate confirmatory decisions from a custody status object."""

        validity = getattr(status, "confirmatory_claims_valid", None)
        if not isinstance(validity, bool):
            raise ClaimValidationError(
                "custody confirmatory_claims_valid must be boolean"
            )
        if validity:
            return ()
        reasons = getattr(status, "violation_reasons", ())
        if not isinstance(reasons, tuple) or any(
            not isinstance(value, str) or not value.strip() for value in reasons
        ):
            raise ClaimValidationError(
                "custody violation_reasons must be a tuple of non-empty strings"
            )
        reason = (
            "holdout custody violation: " + "; ".join(str(value) for value in reasons)
            if reasons
            else "holdout is not valid for confirmatory claims"
        )
        return self.invalidate_confirmatory_claims(reason=reason)

    def writer_view(self) -> tuple[dict[str, Any], ...]:
        """Return only currently eligible claims in the writer's narrow schema."""

        result: list[dict[str, Any]] = []
        for claim in self.claims:
            decision = self._decisions.get(claim.claim_id)
            if decision is None or decision.decision is not ClaimDecision.ELIGIBLE:
                continue
            nodes, receipts, issues, missing, contradictions = self._linked_nodes(
                claim,
                self._evidence_resolver,
            )
            verifier_receipt_issues = tuple(
                f"support receipt verifier mismatch for {receipt.evidence_id}"
                for receipt in receipts
                if receipt.support_verifier_id != decision.verifier_id
            )
            issues = issues + verifier_receipt_issues
            current_receipts = tuple(sorted(receipt.sha256 for receipt in receipts))
            if (
                issues
                or missing
                or contradictions
                or tuple(sorted(node.artifact_hash for node in nodes))
                != decision.checked_evidence_hashes
                or current_receipts != decision.evidence_receipt_hashes
            ):
                continue
            scope = [node.description for node in nodes if node.kind is EvidenceKind.SCOPE_QUALIFIER]
            limitations = [node.description for node in nodes if node.kind is EvidenceKind.LIMITATION]
            result.append(
                {
                    "claim_id": claim.claim_id,
                    "text": claim.text,
                    "scope_qualifier": " ".join(scope),
                    "limitations": limitations,
                    "verifier_decision": ClaimDecision.ELIGIBLE.value,
                    "verifier_decision_hash": decision.sha256,
                    "evidence_hashes": list(decision.checked_evidence_hashes),
                    "evidence_receipt_hashes": list(decision.evidence_receipt_hashes),
                    "confirmatory": claim.confirmatory,
                }
            )
        return tuple(result)

    def to_dict(self) -> dict[str, Any]:
        claims = []
        for claim in self.claims:
            claims.append(
                {
                    "claim_id": claim.claim_id,
                    "text": claim.text,
                    "producer_role": claim.producer_role.value,
                    "confirmatory": claim.confirmatory,
                    "evidence_links": [
                        {"evidence_id": link.evidence_id, "kind": link.kind.value}
                        for link in claim.evidence_links
                    ],
                }
            )
        decisions = []
        for decision in self.decisions:
            decisions.append(
                {
                    "claim_id": decision.claim_id,
                    "decision": decision.decision.value,
                    "verifier_id": decision.verifier_id,
                    "verifier_role": decision.verifier_role.value,
                    "reason": decision.reason,
                    "checked_evidence_hashes": list(decision.checked_evidence_hashes),
                    "evidence_receipt_hashes": list(decision.evidence_receipt_hashes),
                    "missing_kinds": [kind.value for kind in decision.missing_kinds],
                    "contradictions": list(decision.contradictions),
                    "sha256": decision.sha256,
                }
            )
        decision_history = []
        for decision in self.decision_history:
            decision_history.append(
                {
                    "claim_id": decision.claim_id,
                    "decision": decision.decision.value,
                    "verifier_id": decision.verifier_id,
                    "verifier_role": decision.verifier_role.value,
                    "reason": decision.reason,
                    "checked_evidence_hashes": list(decision.checked_evidence_hashes),
                    "evidence_receipt_hashes": list(decision.evidence_receipt_hashes),
                    "missing_kinds": [kind.value for kind in decision.missing_kinds],
                    "contradictions": list(decision.contradictions),
                    "sha256": decision.sha256,
                }
            )
        return {
            "evidence": [node.to_dict() for node in self.evidence],
            "claims": claims,
            "contradictions": [asdict(value) for value in self._contradictions],
            "decisions": decisions,
            "decision_history": decision_history,
        }

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, Any],
        *,
        evidence_resolver: EvidenceResolver | None = None,
    ) -> "ClaimEvidenceGraph":
        """Rehydrate graph definitions for fresh evidence re-verification.

        Serialized eligibility decisions are intentionally not trusted or
        restored.  A downstream consumer must call :meth:`verify_claim` again,
        which re-resolves every evidence and support-receipt artifact.
        """

        expected = {
            "evidence",
            "claims",
            "contradictions",
            "decisions",
            "decision_history",
        }
        if not isinstance(value, Mapping) or set(value) != expected:
            raise ClaimValidationError("serialized claim graph schema is invalid")
        for name in expected:
            if not isinstance(value[name], list):
                raise ClaimValidationError(f"serialized claim graph {name} must be a list")
        graph = cls(evidence_resolver=evidence_resolver)
        evidence_ids: set[str] = set()
        evidence_keys = {
            "evidence_id",
            "kind",
            "artifact_hash",
            "description",
            "verified",
            "frozen",
            "supports_claim",
            "contradicts_claim",
            "locally_verifiable",
            "verification_receipt_hash",
            "metadata",
        }
        try:
            for item in value["evidence"]:
                if not isinstance(item, Mapping) or set(item) != evidence_keys:
                    raise ClaimValidationError("serialized evidence node schema is invalid")
                node = EvidenceNode(
                    evidence_id=item["evidence_id"],
                    kind=EvidenceKind(item["kind"]),
                    artifact_hash=item["artifact_hash"],
                    description=item["description"],
                    verified=item["verified"],
                    frozen=item["frozen"],
                    supports_claim=item["supports_claim"],
                    contradicts_claim=item["contradicts_claim"],
                    locally_verifiable=item["locally_verifiable"],
                    verification_receipt_hash=item["verification_receipt_hash"],
                    metadata=item["metadata"],
                )
                if node.evidence_id in evidence_ids:
                    raise ClaimValidationError("serialized graph duplicates an evidence ID")
                evidence_ids.add(node.evidence_id)
                graph.add_evidence(node)

            claim_ids: set[str] = set()
            claim_keys = {
                "claim_id",
                "text",
                "producer_role",
                "confirmatory",
                "evidence_links",
            }
            link_keys = {"evidence_id", "kind"}
            for item in value["claims"]:
                if not isinstance(item, Mapping) or set(item) != claim_keys:
                    raise ClaimValidationError("serialized material claim schema is invalid")
                links_value = item["evidence_links"]
                if not isinstance(links_value, list):
                    raise ClaimValidationError("serialized evidence links must be a list")
                links: list[EvidenceLink] = []
                for link in links_value:
                    if not isinstance(link, Mapping) or set(link) != link_keys:
                        raise ClaimValidationError("serialized evidence link schema is invalid")
                    links.append(
                        EvidenceLink(
                            evidence_id=link["evidence_id"],
                            kind=EvidenceKind(link["kind"]),
                        )
                    )
                claim = MaterialClaim(
                    claim_id=item["claim_id"],
                    text=item["text"],
                    evidence_links=tuple(links),
                    producer_role=Role(item["producer_role"]),
                    confirmatory=item["confirmatory"],
                )
                if claim.claim_id in claim_ids:
                    raise ClaimValidationError("serialized graph duplicates a claim ID")
                claim_ids.add(claim.claim_id)
                graph.add_claim(claim)

            contradiction_keys = {"claim_id", "evidence_id", "reason"}
            seen_contradictions: set[tuple[str, str, str]] = set()
            for item in value["contradictions"]:
                if not isinstance(item, Mapping) or set(item) != contradiction_keys:
                    raise ClaimValidationError("serialized contradiction schema is invalid")
                contradiction = Contradiction(
                    claim_id=item["claim_id"],
                    evidence_id=item["evidence_id"],
                    reason=item["reason"],
                )
                identity = (
                    contradiction.claim_id,
                    contradiction.evidence_id,
                    contradiction.reason,
                )
                if identity in seen_contradictions:
                    raise ClaimValidationError("serialized graph duplicates a contradiction")
                seen_contradictions.add(identity)
                graph.add_contradiction(contradiction)

            decision_keys = {
                "claim_id",
                "decision",
                "verifier_id",
                "verifier_role",
                "reason",
                "checked_evidence_hashes",
                "evidence_receipt_hashes",
                "missing_kinds",
                "contradictions",
                "sha256",
            }

            def parse_decision(item: Any) -> VerifierDecision:
                if not isinstance(item, Mapping) or set(item) != decision_keys:
                    raise ClaimValidationError("serialized verifier decision schema is invalid")
                for name in (
                    "checked_evidence_hashes",
                    "evidence_receipt_hashes",
                    "missing_kinds",
                    "contradictions",
                ):
                    if not isinstance(item[name], list):
                        raise ClaimValidationError(
                            f"serialized verifier decision {name} must be a list"
                        )
                parsed = VerifierDecision(
                    claim_id=item["claim_id"],
                    decision=ClaimDecision(item["decision"]),
                    verifier_id=item["verifier_id"],
                    verifier_role=Role(item["verifier_role"]),
                    reason=item["reason"],
                    checked_evidence_hashes=tuple(item["checked_evidence_hashes"]),
                    evidence_receipt_hashes=tuple(item["evidence_receipt_hashes"]),
                    missing_kinds=tuple(
                        EvidenceKind(kind) for kind in item["missing_kinds"]
                    ),
                    contradictions=tuple(item["contradictions"]),
                )
                _sha256(item["sha256"], "serialized verifier decision hash")
                if parsed.sha256 != item["sha256"]:
                    raise ClaimValidationError("serialized verifier decision hash mismatch")
                if parsed.claim_id not in claim_ids:
                    raise ClaimValidationError("serialized decision references an unknown claim")
                return parsed

            current_decisions: dict[str, VerifierDecision] = {}
            for item in value["decisions"]:
                decision = parse_decision(item)
                if decision.claim_id in current_decisions:
                    raise ClaimValidationError(
                        "serialized graph duplicates a current claim decision"
                    )
                current_decisions[decision.claim_id] = decision
            history = tuple(parse_decision(item) for item in value["decision_history"])
            for claim_id, current in current_decisions.items():
                matching = tuple(item for item in history if item.claim_id == claim_id)
                if not matching or matching[-1] != current:
                    raise ClaimValidationError(
                        "serialized current decision does not match decision history"
                    )
        except ClaimValidationError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise ClaimValidationError("serialized claim graph is malformed") from exc
        return graph

    @property
    def sha256(self) -> str:
        return _canonical_hash(self.to_dict())


def writer_view(graph: ClaimEvidenceGraph) -> tuple[dict[str, Any], ...]:
    if not isinstance(graph, ClaimEvidenceGraph):
        raise ClaimValidationError("writer_view requires ClaimEvidenceGraph")
    return graph.writer_view()


def verify_claims(
    graph: ClaimEvidenceGraph,
    *,
    verifier_id: str,
    confirmatory_evidence_valid: bool = True,
    evidence_resolver: EvidenceResolver | None = None,
) -> tuple[VerifierDecision, ...]:
    """Verify every registered claim deterministically."""

    return tuple(
        graph.verify_claim(
            claim.claim_id,
            verifier_id=verifier_id,
            confirmatory_evidence_valid=confirmatory_evidence_valid,
            evidence_resolver=evidence_resolver,
        )
        for claim in graph.claims
    )


__all__ = [
    "ClaimValidationError",
    "ClaimNotEligibleError",
    "EvidenceKind",
    "REQUIRED_EVIDENCE_KINDS",
    "ClaimDecision",
    "EvidenceVerificationReceipt",
    "EvidenceSupportReceipt",
    "EvidenceResolver",
    "EvidenceNode",
    "EvidenceLink",
    "MaterialClaim",
    "Contradiction",
    "VerifierDecision",
    "ClaimEvidenceGraph",
    "text_evidence",
    "artifact_registry_resolver",
    "writer_view",
    "verify_claims",
]
