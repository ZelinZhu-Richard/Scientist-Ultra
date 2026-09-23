"""Generate paper/demo prose and simple figures only from verified structured data."""

from __future__ import annotations

import csv
import html
import io
import json
from pathlib import Path
from typing import Any, Iterable

from .errors import PathSecurityError, UnsafeSerializationError
from .security import (
    DEFAULT_MAX_JSON_BYTES,
    atomic_write_bytes,
    read_confined_bytes,
    safe_json_loads,
)


REQUIRED_CLAIM_GRAPH_FIELDS = (
    "hypothesis_id",
    "estimand_id",
    "dataset_or_fixture_id",
    "protocol_hash",
    "code_hash",
    "result_artifact_hash",
    "statistical_analysis_hash",
    "robustness_evidence_hashes",
    "figure_or_table_ids",
    "source_citation_ids",
    "scope_qualifier",
    "limitations",
    "verifier_decision",
    "verifier_artifact_hash",
)


def _eligible_claims(claims: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    selected = [claim for claim in claims if claim.get("verifier_decision") == "ELIGIBLE"]
    for claim in selected:
        missing = [field for field in REQUIRED_CLAIM_GRAPH_FIELDS if not claim.get(field)]
        if missing:
            raise ValueError(f"eligible claim has incomplete evidence graph: {','.join(missing)}")
        for field in (
            "protocol_hash",
            "code_hash",
            "result_artifact_hash",
            "statistical_analysis_hash",
            "verifier_artifact_hash",
        ):
            value = claim[field]
            if not isinstance(value, str) or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
                raise ValueError(f"eligible claim has invalid {field}")
    return selected


def _atomic_write(target: Path, data: bytes, root: Path) -> Path:
    try:
        # Immutable publication is idempotent for identical bytes and refuses
        # replacement.  The shared writer pins every parent directory and uses
        # no-follow descriptors, closing parent/leaf swap races.
        return atomic_write_bytes(root, target, data, immutable=True)
    except PathSecurityError as exc:
        raise ValueError("output target is not a confined immutable file") from exc


def render_results_table_bytes(results: list[dict[str, Any]]) -> bytes:
    """Return the deterministic CSV bytes without touching the filesystem."""

    if not results:
        raise ValueError("cannot generate an empty results table")
    fields = sorted({key for row in results for key in row})
    buffer = io.StringIO(newline="")
    with buffer as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(results)
        return handle.getvalue().encode()


def write_results_table(results: list[dict[str, Any]], target: Path, *, root: Path) -> Path:
    return _atomic_write(target, render_results_table_bytes(results), root)


def render_svg_effect_figure_bytes(results: list[dict[str, Any]]) -> bytes:
    """Return a deterministic dependency-free SVG bar figure as bytes."""

    values = [(str(row["task"]), float(row["effect_size"])) for row in results]
    width, height, margin = 720, 320, 50
    max_abs = max(1.0, *(abs(value) for _, value in values))
    zero = height // 2
    step = (width - 2 * margin) / max(1, len(values))
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="white"/>',
        f'<line x1="{margin}" y1="{zero}" x2="{width-margin}" y2="{zero}" stroke="black"/>',
        '<text x="20" y="20" font-family="sans-serif" font-size="14">Confirmatory effect sizes (synthetic demo)</text>',
    ]
    for index, (label, value) in enumerate(values):
        x = margin + index * step + step * 0.2
        bar_width = step * 0.6
        bar_height = abs(value) / max_abs * (height / 2 - 60)
        y = zero - bar_height if value >= 0 else zero
        color = "#2563eb" if value >= 0 else "#dc2626"
        parts.append(f'<rect x="{x:.2f}" y="{y:.2f}" width="{bar_width:.2f}" height="{bar_height:.2f}" fill="{color}"/>')
        parts.append(
            f'<text x="{x + bar_width / 2:.2f}" y="{height-25}" text-anchor="middle" '
            f'font-family="sans-serif" font-size="11">{html.escape(label)}</text>'
        )
    parts.append("</svg>")
    return ("\n".join(parts) + "\n").encode()


def write_svg_effect_figure(results: list[dict[str, Any]], target: Path, *, root: Path) -> Path:
    """Create a deterministic dependency-free SVG bar figure."""

    return _atomic_write(target, render_svg_effect_figure_bytes(results), root)


def render_demo_paper_bytes(
    manifest: dict[str, Any],
    claims: list[dict[str, Any]],
    results_path: Path,
    figure_path: Path,
) -> bytes:
    """Return the bounded synthetic paper bytes without publishing a path."""

    eligible = _eligible_claims(claims)
    if manifest.get("package_kind") != "DEMO_RESEARCH_PACKAGE":
        raise ValueError("this writer only produces the bounded synthetic demo paper")
    claim_lines = "\n".join(f"- {claim['text']} ({claim['scope_qualifier']})" for claim in eligible)
    limitation_lines = "\n".join(
        f"- {limitation}" for claim in eligible for limitation in claim["limitations"]
    ) or "- No eligible claim exists."
    content = f"""# Scientist-One Synthetic Workflow Demonstration

**Artifact status:** DEMO_RESEARCH_PACKAGE  
**Novelty status:** NOVELTY_UNVERIFIED  
**Release status:** Local candidate for human review only; E4 approval is absent.

## Abstract

This document reports a deterministic synthetic demonstration of Scientist-One's scientific controls. It does not establish external novelty, real-world value, independent holdout custody, or submission readiness.

## Introduction and related work

The run validates local controller behavior rather than a real research contribution. No external literature was accessed, so related-work and novelty claims are intentionally withheld.

## Problem formulation

The benchmark asks whether the controller distinguishes planted signal, true null, reversal, leakage, invalid analysis, and corrupted evidence while preserving a frozen confirmatory reserve.

## Methodology and protocol

Protocol hash: `{manifest.get('protocol_hash', 'UNAVAILABLE')}`. The validity reserve is 40%. Simulated holdout custody is explicitly non-independent. Pilot evidence is excluded from confirmatory claims.

## Results

Machine-readable table: `{results_path.as_posix()}`  
Generated figure: `{figure_path.as_posix()}`

### Eligible claims

{claim_lines or '- No material claim was eligible.'}

## Ablations, robustness, and negative controls

The calibration suite contains positive, null, reversal, leakage, invalid-resampling, multiplicity, baseline-mismatch, corrupted-provenance, unsupported-claim, holdout-violation, and prompt-injection cases. These are architecture fixtures, not empirical evidence about an external domain.

## Limitations

{limitation_lines}
- The same local process owns simulated custody; it is not genuinely independent.
- The corpus contains no locally verifiable external literature or citation evidence.
- Synthetic success cannot establish scientific importance, novelty, or generalization.

## Broader and ethical considerations

The controller is designed to prefer negative, inconclusive, or blocked outcomes over unsupported claims. Human review remains necessary before any external use or release.

## Reproducibility statement

Replay uses the frozen local manifest, standard-library Python, exact input/config/code fingerprints, fixed seeds, and declared numeric tolerances. The reproduction verifier may not modify original evidence.
"""
    return content.encode()


def write_demo_paper(
    manifest: dict[str, Any],
    claims: list[dict[str, Any]],
    results_path: Path,
    figure_path: Path,
    target: Path,
    *,
    root: Path,
) -> Path:
    return _atomic_write(
        target,
        render_demo_paper_bytes(manifest, claims, results_path, figure_path),
        root,
    )


def load_machine_results(path: Path, *, root: Path) -> list[dict[str, Any]]:
    # Treat machine results as untrusted evidence: descriptor-pinned read,
    # finite/duplicate-free bounded JSON, and no hard-linked input.  The trust
    # root is explicit: deriving it from ``path.parent`` would make every
    # caller-selected absolute directory a project boundary.
    try:
        canonical_root = root.resolve(strict=True)
        candidate = path if path.is_absolute() else canonical_root / path
        relative = candidate.relative_to(canonical_root)
        payload = read_confined_bytes(
            canonical_root,
            relative,
            reject_hardlinks=True,
            max_bytes=DEFAULT_MAX_JSON_BYTES,
        )
        if payload is None:
            raise ValueError("machine results are absent")
        value = safe_json_loads(payload)
    except (OSError, ValueError, PathSecurityError, UnsafeSerializationError) as exc:
        raise ValueError("machine results cannot be safely loaded") from exc
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValueError("machine results must be a JSON list of objects")
    return value
