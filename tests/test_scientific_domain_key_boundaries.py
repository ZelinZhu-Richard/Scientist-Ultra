"""Secret-boundary regressions for the local scientific-domain trust root."""

from __future__ import annotations

import base64
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from scientist_one.artifacts import ArtifactRegistry
from scientist_one.domains import (
    SCIENTIFIC_DOMAIN_GENERIC_ML_TRUST_ROOT_BASENAME,
)
from scientist_one.packaging import (
    PackagingError,
    _assert_gateway_trust_root_not_serialized,
)
from scientist_one.reproduction import (
    ReproductionError,
    _assert_scientific_domain_trust_root_not_serialized,
)


class ScientificDomainKeyBoundaryTests(unittest.TestCase):
    def test_domain_key_name_and_material_are_excluded_everywhere(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            registry = ArtifactRegistry(root, "runs/run-domain-key/registry")
            key_material = bytes(range(32))
            key_path = (
                root
                / registry.base_path
                / SCIENTIFIC_DOMAIN_GENERIC_ML_TRUST_ROOT_BASENAME
            )
            key_path.write_bytes(key_material)
            key_path.chmod(0o600)

            safe = {"packet.json": b'{"safe":true}\n'}
            _assert_gateway_trust_root_not_serialized(registry, safe)
            _assert_scientific_domain_trust_root_not_serialized(registry, safe)

            cases = (
                (
                    {
                        f"registry/{SCIENTIFIC_DOMAIN_GENERIC_ML_TRUST_ROOT_BASENAME}": b""
                    },
                    "path",
                ),
                (
                    {
                        "packet.json": (
                            SCIENTIFIC_DOMAIN_GENERIC_ML_TRUST_ROOT_BASENAME.encode(
                                "utf-8"
                            )
                        )
                    },
                    "name",
                ),
                ({"packet.bin": key_material}, "raw"),
                ({"packet.json": key_material.hex().encode("ascii")}, "hex"),
                (
                    {"packet.json": base64.b64encode(key_material)},
                    "base64",
                ),
            )
            for members, label in cases:
                with self.subTest(boundary="packaging", form=label):
                    with self.assertRaises(PackagingError):
                        _assert_gateway_trust_root_not_serialized(
                            registry,
                            members,
                        )
                with self.subTest(boundary="reproduction", form=label):
                    with self.assertRaises(ReproductionError):
                        _assert_scientific_domain_trust_root_not_serialized(
                            registry,
                            members,
                        )

    def test_unsafe_domain_key_fails_closed(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            registry = ArtifactRegistry(root, "runs/run-domain-key/registry")
            key_path = (
                root
                / registry.base_path
                / SCIENTIFIC_DOMAIN_GENERIC_ML_TRUST_ROOT_BASENAME
            )
            key_path.write_bytes(bytes(range(32)))
            key_path.chmod(0o644)

            with self.assertRaises(PackagingError):
                _assert_gateway_trust_root_not_serialized(
                    registry,
                    {"packet.json": b"{}\n"},
                )
            with self.assertRaises(ReproductionError):
                _assert_scientific_domain_trust_root_not_serialized(
                    registry,
                    {"packet.json": b"{}\n"},
                )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
