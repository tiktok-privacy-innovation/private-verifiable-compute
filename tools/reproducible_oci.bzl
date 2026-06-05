"""Helpers for reproducible OCI image layers via rules_pkg and rules_oci."""

load("@rules_oci//oci:defs.bzl", _oci_image = "oci_image")
load("@rules_pkg//pkg:tar.bzl", _pkg_tar = "pkg_tar")

# Use portable_mtime so archive metadata does not depend on local file mtimes.
# SOURCE_DATE_EPOCH from --config=reproducible is honored by packaging actions.
_REPRODUCIBLE_PKG_TAR_KWARGS = {
    "portable_mtime": True,
}

def reproducible_pkg_tar(name, **kwargs):
    """pkg_tar wrapper with deterministic archive metadata."""
    _pkg_tar(
        name = name,
        **(_REPRODUCIBLE_PKG_TAR_KWARGS | kwargs)
    )

def reproducible_oci_image(name, **kwargs):
    """oci_image wrapper; keep layer order explicit in kwargs."""
    _oci_image(
        name = name,
        **kwargs
    )
