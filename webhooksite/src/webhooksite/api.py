"""Compatibility seam for callers that want the generated HTTP operation."""

from .transport import fetch, load_contract, request_endpoint

__all__ = ["fetch", "load_contract", "request_endpoint"]
