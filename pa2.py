"""Audit a network device inventory (XML) against a compliance policy (YAML)."""

import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import yaml


class AuditError(Exception):
    """Raised when an input file is missing, unreadable or invalid."""


def parse_version(text):
    """Turn a version string such as '15.10' into a tuple of ints (15, 10).

    Raises ValueError if any part is not a whole number.
    """
    parts = str(text).strip().split(".")
    for part in parts:
        if not (part.isascii() and part.isdigit()):
            raise ValueError(f"bad version: {text!r}")
    return tuple(int(part) for part in parts)


def compare_versions(first, second):
    """Compare two version tuples part by part.

    Returns -1, 0 or 1. Missing trailing parts count as zero, so 9.1.0 == 9.1.
    """
    size = max(len(first), len(second))
    first = first + (0,) * (size - len(first))
    second = second + (0,) * (size - len(second))
    return (first > second) - (first < second)