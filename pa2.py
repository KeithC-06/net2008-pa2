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

    class Device:
    """One network device from the inventory."""

    def __init__(self, device_id, role, os_version, owner, interfaces):
        """Store the attributes; interfaces is a list of status strings."""
        self.device_id = device_id
        self.role = role
        self.os_version = os_version
        self.owner = owner
        self.interfaces = interfaces

    @classmethod
    def from_element(cls, element):
        """Build a Device from an XML <device> element."""
        owner_element = element.find("owner")
        owner = owner_element.text if owner_element is not None else None
        statuses = [i.get("status") for i in element.findall("interface")]
        return cls(
            element.get("id"),
            element.get("role", ""),
            element.get("os", ""),
            owner,
            statuses,
        )

    def has_owner(self):
        """Return True if the owner is present and not just spaces."""
        return self.owner is not None and self.owner.strip() != ""

    def interface_counts(self):
        """Count interfaces as up, down or other (any other status)."""
        counts = {"up": 0, "down": 0, "other": 0}
        for status in self.interfaces:
            key = status if status in ("up", "down") else "other"
            counts[key] += 1
        return counts


def load_inventory(path):
    """Read the XML inventory.

    Returns (site, devices, skipped). Devices without an id are skipped.
    Raises AuditError if the file is missing or not valid XML.
    """
    try:
        with open(path, "rb") as handle:
            root = ET.parse(handle).getroot()
    except (OSError, ET.ParseError) as error:
        raise AuditError(f"{path}: cannot read inventory ({error})") from error
    if root.tag != "inventory":
        raise AuditError(f"{path}: root element must be <inventory>")
    devices = []
    skipped = 0
    for element in root.findall("device"):
        if element.get("id") is None:
            skipped += 1
        else:
            devices.append(Device.from_element(element))
    return root.get("site"), devices, skipped