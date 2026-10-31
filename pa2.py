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
    
    def load_policy(path):
    """Read and validate the YAML policy with yaml.safe_load.

    Returns a dict. An empty file gives an empty policy (all checks off).
    Raises AuditError if the file is missing, invalid, or not a mapping.
    """
    try:
        with open(path, encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as error:
        raise AuditError(f"{path}: cannot read policy ({error})") from error
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise AuditError(f"{path}: policy must be a mapping")
    min_os = data.get("min_os")
    if min_os is not None:
        if not isinstance(min_os, dict):
            raise AuditError(f"{path}: min_os must be a mapping")
        for role, version in min_os.items():
            try:
                parse_version(version)
            except ValueError as error:
                raise AuditError(f"{path}: min_os for {role}: {error}") from error
    limit = data.get("max_down_interfaces")
    if limit is not None and (isinstance(limit, bool) or not isinstance(limit, int)):
        raise AuditError(f"{path}: max_down_interfaces must be a whole number")
    return data

    def check_device(device, policy):
    """Return the list of violation dicts for one device."""
    found = []
    min_os = policy.get("min_os")
    if min_os is not None:
        if device.role not in min_os:
            found.append({"device": device.device_id, "type": "unknown_role",
                          "role": device.role})
        else:
            required = str(min_os[device.role])
            try:
                outdated = compare_versions(
                    parse_version(device.os_version), parse_version(required)) < 0
            except ValueError:
                outdated = True  # an unreadable OS version cannot be shown current
            if outdated:
                found.append({"device": device.device_id, "type": "os_outdated",
                              "found": device.os_version, "required": required})
    if policy.get("require_owner") is True and not device.has_owner():
        found.append({"device": device.device_id, "type": "missing_owner"})
    limit = policy.get("max_down_interfaces")
    if limit is not None:
        down = device.interface_counts()["down"]
        if down > limit:
            found.append({"device": device.device_id, "type": "too_many_down",
                          "down": down})
    return found


def build_report(site, devices, skipped, policy):
    """Combine inventory and policy into the audit report dict."""
    roles = {}
    interfaces = {"up": 0, "down": 0, "other": 0}
    violations = []
    compliant = []
    for device in devices:
        roles[device.role] = roles.get(device.role, 0) + 1
        for key, value in device.interface_counts().items():
            interfaces[key] += value
        problems = check_device(device, policy)
        violations.extend(problems)
        if not problems:
            compliant.append(device.device_id)
    return {
        "site": site,
        "total_devices": len(devices),
        "skipped_devices": skipped,
        "roles": roles,
        "interfaces": interfaces,
        "violations": violations,
        "compliant": sorted(compliant),
    }