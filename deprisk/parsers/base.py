"""Manifest parser interface and registry."""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from typing import List, Optional, Tuple

from ..models import Dependency, Ecosystem, RuntimeInfo


class ManifestParser(ABC):
    ecosystem: Ecosystem
    filenames: List[str] = []

    @abstractmethod
    def parse(self, root: str, path: str) -> Tuple[List[Dependency], List[RuntimeInfo]]:
        """Parse a manifest file into dependencies and runtime info."""


PARSERS: List[ManifestParser] = []


def register(parser_cls):
    PARSERS.append(parser_cls())
    return parser_cls


def detect_manifests(root: str, ecosystems: Optional[List[Ecosystem]] = None) -> List[str]:
    found: List[str] = []
    allowed = set(ecosystems) if ecosystems else None
    for parser in PARSERS:
        if allowed and parser.ecosystem not in allowed:
            continue
        for name in parser.filenames:
            p = os.path.join(root, name)
            if os.path.isfile(p):
                found.append(p)
    return sorted(found)


def parse_manifest(root: str, path: str) -> Tuple[List[Dependency], List[RuntimeInfo]]:
    base = os.path.basename(path)
    for parser in PARSERS:
        if base in parser.filenames:
            return parser.parse(root, path)
    return [], []
