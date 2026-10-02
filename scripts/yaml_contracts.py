# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0
"""Load validation inputs without silently accepting duplicate mapping keys."""

import re
import sys

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required; install .github/requirements-pr-review-test.txt with pip --require-hashes")


class UniqueKeyLoader(yaml.SafeLoader):
    def __init__(self, stream):
        super().__init__(stream)
        self.validated_mappings = set()

    def flatten_mapping(self, node):
        # Validate the original keys before SafeLoader expands merges. Merged
        # defaults may overlap each other or be overridden by explicit keys.
        if node not in self.validated_mappings:
            self.validated_mappings.add(node)
            keys = set()
            for key_node, _ in node.value:
                if key_node.tag == "tag:yaml.org,2002:merge":
                    continue
                key = self.construct_object(key_node)
                if key in keys:
                    raise ValueError(f"duplicate YAML key: {key}")
                keys.add(key)
        super().flatten_mapping(node)


class WorkflowLoader(UniqueKeyLoader):
    """Resolve plain scalars using the YAML 1.2 core schema used by workflows."""

    # YAML 1.2.2 section 10.3.2 defines these scalar spellings.
    integer = re.compile(r"(?:[-+]?[0-9]+|0o[0-7]+|0x[0-9a-fA-F]+)\Z")
    floating = re.compile(r"(?:[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)(?:[eE][-+]?[0-9]+)?|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))\Z")

    def resolve(self, kind, value, implicit):
        if kind is yaml.ScalarNode and implicit[0]:
            tag = "str"
            if value in ("", "~", "null", "Null", "NULL"):
                tag = "null"
            elif value in ("true", "True", "TRUE", "false", "False", "FALSE"):
                tag = "bool"
            elif self.integer.fullmatch(value):
                tag = "int"
            elif self.floating.fullmatch(value):
                tag = "float"
            elif value == "<<":
                tag = "merge"
            return "tag:yaml.org,2002:" + tag
        return super().resolve(kind, value, implicit)

    def construct_core_int(self, node):
        value = self.construct_scalar(node)
        if not self.integer.fullmatch(value):
            raise ValueError("unsupported workflow integer spelling")
        return int(value, 8 if value.startswith("0o") else 16 if value.startswith("0x") else 10)


WorkflowLoader.add_constructor("tag:yaml.org,2002:int", WorkflowLoader.construct_core_int)
