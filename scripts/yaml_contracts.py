# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0
"""Load validation inputs without silently accepting duplicate mapping keys."""

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
