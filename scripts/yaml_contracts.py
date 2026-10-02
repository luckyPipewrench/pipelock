# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0
"""Load validation inputs without silently accepting duplicate mapping keys."""

import sys

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required; install .github/requirements-pr-review-test.txt with pip --require-hashes")


class UniqueKeyLoader(yaml.SafeLoader):
    pass


def construct_mapping(loader, node):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        if key in result:
            raise ValueError(f"duplicate YAML key: {key}")
        result[key] = loader.construct_object(value_node)
    return result


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_mapping
)
