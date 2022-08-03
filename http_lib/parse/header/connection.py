from typing import ByteString

from abnf_parse.rulesets.rfc9110 import RFC9110_RULESET


def parse_connection(connection_value: ByteString | bytes | str) -> list[str]:
    """
    Parse a `Connection` header value.

    :param connection_value: The `Connection` header value to be parsed.
    :return: A list of connection options parsed from the `Connection` header value.
    """

    connection_node = RFC9110_RULESET['Connection'].evaluate(source=connection_value)
    return [
        str(connection_option_node)
        for connection_option_node in connection_node.search(name='connection-option', max_depth=2)
    ]
