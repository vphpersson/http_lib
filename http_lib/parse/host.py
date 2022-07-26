from ipaddress import IPv4Address, IPv6Address
from typing import ByteString

from abnf_parse.rulesets.rfc9110 import RFC9110_RULESET


class IPvFutureString(str):
    def __init__(self, *args):
        super().__init__(*args)


def parse_host(
    host_value: ByteString | memoryview
) -> tuple[str | IPvFutureString | IPv4Address | IPv6Address, int | None]:
    """
    Parse a host value into a URI host and an optional port number.

    :param host_value: The host value to be parsed.
    :return: A URI host value and an optional port number.
    """

    host_node = RFC9110_RULESET['Host'].evaluate(source=host_value)

    port: int | None = (
        int(str(port_node))
        if (port_node := next(host_node.search(name='port', max_depth=2), None))
        else None
    )

    resolved_host_node = next(
        host_node.get_field(name='uri-host').search(
            name={'IPv4address', 'reg-name', 'IPv6address', 'IPvFuture'},
            max_depth=2
        )
    )

    match resolved_host_node.name:
        case 'IPv4address':
            return IPv4Address(str(resolved_host_node)), port
        case 'reg-name':
            return str(resolved_host_node), port
        case 'IPv6address':
            return IPv6Address(str(resolved_host_node)), port
        case 'IPvFuture':
            return IPvFutureString(str(resolved_host_node)), port
        case _:
            raise ValueError(f'Unexpected node name "{resolved_host_node.name}".')
