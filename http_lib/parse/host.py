from ipaddress import IPv4Address, IPv6Address

from abnf.parser import Rule, Node
from abnf.grammars.misc import load_grammar_rules
from abnf.grammars import rfc3986


class IPvFutureString(str):
    def __init__(self, *args):
        super().__init__(*args)


# NOTE: The official, formal `IPv6address` rule requires backtracking, which the `abnf` library does not support.
@load_grammar_rules([
    ('IPv4address', rfc3986.Rule('IPv4address')),
    ('reg-name', rfc3986.Rule('reg-name')),
    ('IPvFuture', rfc3986.Rule('IPvFuture')),
    ('port', rfc3986.Rule('port'))
])
class _HostRule(Rule):
    grammar = [
        'host = uri-host [ ":" port ]',
        'uri-host = IP-literal / IPv4address / reg-name',
        'IP-literal = "[" ( IPv6address / IPvFuture ) "]"',
        'IPv6address = 1*(%x21-5C / %x5E-7E)'
    ]


def parse_host(host_value: str) -> tuple[str | IPvFutureString | IPv4Address | IPv6Address, int | None]:
    """
    Parse a host value into a URI host and an optional port number.

    :param host_value: The host value to be parsed.
    :return: A URI host value and an optional port number.
    """

    node: Node = _HostRule('host').parse_all(source=host_value)

    port: int | None = int(node.children[2].value) if len(node.children) == 3 else None

    match (uri_host_node := node.children[0].children[0]).name:
        case 'IPv4address':
            return IPv4Address(uri_host_node.value), port
        case 'IP-literal':
            return (
                IPv6Address(literal_ip_node.value)
                if (literal_ip_node := uri_host_node.children[1]).name == 'IPv6address' else IPvFutureString(literal_ip_node.value)
            ), port
        case 'reg-name':
            return uri_host_node.value, port
        case _:
            raise ValueError(f'Unexpected node name "{uri_host_node.name}".')
