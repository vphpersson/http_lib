from dataclasses import dataclass
from typing import Type
from collections import deque
from ipaddress import IPv4Address, IPv6Address

from abnf.parser import Rule, Node
from abnf.grammars.misc import load_grammar_rules
from abnf.grammars import rfc7230
from abnf.grammars import rfc3986

from http_lib.parse.host import parse_host, IPvFutureString


# NOTE: The official, formal `IPv6address` rule requires backtracking, which the `abnf` library does not support.
@load_grammar_rules([
    ('IPv4address', rfc3986.Rule('IPv4address')),
])
class _ForwardedNodeRule(Rule):
    grammar = [
        'node = nodename [ ":" node-port ]',
        'IPv6address = 1*(%x21-5C / %x5E-7E)',
        'nodename = IPv4address / "[" IPv6address "]" / "unknown" / obfnode',
        'obfnode = "_" 1*( ALPHA / DIGIT / "." / "_" / "-")',
        'node-port = port / obfport',
        'port = 1*5DIGIT',
        'obfport = "_" 1*(ALPHA / DIGIT / "." / "_" / "-")'
    ]


@load_grammar_rules([
    ('tchar', rfc7230.Rule('tchar')),
    ('token', rfc7230.Rule('token')),
    ('quoted-pair', rfc7230.Rule('quoted-pair')),
    ('qdtext', rfc7230.Rule('qdtext')),
    ('obs-text', rfc7230.Rule('obs-text')),
    ('quoted-string', rfc7230.Rule('quoted-string')),
    ('OWS', rfc7230.Rule('OWS'))
])
class _ForwardedHeaderRule(Rule):
    grammar = [
        'value = token / quoted-string',
        'forwarded-pair = token "=" value',
        'forwarded-element = [ forwarded-pair ] *( ";" [ forwarded-pair ] )',
        'Forwarded = forwarded-element',

        'ForwardedValue = forwarded-element *( OWS "," [ OWS forwarded-element ] )',
        'ForwardedHeader = %s"Forwarded:" OWS ForwardedValue OWS'
    ]


@dataclass
class ForwardedElement:
    by_value: str | None = None
    for_value: str | None = None
    host_value: str | None = None
    proto_value: str | None = None


@dataclass
class ParameterParsedForwardedElement:
    by_value: tuple[str | IPv4Address | IPv6Address, int | None] | None = None
    for_value: tuple[str | IPv4Address | IPv6Address, int | None] | None = None
    host_value: tuple[str | IPvFutureString | IPv4Address | IPv6Address, int | None] | None = None
    proto_value: str | None = None


def parse_forwarded_header_value(
    forwarded_value: str,
    parse_parameter_values: bool = False
) -> list[ParameterParsedForwardedElement] | list[ForwardedElement]:
    """
    Parse the `Forwarded` header value.

    :param forwarded_value: The `Forwarded` header value to be parsed.
    :param parse_parameter_values: Whether to parse the parameter values.
    :return: A list of "forwarded-element" structures.
    """

    forwarded_elements: list[ForwardedElement] = []

    forwarded_element_nodes = [
        child
        for child in _ForwardedHeaderRule('ForwardedValue').parse_all(forwarded_value).children
        if child.name == 'forwarded-element'
    ]
    for forwarded_element_node in forwarded_element_nodes:
        parameters = []
        values = []

        queue: deque[Node] = deque([forwarded_element_node])
        while queue:
            current_node: Node = queue.popleft()
            if current_node.name == 'forwarded-pair':
                lowercase_parameter = current_node.children[0].value.lower()
                if lowercase_parameter in parameters:
                    raise ValueError(f'Multiple parameters with same field-value: {lowercase_parameter}')

                parameters.append(lowercase_parameter)

                if (value_node_child := current_node.children[2].children[0]).name == 'quoted-string':
                    value = ''.join(child.value for child in value_node_child.children if child.name != 'DQUOTE')
                else:
                    value = current_node.children[2].value

                if parse_parameter_values:
                    match lowercase_parameter:
                        case 'for' | 'by':
                            value_node: Node = _ForwardedNodeRule('node').parse_all(value)

                            port: int | None = None
                            if node_port := next((child for child in value_node.children if child.name == 'node-port'), None):
                                port = int(node_port.value)

                            value = value_node.value

                            if (ip_address_node := value_node.children[0].children[0]).name == 'IPv4address':
                                value = IPv4Address(ip_address_node.value), port
                            elif len(value_node.children[0].children) == 3:
                                value = IPv6Address(value_node.children[0].children[1].value), port
                        case 'host':
                            value = parse_host(host_value=value)

                values.append(value)

            else:
                queue.extend(current_node.children)

        constructor: Type[ParameterParsedForwardedElement | ForwardedElement] = (
            ParameterParsedForwardedElement if parse_parameter_values else ForwardedElement
        )
        forwarded_elements.append(
            constructor(
                **{f'{parameter}_value': value for parameter, value in zip(parameters, values)}
            )
        )

    return forwarded_elements
