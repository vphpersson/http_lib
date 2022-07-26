from dataclasses import dataclass
from typing import ByteString
from ipaddress import IPv4Address, IPv6Address

from abnf_parse.rulesets.rfc7239 import RFC7239_RULESET

from http_lib.parse.host import parse_host, IPvFutureString


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
    forwarded_value: ByteString | memoryview,
    parse_parameter_values: bool = False
) -> list[ParameterParsedForwardedElement] | list[ForwardedElement]:
    """
    Parse the `Forwarded` header value.

    :param forwarded_value: The `Forwarded` header value to be parsed.
    :param parse_parameter_values: Whether to parse the parameter values.
    :return: A list of "forwarded-element" structures.
    """

    forwarded_elements: list[ForwardedElement] | list[ParameterParsedForwardedElement] = []

    forwarded_element_nodes = RFC7239_RULESET['Forwarded'].evaluate(
        source=forwarded_value
    ).search(name='forwarded-element', max_depth=2)

    for forwarded_element_node in forwarded_element_nodes:
        parameters: list[str] = []
        values: list[str] | list[str | tuple] = []

        for forwarded_pair_node in forwarded_element_node.search(name='forwarded-pair', max_depth=2):
            lowercase_parameter = str(forwarded_pair_node.get_field(name='token')).lower()
            if lowercase_parameter in parameters:
                raise ValueError(f'Multiple parameters with same field-value: {lowercase_parameter}')

            parameters.append(lowercase_parameter)

            value_node = forwarded_pair_node.get_field(name='value')
            if quoted_string_node := value_node.get_field(name='quoted-string'):
                value = quoted_string_node.source[
                    quoted_string_node.start_offset+1:quoted_string_node.end_offset-1
                ].tobytes()
            else:
                value = value_node.get_value()

            if parse_parameter_values:
                match lowercase_parameter:
                    case 'for' | 'by':
                        node_node = RFC7239_RULESET['node'].evaluate(source=value)

                        port: int | None = None
                        if node_port_node := next(node_node.search(name='node-port', max_depth=2), None):
                            port = int(str(node_port_node))

                        nodename_node = node_node.get_field(name='nodename')
                        if ipv4_address_node := nodename_node.get_field(name='IPv4address'):
                            value = IPv4Address(str(ipv4_address_node)), port
                        elif ipv6_address_node := next(nodename_node.search(name='IPv6address', max_depth=2), None):
                            value = IPv6Address(str(ipv6_address_node)), port
                        else:
                            value.decode()
                    case 'host':
                        value = parse_host(host_value=value)
                    case _:
                        value = value.decode()
            else:
                value = value.decode()

            values.append(value)

        if parse_parameter_values:
            constructor = ParameterParsedForwardedElement
        else:
            constructor = ForwardedElement

        forwarded_elements.append(
            constructor(
                **{f'{parameter}_value': value for parameter, value in zip(parameters, values)}
            )
        )

    return forwarded_elements
