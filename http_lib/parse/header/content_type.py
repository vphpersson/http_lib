from dataclasses import dataclass, field
from typing import ByteString

from abnf_parse.rulesets.rfc9110 import RFC9110_RULESET


@dataclass
class MediaType:
    type: str
    subtype: str
    parameters: list[tuple[str, str]] = field(default_factory=list)

    @property
    def full_type(self) -> str:
        return f'{self.type}/{self.subtype}'


def parse_content_type(content_type_value: ByteString | memoryview | str) -> MediaType | None:

    if not content_type_value:
        return None

    content_type_node = RFC9110_RULESET['Content-Type'].evaluate(source=content_type_value)
    if not content_type_node:
        return None

    media_type_type: str | None = None
    media_type_subtype: str | None = None
    parameters: list[tuple[str, str]] = []

    for node in content_type_node.search(name={'type', 'subtype', 'parameter'}):
        match node.name:
            case 'type':
                media_type_type = str(node)
            case 'subtype':
                media_type_subtype = str(node)
            case 'parameter':
                parameter_value_node = node.get_field(name='parameter-value')
                if quoted_string_node := parameter_value_node.get_field(name='quoted-string'):
                    value = quoted_string_node.source[
                        quoted_string_node.start_offset+1:quoted_string_node.end_offset-1
                    ].tobytes()
                else:
                    value = parameter_value_node.get_value()

                parameters.append((str(node.get_field(name='parameter-name')), value.decode()))

    return MediaType(type=media_type_type, subtype=media_type_subtype, parameters=parameters)
