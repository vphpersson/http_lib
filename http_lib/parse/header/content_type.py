from dataclasses import dataclass, field
from collections import deque

from abnf.grammars import rfc7231
from abnf import Node


@dataclass
class MediaType:
    type: str
    subtype: str
    parameters: list[tuple[str, str]] = field(default_factory=list)

    @property
    def full_type(self) -> str:
        return f'{self.type}/{self.subtype}'


def parse_content_type(content_type_value: str) -> MediaType | None:

    if not content_type_value:
        return None

    node: Node = rfc7231.Rule(name='Content-Type').parse_all(source=content_type_value)

    media_type_type: str | None = None
    media_type_subtype: str | None = None
    parameters: list[tuple[str, str]] = []

    queue: deque[Node] = deque([node])
    while queue:
        current_node: Node = queue.popleft()

        match current_node.name:
            case 'type':
                media_type_type: str = current_node.value
            case 'subtype':
                media_type_subtype: str = current_node.value
            case 'parameter':
                key: str = current_node.children[0].value
                value_node: Node = current_node.children[2]

                if value_node.name == 'quoted-string':
                    value: str = ''.join(child.value for child in value_node.children if child.name != 'DQUOTE')
                else:
                    value: str = value_node.value

                parameters.append((key, value))
            case _:
                queue.extend(current_node.children)

    return MediaType(type=media_type_type, subtype=media_type_subtype, parameters=parameters)
