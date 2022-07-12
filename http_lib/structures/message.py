from dataclasses import dataclass, field
from typing import ByteString, Type
from abc import ABC
from collections import deque

from abnf import Node
from abnf.grammars import rfc7230


@dataclass
class RequestLine:
    method: str
    request_target: str
    http_version: str


@dataclass
class StatusLine:
    http_version: str
    status_code: int
    reason_phrase: str


@dataclass
class Message(ABC):
    start_line: RequestLine | StatusLine | None = None
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: str | None = None
    raw: str | None = None

    @classmethod
    def from_string(cls, string: str, store_raw: bool = False) -> 'Message':
        http_message_node: Node = rfc7230.Rule('HTTP-message').parse_all(source=string)

        start_line: RequestLine | StatusLine | None = None
        headers: list[tuple[str, str]] = []
        body = ''

        message_constructor: Type[Request | Response] | None = None

        queue: deque[Node] = deque([http_message_node])
        while queue:
            current_node: Node = queue.popleft()

            match current_node.name:
                case 'start-line':
                    match (start_line_child := current_node.children[0]).name:
                        case 'request-line':
                            message_constructor = Request
                            start_line = RequestLine(
                                method=start_line_child.children[0].value,
                                request_target=start_line_child.children[2].value,
                                http_version=start_line_child.children[4].value
                            )
                        case 'status-line':
                            message_constructor = Response
                            start_line = StatusLine(
                                http_version=start_line_child.children[0].value,
                                status_code=int(start_line_child.children[2].value),
                                reason_phrase=start_line_child.children[4].value
                            )
                        case _:
                            raise ValueError(f'Unexpected start-line type: {start_line_child.name}')
                case 'header-field':
                    headers.append(
                        (
                            current_node.children[0].value,
                            (
                                field_value_node.value
                                if (field_value_node := next((node for node in current_node.children[1:] if node.name == 'field-value'), None))
                                else ''
                            )
                        )
                    )
                case 'message-body':
                    body = current_node.value
                case _:
                    queue.extend(current_node.children)

        return message_constructor(start_line=start_line, headers=headers, body=body, raw=string if store_raw else None)

    @classmethod
    def from_bytes(cls, byte_string: ByteString) -> 'Message':
        return cls.from_string(string=bytes(byte_string).decode(encoding='charmap'))


@dataclass
class Request(Message):

    @property
    def request_line(self) -> RequestLine:
        return self.start_line


@dataclass
class Response(Message):

    @property
    def status_line(self) -> StatusLine:
        return self.start_line
