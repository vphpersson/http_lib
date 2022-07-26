from dataclasses import dataclass, field
from typing import ByteString, Type
from abc import ABC

from abnf_parse.rulesets.rfc9112 import RFC9112_RULESET


@dataclass
class StartLine(ABC):
    http_version: str | None = None


@dataclass
class RequestLine(StartLine):
    method: str | None = None
    request_target: str | None = None


@dataclass
class StatusLine(StartLine):
    status_code: int | None = None
    reason_phrase: str | None = None


@dataclass
class Message(ABC):
    start_line: StartLine | None = None
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: memoryview | None = None
    raw: memoryview | None = None

    @classmethod
    def from_bytes(cls, data: ByteString | memoryview, store_raw: bool = False) -> 'Message':
        """
        Make an HTTP message from a byte string.

        :param data: Data constituting an HTTP message to be parsed.
        :param store_raw: Whether to store the raw data in the resulting structure.
        :return: A structure constituting an HTTP message made from the input byte string.
        """

        http_message_node = RFC9112_RULESET['HTTP-message'].evaluate(source=data)

        start_line: RequestLine | StatusLine | None = None
        headers: list[tuple[str, str]] = []
        body = None

        message_constructor: Type[Request | Response] | None = None

        for node in http_message_node.search(name={'start-line', 'field-line', 'message-body'}):
            match node.name:
                case 'start-line':
                    match (start_line_child := node.children[0]).name:
                        case 'request-line':
                            message_constructor = Request
                            start_line = RequestLine(
                                method=str(start_line_child.get_field(name='method')),
                                request_target=str(start_line_child.get_field(name='request-target')),
                                http_version=str(start_line_child.get_field(name='HTTP-version'))
                            )
                        case 'status-line':
                            message_constructor = Response
                            start_line = StatusLine(
                                http_version=str(start_line_child.get_field(name='HTTP-version')),
                                status_code=int(str(start_line_child.get_field(name='status-code'))),
                                reason_phrase=(
                                    str(reason_phrase_node)
                                    if (reason_phrase_node := start_line_child.get_field(name='reason-phrase'))
                                    else None
                                )
                            )
                        case _:
                            raise ValueError(f'Unexpected start-line type: {start_line_child.name}')

                    if cls != Message and cls != message_constructor:
                        raise ValueError('The data does not constitute an HTTP message of the specified type.')

                case 'field-line':
                    headers.append((str(node.get_field(name='field-name')), str(node.get_field(name='field-value'))))
                case 'message-body':
                    body = node.source

        return message_constructor(
            start_line=start_line,
            headers=headers,
            body=body,
            raw=memoryview(data) if store_raw else None
        )


@dataclass
class Request(Message):

    @property
    def request_line(self) -> RequestLine | None:
        return self.start_line


@dataclass
class Response(Message):

    @property
    def status_line(self) -> StatusLine | None:
        return self.start_line
