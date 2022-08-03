from __future__ import annotations
from dataclasses import dataclass, field
from typing import ByteString, Type, Generator, ClassVar, AsyncIterable
from abc import ABC
from asyncio import StreamReader, wait_for
from re import compile as re_compile, Pattern, Match as ReMatch

from abnf_parse.rulesets.rfc9112 import RFC9112_RULESET
from abnf_parse.structures.match_node import MatchNode


FIELD_LINE_PATTERN: Pattern = re_compile(pattern=rb'.*\r\n')


def headers_from_bytes(data: ByteString | memoryview) -> list[tuple[str, str]]:
    """
    Turn bytes into a list of HTTP headers, i.e. field name-field value pairs.

    :param data: Data constituting the HTTP headers to be extracted.
    :return: A list of field name-field value pairs extracted from the data.
    """

    # TODO/NOTE: ABNF grammar is not used to check if the headers are in a correct format. I will probably rewrite or
    #  remove this function.

    data_memoryview = memoryview(data)

    headers: list[tuple[str, str]] = []
    field_line_re_match: ReMatch
    for field_line_re_match in FIELD_LINE_PATTERN.finditer(string=data_memoryview):
        field_line_content = data_memoryview[field_line_re_match.start(0):field_line_re_match.end(0) - 2]
        if not field_line_content:
            break

        name: bytes
        value: bytes
        name, value = field_line_content.tobytes().split(sep=b': ', maxsplit=1)

        headers.append((name.decode(), value.strip().decode()))

    return headers


@dataclass
class StartLine(ABC):
    MESSAGE_TYPE: ClassVar[Type[Message]] = NotImplemented

    http_version: str | None = None

    @classmethod
    def from_abnf_node(cls, node: MatchNode) -> RequestLine | StatusLine:
        match node.name:
            case 'request-line':
                return RequestLine(
                    method=str(node.get_field(name='method')),
                    request_target=str(node.get_field(name='request-target')),
                    http_version=str(node.get_field(name='HTTP-version'))
                )
            case 'status-line':
                return StatusLine(
                    http_version=str(node.children[0].get_field(name='HTTP-version')),
                    status_code=int(str(node.children[0].get_field(name='status-code'))),
                    reason_phrase=(
                        str(reason_phrase_node)
                        if (reason_phrase_node := node.get_field(name='reason-phrase'))
                        else None
                    )
                )
            case _:
                raise ValueError(f'Unexpected start-line type: {node.name}')

    @classmethod
    def from_bytes(cls, data: ByteString | memoryview) -> StartLine:
        start_line = cls.from_abnf_node(node=RFC9112_RULESET['start-line'].evaluate(source=data).children[0])
        if cls != StartLine and not isinstance(start_line, cls):
            raise ValueError('The data does not constitute an start line of the specified type.')

        return start_line


@dataclass
class Message(ABC):
    start_line: StartLine | None = None
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: memoryview | None = None
    raw: memoryview | None = None

    @classmethod
    def from_bytes(cls, data: ByteString | memoryview, store_raw: bool = False) -> Message:
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
                    start_line = StartLine.from_abnf_node(node=node.children[0])
                    message_constructor = start_line.MESSAGE_TYPE
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


async def message_body_from_reader(
    reader: StreamReader,
    headers: list[tuple[str, str]],
    timeout: float | None = None
) -> AsyncIterable[bytes]:
    """
    Provide HTTP message body parts from a reader.

    :param reader: The reader from which to read body parts.
    :param headers: HTTP headers that describe how the body parts should be read.
    :param timeout: The maximum number of seconds to wait before timing out when reading.
    :return: An iterator yielding body parts from the reader.
    """

    content_length: int | None = None
    transfer_encoding: str | None = None
    chunked = False
    includes_trailers: bool | None = None

    name: str
    value: str
    for (name, value) in headers:
        match name.lower():
            case 'content-length':
                if content_length is not None:
                    raise ValueError('Content length has already been set.')
                content_length = int(value)
            case 'transfer-encoding':
                if transfer_encoding is not None:
                    raise ValueError('Transfer encoding has already been set.')
                if value.lower() == 'chunked':
                    chunked = True
            case 'trailers':
                if includes_trailers is not None:
                    raise ValueError('Trailers has already been set.')
                includes_trailers = True

    if chunked:
        chunk_size_bytes: bytes
        while chunk_size_bytes := await wait_for(fut=reader.readuntil(separator=b'\r\n'), timeout=timeout):
            num_content_bytes = int(chunk_size_bytes.decode()[:-2], base=16)

            if num_content_bytes == 0:
                break

            # Read the chunk, including a trailing CRLF.
            chunk_bytes = await wait_for(
                fut=reader.readexactly(n=num_content_bytes + 2),
                timeout=timeout
            )

            yield chunk_size_bytes + chunk_bytes

        if includes_trailers:
            while trailer := await wait_for(fut=reader.readuntil(separator=b'\r\n'), timeout=timeout):
                yield trailer

                if trailer == b'\r\n':
                    break
        else:
            crlf = await wait_for(fut=reader.readuntil(separator=b'\r\n'), timeout=timeout)
            if len(crlf) != 2:
                raise ValueError('Additional data after body.')

            yield chunk_size_bytes + crlf
    elif content_length is not None:
        yield await wait_for(fut=reader.readexactly(n=content_length), timeout=timeout)


async def message_parts_from_reader(
    reader: StreamReader,
    timeout: float | None = None
) -> Generator[bytes, list[tuple[str, str]], None]:
    """
    Provide HTTP message parts from a reader.

    :param reader: A `StreamReader` from which to read message data.
    :param timeout: The maximum time to wait when reading message data.
    :return: A generator that yield HTTP message parts and that accept parsed HTTP headers from which it learns how to
        read the message body parts.
    """

    # Yield the start line bytes.

    yield await wait_for(fut=reader.readuntil(separator=b'\r\n'), timeout=timeout)

    # Yield the header bytes.

    header_bytearray = bytearray()

    field_line_bytes: bytes
    while field_line_bytes := await wait_for(fut=reader.readuntil(separator=b'\r\n'), timeout=timeout):
        header_bytearray += field_line_bytes
        if field_line_bytes == b'\r\n':
            break

    # Yield the header bytes and wait parsed headers to be sent.
    headers = yield bytes(header_bytearray)
    yield

    # Yield body bytes.

    async for body in message_body_from_reader(reader=reader, headers=headers, timeout=timeout):
        yield body


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


@dataclass
class RequestLine(StartLine):
    MESSAGE_TYPE: ClassVar[Type[Message]] = Request

    method: str | None = None
    request_target: str | None = None


@dataclass
class StatusLine(StartLine):
    MESSAGE_TYPE: ClassVar[Type[Message]] = Response

    status_code: int | None = None
    reason_phrase: str | None = None

    def __bytes__(self) -> bytes:
        return b' '.join([self.http_version.encode(), str(self.status_code).encode(), self.reason_phrase.encode()])
