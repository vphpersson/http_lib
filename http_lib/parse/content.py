from typing import AnyStr
from gzip import decompress as gzip_decompress


def decompress_body(body: AnyStr, mime_type: str) -> bytes | None:
    """
    Decompress a body based on a mime type.

    :param body: A body to be compressed.
    :param mime_type: The mime type of the body.
    :return: A decompressed version of body if the mime type is supported, else `None`.
    """

    if isinstance(body, str):
        body = body.encode(encoding='charmap')

    match mime_type:
        case 'application/gzip':
            return gzip_decompress(data=body)
        case _:
            return None
