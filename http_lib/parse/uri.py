from dataclasses import dataclass
from urllib.parse import urlparse, parse_qsl, ParseResult
from ipaddress import IPv6Address

from public_suffix.structures.public_suffix_list_trie import PublicSuffixListTrie, DomainProperties

from http_lib.parse.host import parse_host, IPvFutureString


@dataclass
class ParsedURI:
    scheme: str | None = None
    host: str | None = None
    path: str | None = None
    query: str | None = None
    fragment: str | None = None
    username: str | None = None
    port: int | None = None
    password: str | None = None

    registered_domain: str | None = None
    subdomain: str | None = None
    top_level_domain: str | None = None


def parse_query_string(query_string: str) -> list[tuple[str, str]]:
    return parse_qsl(qs=query_string, keep_blank_values=True)


def parse_uri(uri_string: str, public_suffix_trie: PublicSuffixListTrie | None = None):

    parsed_url: ParseResult = urlparse(url=uri_string)

    host: str | None = None
    registered_domain: str | None = None
    subdomain: str | None = None
    top_level_domain: str | None = None

    if parsed_url.netloc:
        uri_host, _ = parse_host(host_value=parsed_url.netloc)

        host = str(uri_host)

        if isinstance(uri_host, str) and not isinstance(uri_host, IPvFutureString) and public_suffix_trie:
            domain_properties: DomainProperties | None = public_suffix_trie.get_domain_properties(domain=host)

            registered_domain = domain_properties.registered_domain
            subdomain = domain_properties.subdomain
            top_level_domain = domain_properties.effective_top_level_domain
        elif isinstance(uri_host, IPv6Address):
            host = f'[{host}]'

    port: int | None = parsed_url.port

    if not parsed_url.port:
        match parsed_url.scheme:
            case 'http':
                port = 80
            case 'https':
                port = 443

    return ParsedURI(
        scheme=parsed_url.scheme,
        host=host,
        path=parsed_url.path,
        query=parsed_url.query,
        fragment=parsed_url.fragment,
        username=parsed_url.username,
        password=parsed_url.password,
        port=port,
        registered_domain=registered_domain,
        subdomain=subdomain,
        top_level_domain=top_level_domain
    )
