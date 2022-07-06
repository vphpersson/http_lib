from dataclasses import dataclass
from collections import deque

from abnf.grammars import rfc7231
from abnf import Node


@dataclass
class Product:
    name: str
    version: str | None = None


def parse_user_agent_value(user_agent_value: str) -> tuple[list[Product], list[str]]:
    """
    Parse a user agent string.

    :param user_agent_value: A user agent string to be parsed.
    :return: A list of products and a list of comments parsed from the user agent string.
    """

    node: Node = rfc7231.Rule('User-Agent').parse_all(source=user_agent_value)

    products: list[Product] = []
    comments: list[str] = []

    queue: deque[Node] = deque([node])
    while queue:
        current_node: Node = queue.popleft()

        match current_node.name:
            case 'product':
                product_name_node: Node
                product_version_node: Node | None

                product_name_node, _, product_version_node = current_node.children

                products.append(
                    Product(
                        name=product_name_node.value,
                        version=product_version_node.value if product_version_node else None
                    )
                )
            case 'comment':
                comments.append(current_node.value)
            case _:
                queue.extend(current_node.children)

    return products, comments
