from urllib import request as _ur, parse as _up
from html.parser import HTMLParser


class HTMLParserWithHandler(HTMLParser):
    def __init__(self, handler, *args, **kwargs):
        self.__handler = handler
        super().__init__(*args, **kwargs)

    handle_starttag = property(lambda self: self.__handler.handle_starttag)
    handle_endtag = property(lambda self: self.__handler.handle_endtag)
    handle_data = property(lambda self: self.__handler.handle_data)


class PyPISimpleIndexHandler:
    def __init__(self):
        self.tags = []
        self._current_tag = None

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._current_tag = d = dict(attrs)
            self.tags.append(d)

    def handle_endtag(self, tag):
        if tag == "a":
            self._current_tag = None

    def handle_data(self, data):
        if (d := self._current_tag) is not None:
            d[""] = data

    @classmethod
    def parse(cls, parser_factory, text):
        h = cls()
        parser = parser_factory(handler=h)
        parser.feed(text)
        return h.tags


def pypi_resolve_url(url: str):
    """
    Turn "pypi:https://pypi.org/simple/pure-radix/#/pure_radix-2.1.0-py3-none-any.whl" into the
    actual URL which downloads that wheel file.
    """
    if url.startswith("pypi:"):
        url = url[len("pypi:") :]
    else:
        return url

    u = _up.urlsplit(url)
    filename = _up.unquote(u.fragment).strip("/")
    project_url = u._replace(fragment="").geturl()

    with _ur.urlopen(project_url) as f:
        data = f.read()

    links = PyPISimpleIndexHandler.parse(
        HTMLParserWithHandler, data.decode("utf-8", errors="replace")
    )
    for link in links:
        if link.get("") == filename:
            return link["href"]

    raise ValueError(f"could not resolve {url}")
