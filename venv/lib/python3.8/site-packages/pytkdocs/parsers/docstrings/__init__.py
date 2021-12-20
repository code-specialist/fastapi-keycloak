"""The parsers' package."""

from typing import Dict, Type

from pytkdocs.parsers.docstrings.base import Parser, UnavailableParser
from pytkdocs.parsers.docstrings.google import Google
from pytkdocs.parsers.docstrings.restructured_text import RestructuredText

try:
    from pytkdocs.parsers.docstrings.numpy import Numpy
except ImportError:
    Numpy = UnavailableParser(  # type: ignore
        "pytkdocs must be installed with 'numpy-style' extra to parse Numpy docstrings"
    )


PARSERS: Dict[str, Type[Parser]] = {
    "google": Google,
    "restructured-text": RestructuredText,
    "numpy": Numpy,
}
