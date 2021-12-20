"""This module simply defines regular expressions and their associated predicates."""

import re
from typing import Callable, Pattern, Tuple

ApplicableNameProperty = Tuple[str, Callable[[str], bool]]

# exactly two leading underscores, exactly two trailing underscores
# since we enforce one non-underscore after the two leading underscores,
# we put the rest in an optional group
RE_SPECIAL: Pattern = re.compile(r"^__[^_]([\w_]*[^_])?__$")
"""Regular expression to match `__special__` names."""

# at least two leading underscores, at most one trailing underscore
# since we enforce one non-underscore before the last,
# we make the previous characters optional with an asterisk
RE_CLASS_PRIVATE: Pattern = re.compile(r"^__[\w_]*[^_]_?$")
"""Regular expression to match `__class_private` names."""

# at most one leading underscore, then whatever
RE_PRIVATE: Pattern = re.compile(r"^_[^_][\w_]*$")
"""Regular expression to match `_private` names."""

NAME_SPECIAL: ApplicableNameProperty = ("special", lambda name: bool(RE_SPECIAL.match(name)))
"""Applicable property: `special`."""

NAME_CLASS_PRIVATE: ApplicableNameProperty = ("class-private", lambda name: bool(RE_CLASS_PRIVATE.match(name)))
"""Applicable property: `class-private`."""

NAME_PRIVATE: ApplicableNameProperty = ("private", lambda name: bool(RE_PRIVATE.match(name)))
"""Applicable property: `private`."""
