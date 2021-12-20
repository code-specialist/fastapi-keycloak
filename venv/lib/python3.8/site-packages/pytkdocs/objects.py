"""
This module defines the documented objects classes.

- the generic [`Object`][pytkdocs.objects.Object] class
- the [`Module`][pytkdocs.objects.Module] class
- the [`Class`][pytkdocs.objects.Class] class
- the [`Method`][pytkdocs.objects.Method] class
- the [`Function`][pytkdocs.objects.Function] class
- the [`Attribute`][pytkdocs.objects.Attribute] class

Note that properties are considered attributes, because they are used like such.

It also defines a convenient [`Source`][pytkdocs.objects.Source] class to represent source code.
"""

import importlib
import inspect
import os
import sys
from abc import ABCMeta
from functools import lru_cache
from pathlib import Path
from typing import List, Optional, Union

from pytkdocs.parsers.docstrings.base import Parser, Section
from pytkdocs.properties import NAME_CLASS_PRIVATE, NAME_PRIVATE, NAME_SPECIAL, ApplicableNameProperty


class Source:
    """
    Helper class to represent source code.

    It is simply used to wrap the result of
    [`inspect.getsourceslines`](https://docs.python.org/3/library/inspect.html#inspect.getsourcelines).
    """

    def __init__(self, lines: Union[str, List[str]], line_start: int) -> None:
        """
        Initialize the object.

        Arguments:
            lines: A list of strings. The strings should have trailing newlines.
            line_start: The line number of where the code starts in the file.
        """
        if isinstance(lines, list):
            code = "".join(lines)
        else:
            code = lines
        self.code = code
        """The code, as a single string."""
        self.line_start = line_start
        """The first line number."""


class Object(metaclass=ABCMeta):
    """
    A base class to store information about a Python object.

    Each instance additionally stores references to its children, grouped by category.
    """

    possible_name_properties: List[ApplicableNameProperty] = []
    """
    The properties that we can apply to the object based on its name.

    The applicable properties vary from one subclass of `Object` to another.
    """

    def __init__(
        self,
        name: str,
        path: str,
        file_path: str,
        docstring: Optional[str] = "",
        properties: Optional[List[str]] = None,
        source: Optional[Source] = None,
    ) -> None:
        """
        Initialize the object.

        Arguments:
            name: The object's name.
            path: The object's dotted-path.
            file_path: The file path of the object's direct parent module.
            docstring: The object's docstring.
            properties: The object's properties.
            source: The object's source code.
        """
        self.name = name
        """The object's name."""
        self.path = path
        """The object's dotted-path."""
        self.file_path = file_path
        """The file path of the object's direct parent module."""
        self.docstring = docstring
        """The object's docstring."""
        self.docstring_sections: List[Section] = []
        """The object's docstring parsed into sections."""
        self.docstring_errors: List[str] = []
        """The errors detected while parsing the docstring."""
        self.properties = properties or []
        """The object's properties."""
        self.parent: Optional[Object] = None
        """The object's parent (another instance of a subclass of `Object`)."""
        self.source = source
        """The object's source code."""

        self._path_map = {self.path: self}
        self._parsed = False

        self.attributes: List[Attribute] = []
        """The list of all the object's attributes."""
        self.methods: List[Method] = []
        """The list of all the object's methods."""
        self.functions: List[Function] = []
        """The list of all the object's functions."""
        self.modules: List[Module] = []
        """The list of all the object's submodules."""
        self.classes: List[Class] = []
        """The list of all the object's classes."""
        self.children: List[Object] = []
        """The list of all the object's children."""

    def __str__(self) -> str:
        return self.path

    @property
    def category(self) -> str:
        """
        Return the object's category.

        Returns:
            The object's category (module, class, function, method or attribute).
        """
        return self.__class__.__name__.lower()

    @property
    def root(self) -> "Object":
        """
        Return the object's root.

        Returns:
            The object's root (top-most parent).
        """
        obj = self
        while obj.parent:
            obj = obj.parent
        return obj  # type: ignore

    @property
    def relative_file_path(self) -> str:
        """
        Return the relative file path of the object.

        It is the relative path to the object's module,
        starting at the path of the top-most package it is contained in.

        For example:

        - package is `a`
        - package absolute path is `/abs/path/to/a`
        - module is `a.b.c`
        - object is `c` or anything defined in `c`
        - relative file path is `a/b/c.py`

        If the relative file path cannot be determined, the value returned is `""` (empty string).

        Returns:
            The path relative to the object's package.
        """
        parts = self.path.split(".")
        namespaces = [".".join(parts[:length]) for length in range(1, len(parts) + 1)]  # noqa: WPS221 (not complex)
        # Iterate through all sub namespaces including the last in case it is a module
        for namespace in namespaces:
            try:  # noqa: WPS229 (more compact)
                importlib.import_module(namespace)
                top_package = sys.modules[namespace]
            except (ModuleNotFoundError, ImportError, KeyError):
                # ImportError: Triggered if the namespace is not importable
                # ModuleNotFoundError: Triggered if the namespace is not a module
                # KeyError: Triggered if the imported package isn't referenced under the same fully qualified name
                # Namespace packages are importable, so this should work for them
                return ""

            try:  # noqa: WPS229 (more compact)
                top_package_path = Path(inspect.getabsfile(top_package)).parent
                return str(Path(self.file_path).relative_to(top_package_path.parent))
            except TypeError:
                # Triggered if getabsfile() can't be found in the case of a Namespace package
                pass  # noqa: WPS420 (passing is the only way)
            except ValueError:
                # Triggered if Path().relative_to can't find an appropriate path
                return ""

        return ""

    @property
    def name_to_check(self) -> str:
        """
        Return the attribute to check against name-properties regular expressions (private, class-private, special).

        Returns:
            The attribute to check (its name).
        """
        return self.name

    @property
    def name_properties(self) -> List[str]:
        """
        Return the object's name properties.

        Returns:
            The object's name properties (private, class-private, special).
        """
        properties = []
        for prop, predicate in self.possible_name_properties:
            if predicate(self.name_to_check):
                properties.append(prop)
        return properties

    @property
    def parent_path(self) -> str:
        """
        Return the parent's path, computed from the current path.

        The parent object path is not used: this property is used to see if an object is really related to another one,
        to add it as a child to the other. When we do that, the child doesn't even have a parent.

        Returns:
            The dotted path of the parent object.
        """
        return self.path.rsplit(".", 1)[0]

    def add_child(self, obj: "Object") -> None:  # noqa: WPS231 (not complex)
        """
        Add an object as a child of this object.

        If the child computed `parent_path` is not equal to this object's path, abort.

        Append the child to the `children` list, and to the right category list.

        Arguments:
            obj: An instance of documented object.
        """
        if obj.parent_path != self.path:
            return

        self.children.append(obj)
        if isinstance(obj, Module):
            self.modules.append(obj)  # type: ignore
        elif isinstance(obj, Class):
            self.classes.append(obj)  # type: ignore
        elif isinstance(obj, Function):
            self.functions.append(obj)  # type: ignore
        elif isinstance(obj, Method):
            self.methods.append(obj)  # type: ignore
        elif isinstance(obj, Attribute):
            # Dataclass attributes with default values will already be present in `self.attributes` as they are
            # resolved differently by the python interpreter. As they have a concrete value, they are already present
            # in the "original" class. They should be overridden with the new "dataclass" attribute coming in here
            # (having the "dataclass_field" property set)
            new_attribute_name = obj.name
            for attribute in self.attributes:
                if attribute.name == new_attribute_name:
                    self.attributes.remove(attribute)
            self.attributes.append(obj)  # type: ignore
        obj.parent = self

        self._path_map[obj.path] = obj

    def add_children(self, children: List["Object"]) -> None:
        """
        Add a list of objects as children of this object.

        Arguments:
            children: The list of children to add.
        """
        for child in children:
            self.add_child(child)

    def parse_docstring(self, parser: Parser, **context) -> None:
        """
        Parse the docstring of this object.

        Arguments:
            parser: A parser to parse the docstrings.
            **context: Additional context to use when parsing.
        """
        if self.docstring and not self._parsed:
            sections, errors = parser.parse(self.docstring, {"obj": self, **context})
            self.docstring_sections = sections
            self.docstring_errors = errors
            self._parsed = True

    def parse_all_docstrings(self, parser: Parser) -> None:
        """
        Recursively parse the docstring of this object and its children.

        Arguments:
            parser: A parser to parse the docstrings.
        """
        self.parse_docstring(parser)
        for child in self.children:
            child.parse_all_docstrings(parser)

    @lru_cache()
    def has_contents(self) -> bool:
        """
        Tells if the object has "contents".

        An object has contents when:

        - it is the root of the object tree
        - it has a docstring
        - at least one of its children (whatever the depth) has contents

        The value is cached, so this method should be called last, when the tree doesn't change anymore.

        Returns:
            Whether this object has contents or not.
        """
        has_docstring = bool(self.docstring)
        is_root = not self.parent
        children_have_contents = any(child.has_contents() for child in self.children)
        return has_docstring or is_root or children_have_contents


class Module(Object):
    """A class to store information about a module."""

    possible_name_properties: List[ApplicableNameProperty] = [NAME_SPECIAL, NAME_PRIVATE]

    @property
    def file_name(self) -> str:
        """
        Return the base name of the module file, without the extension.

        Returns:
            The module file's base name.
        """
        return os.path.splitext(os.path.basename(self.file_path))[0]

    @property
    def name_to_check(self) -> str:  # noqa: D102
        return self.file_name


class Class(Object):
    """A class to store information about a class."""

    possible_name_properties: List[ApplicableNameProperty] = [NAME_PRIVATE]

    def __init__(self, *args, bases: List[str] = None, **kwargs):
        """
        Initialize the object.

        Arguments:
            *args: Arguments passed to the parent class Initialize the object.
            bases: The base classes (dotted paths).
            **kwargs: Arguments passed to the parent class Initialize the object.
        """
        super().__init__(*args, **kwargs)
        self.bases = bases or ["object"]


class Function(Object):
    """
    A class to store information about a function.

    It accepts an additional `signature` argument at instantiation.
    """

    possible_name_properties: List[ApplicableNameProperty] = [NAME_PRIVATE]

    def __init__(self, *args, signature=None, **kwargs):
        """
        Initialize the object.

        Arguments:
            *args: Arguments passed to the parent class Initialize the object.
            signature: The function signature.
            **kwargs: Arguments passed to the parent class Initialize the object.
        """
        super().__init__(*args, **kwargs)
        self.signature = signature


class Method(Object):
    """
    A class to store information about a method.

    It accepts an additional `signature` argument at instantiation.
    """

    possible_name_properties: List[ApplicableNameProperty] = [NAME_SPECIAL, NAME_PRIVATE]

    def __init__(self, *args, signature=None, **kwargs):
        """
        Initialize the object.

        Arguments:
            *args: Arguments passed to the parent class Initialize the object.
            signature: The function signature.
            **kwargs: Arguments passed to the parent class Initialize the object.
        """
        super().__init__(*args, **kwargs)
        self.signature = signature


class Attribute(Object):
    """
    A class to store information about an attribute.

    It accepts an additional `attr_type` argument at instantiation.
    """

    possible_name_properties: List[ApplicableNameProperty] = [NAME_SPECIAL, NAME_CLASS_PRIVATE, NAME_PRIVATE]

    def __init__(self, *args, attr_type=None, **kwargs):
        """
        Initialize the object.

        Arguments:
            *args: Arguments passed to the parent class Initialize the object.
            attr_type: The attribute type.
            **kwargs: Arguments passed to the parent class Initialize the object.
        """
        super().__init__(*args, **kwargs)
        self.type = attr_type
