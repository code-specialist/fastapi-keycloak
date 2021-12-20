"""
This module is responsible for loading the documentation from Python objects.

It uses [`inspect`](https://docs.python.org/3/library/inspect.html) for introspecting objects,
iterating over their members, etc.
"""

import importlib
import inspect
import pkgutil
import re
from functools import lru_cache
from itertools import chain
from operator import attrgetter
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Set, Tuple, Union

from pytkdocs.objects import Attribute, Class, Function, Method, Module, Object, Source
from pytkdocs.parsers.attributes import get_class_attributes, get_instance_attributes, get_module_attributes, merge
from pytkdocs.parsers.docstrings import PARSERS
from pytkdocs.properties import RE_SPECIAL

try:
    from functools import cached_property  # type: ignore
except ImportError:
    from cached_property import cached_property  # type: ignore


class ObjectNode:
    """
    Helper class to represent an object tree.

    It's not really a tree but more a backward-linked list:
    each node has a reference to its parent, but not to its child (for simplicity purposes and to avoid bugs).

    Each node stores an object, its name, and a reference to its parent node.
    """

    def __init__(self, obj: Any, name: str, parent: Optional["ObjectNode"] = None) -> None:
        """
        Initialize the object.

        Arguments:
            obj: A Python object.
            name: The object's name.
            parent: The object's parent node.
        """
        try:
            obj = inspect.unwrap(obj)
        except Exception:  # noqa: S110,W0703 (we purposely catch every possible exception)
            # inspect.unwrap at some point runs hasattr(obj, "__wrapped__"),
            # which triggers the __getattr__ method of the object, which in
            # turn can raise various exceptions. Probably not just __getattr__.
            # See https://github.com/pawamoy/pytkdocs/issues/45
            pass  # noqa: WPS420 (no other way than passing)

        self.obj: Any = obj
        """The actual Python object."""

        self.name: str = name
        """The Python object's name."""

        self.parent: Optional[ObjectNode] = parent
        """The parent node."""

    @property
    def dotted_path(self) -> str:
        """
        Return the Python dotted path to the object.

        Returns:
            The Python dotted path to the object.
        """
        parts = [self.name]
        current = self.parent
        while current:
            parts.append(current.name)
            current = current.parent
        return ".".join(reversed(parts))

    @property
    def file_path(self) -> str:
        """
        Return the object's module file path.

        Returns:
            The object's module file path.
        """
        return inspect.getabsfile(self.root.obj)

    @property
    def root(self) -> "ObjectNode":
        """
        Return the root of the tree.

        Returns:
            The root of the tree.
        """
        if self.parent is not None:
            return self.parent.root
        return self

    def is_module(self) -> bool:
        """
        Tell if this node's object is a module.

        Returns:
            The root of the tree.
        """
        return inspect.ismodule(self.obj)

    def is_class(self) -> bool:
        """
        Tell if this node's object is a class.

        Returns:
            If this node's object is a class.
        """
        return inspect.isclass(self.obj)

    def is_function(self) -> bool:
        """
        Tell if this node's object is a function.

        Returns:
            If this node's object is a function.
        """
        return inspect.isfunction(self.obj)

    def is_coroutine_function(self) -> bool:
        """
        Tell if this node's object is a coroutine.

        Returns:
            If this node's object is a coroutine.
        """
        return inspect.iscoroutinefunction(self.obj)

    def is_property(self) -> bool:
        """
        Tell if this node's object is a property.

        Returns:
            If this node's object is a property.
        """
        return isinstance(self.obj, property) or self.is_cached_property()

    def is_cached_property(self) -> bool:
        """
        Tell if this node's object is a cached property.

        Returns:
            If this node's object is a cached property.
        """
        return isinstance(self.obj, cached_property)

    def parent_is_class(self) -> bool:
        """
        Tell if the object of this node's parent is a class.

        Returns:
            If the object of this node's parent is a class.
        """
        return bool(self.parent and self.parent.is_class())

    def is_method(self) -> bool:
        """
        Tell if this node's object is a method.

        Returns:
            If this node's object is a method.
        """
        function_type = type(lambda: None)
        return self.parent_is_class() and isinstance(self.obj, function_type)

    def is_method_descriptor(self) -> bool:
        """
        Tell if this node's object is a method descriptor.

        Built-in methods (e.g. those implemented in C/Rust) are often
        method descriptors, rather than normal methods.

        Returns:
            If this node's object is a method descriptor.
        """
        return inspect.ismethoddescriptor(self.obj)

    def is_staticmethod(self) -> bool:
        """
        Tell if this node's object is a staticmethod.

        Returns:
            If this node's object is a staticmethod.
        """
        if not self.parent:
            return False
        self_from_parent = self.parent.obj.__dict__.get(self.name, None)
        return self.parent_is_class() and isinstance(self_from_parent, staticmethod)

    def is_classmethod(self) -> bool:
        """
        Tell if this node's object is a classmethod.

        Returns:
            If this node's object is a classmethod.
        """
        if not self.parent:
            return False
        self_from_parent = self.parent.obj.__dict__.get(self.name, None)
        return self.parent_is_class() and isinstance(self_from_parent, classmethod)


# New path syntax: the new path syntax uses a colon to separate the
# modules (to import) from the objects (to get with getattr).
# It's easier to deal with, and it naturally improves error handling.
# At first, we default to the old syntax, then at some point we will
# default to the new syntax, and later again we will drop the old syntax.
def get_object_tree(path: str, new_path_syntax: bool = False) -> ObjectNode:
    """
    Transform a path into an actual Python object.

    The path can be arbitrary long. You can pass the path to a package,
    a module, a class, a function or a global variable, as deep as you
    want, as long as the deepest module is importable through
    `importlib.import_module` and each object is obtainable through
    the `getattr` method. It is not possible to load local objects.

    Args:
        path: The dot/colon-separated path of the object.
        new_path_syntax: Whether to use the "colon" syntax for the path.

    Raises:
        ValueError: When the path is not valid (evaluates to `False`).
        ImportError: When the object or its parent module could not be imported.

    Returns:
        The leaf node representing the object and its parents.
    """
    if not path:
        raise ValueError(f"path must be a valid Python path, not {path}")

    objects: List[str] = []

    if ":" in path or new_path_syntax:
        try:
            module_path, object_path = path.split(":")
        except ValueError:  # no colon
            module_path, objects = path, []
        else:
            objects = object_path.split(".")

        # let the ImportError bubble up
        parent_module = importlib.import_module(module_path)

    else:
        # We will try to import the longest dotted-path first.
        # If it fails, we remove the right-most part and put it in a list of "objects", used later.
        # We loop until we find the deepest importable submodule.
        obj_parent_modules = path.split(".")

        while True:
            parent_module_path = ".".join(obj_parent_modules)
            try:
                parent_module = importlib.import_module(parent_module_path)
            except ImportError as error:
                if len(obj_parent_modules) == 1:
                    raise ImportError(
                        f"Importing '{path}' failed, possible causes are:\n"
                        f"- an exception happened while importing\n"
                        f"- an element in the path does not exist",
                    ) from error
                objects.insert(0, obj_parent_modules.pop(-1))
            else:
                break

    # We now have the module containing the desired object.
    # We will build the object tree by iterating over the previously stored objects names
    # and trying to get them as attributes.
    current_node = ObjectNode(parent_module, parent_module.__name__)
    for obj_name in objects:
        obj = getattr(current_node.obj, obj_name)
        child = ObjectNode(obj, obj_name, parent=current_node)
        current_node = child

    leaf = current_node

    # We now try to get the "real" parent module, not the one the object was imported into.
    # This is important if we want to be able to retrieve the docstring of an attribute for example.
    # Once we find an object for which we could get the module, we stop trying to get the module.
    # Once we reach the node before the root, we apply the module if found, and break.
    real_module = None
    while current_node.parent is not None:
        if real_module is None:
            real_module = inspect.getmodule(current_node.obj)
        if inspect.ismodule(current_node.parent.obj):
            if real_module is not None and real_module is not current_node.parent.obj:
                current_node.parent = ObjectNode(real_module, real_module.__name__)
            break
        current_node = current_node.parent

    return leaf


class Loader:
    """
    This class contains the object documentation loading mechanisms.

    Any error that occurred during collection of the objects and their documentation is stored in the `errors` list.
    """

    def __init__(
        self,
        filters: Optional[List[str]] = None,
        docstring_style: str = "google",
        docstring_options: Optional[dict] = None,
        inherited_members: bool = False,
        new_path_syntax: bool = False,
    ) -> None:
        """
        Initialize the object.

        Arguments:
            filters: A list of regular expressions to fine-grain select members. It is applied recursively.
            docstring_style: The style to use when parsing docstrings.
            docstring_options: The options to pass to the docstrings parser.
            inherited_members: Whether to select inherited members for classes.
            new_path_syntax: Whether to use the "colon" syntax for the path.
        """
        if not filters:
            filters = []

        self.filters = [(filtr, re.compile(filtr.lstrip("!"))) for filtr in filters]
        self.docstring_parser = PARSERS[docstring_style](**(docstring_options or {}))  # type: ignore
        self.errors: List[str] = []
        self.select_inherited_members = inherited_members
        self.new_path_syntax = new_path_syntax

    def get_object_documentation(self, dotted_path: str, members: Optional[Union[Set[str], bool]] = None) -> Object:
        """
        Get the documentation for an object and its children.

        Arguments:
            dotted_path: The Python dotted path to the desired object.
            members: `True` to select members and filter them, `False` to select no members,
                or a list of names to explicitly select the members with these names.
                It is applied only on the root object.

        Returns:
            The documented object.
        """
        if members is True:
            members = set()

        root_object: Object
        leaf = get_object_tree(dotted_path, self.new_path_syntax)

        if leaf.is_module():
            root_object = self.get_module_documentation(leaf, members)
        elif leaf.is_class():
            root_object = self.get_class_documentation(leaf, members)
        elif leaf.is_staticmethod():
            root_object = self.get_staticmethod_documentation(leaf)
        elif leaf.is_classmethod():
            root_object = self.get_classmethod_documentation(leaf)
        elif leaf.is_method_descriptor():
            root_object = self.get_regular_method_documentation(leaf)
        elif leaf.is_method():
            root_object = self.get_regular_method_documentation(leaf)
        elif leaf.is_function():
            root_object = self.get_function_documentation(leaf)
        elif leaf.is_property():
            root_object = self.get_property_documentation(leaf)
        else:
            root_object = self.get_attribute_documentation(leaf)

        root_object.parse_all_docstrings(self.docstring_parser)

        return root_object

    def get_module_documentation(self, node: ObjectNode, select_members=None) -> Module:
        """
        Get the documentation for a module and its children.

        Arguments:
            node: The node representing the module and its parents.
            select_members: Explicit members to select.

        Returns:
            The documented module object.
        """
        module = node.obj
        path = node.dotted_path
        name = path.split(".")[-1]
        source: Optional[Source]

        try:
            source = Source(inspect.getsource(module), 1)
        except OSError as error:
            try:
                code = Path(node.file_path).read_text()
            except (OSError, UnicodeDecodeError):
                source = None
            else:
                source = Source(code, 1) if code else None

        root_object = Module(
            name=name,
            path=path,
            file_path=node.file_path,
            docstring=inspect.getdoc(module),
            source=source,
        )

        if select_members is False:
            return root_object

        select_members = select_members or set()

        attributes_data = get_module_attributes(module)
        root_object.parse_docstring(self.docstring_parser, attributes=attributes_data)

        for member_name, member in inspect.getmembers(module):
            if self.select(member_name, select_members):  # type: ignore
                child_node = ObjectNode(member, member_name, parent=node)
                if child_node.is_class() and node.root.obj is inspect.getmodule(child_node.obj):
                    root_object.add_child(self.get_class_documentation(child_node))
                elif child_node.is_function() and node.root.obj is inspect.getmodule(child_node.obj):
                    root_object.add_child(self.get_function_documentation(child_node))
                elif member_name in attributes_data:
                    root_object.add_child(self.get_attribute_documentation(child_node, attributes_data[member_name]))

        if hasattr(module, "__path__"):  # noqa: WPS421 (hasattr)
            for _, modname, _ in pkgutil.iter_modules(module.__path__):
                if self.select(modname, select_members):
                    leaf = get_object_tree(f"{path}.{modname}")
                    root_object.add_child(self.get_module_documentation(leaf))

        return root_object

    @staticmethod
    def _class_path(cls):
        mod = cls.__module__
        qname = cls.__qualname__
        if mod == "builtins":
            return qname
        else:
            return f"{mod}.{qname}"

    def get_class_documentation(self, node: ObjectNode, select_members=None) -> Class:
        """
        Get the documentation for a class and its children.

        Arguments:
            node: The node representing the class and its parents.
            select_members: Explicit members to select.

        Returns:
            The documented class object.
        """
        class_ = node.obj
        docstring = inspect.cleandoc(class_.__doc__ or "")
        bases = [self._class_path(b) for b in class_.__bases__]
        root_object = Class(
            name=node.name, path=node.dotted_path, file_path=node.file_path, docstring=docstring, bases=bases
        )

        # Even if we don't select members, we want to correctly parse the docstring
        attributes_data: Dict[str, Dict[str, Any]] = {}
        for parent_class in reversed(class_.__mro__[:-1]):
            merge(attributes_data, get_class_attributes(parent_class))
        context: Dict[str, Any] = {"attributes": attributes_data}
        if "__init__" in class_.__dict__:
            try:
                attributes_data.update(get_instance_attributes(class_.__init__))
                context["signature"] = inspect.signature(class_.__init__)
            except (TypeError, ValueError):
                pass
        root_object.parse_docstring(self.docstring_parser, attributes=attributes_data)

        if select_members is False:
            return root_object

        select_members = select_members or set()

        # Build the list of members
        members = {}
        inherited = set()
        direct_members = class_.__dict__
        all_members = dict(inspect.getmembers(class_))
        for member_name, member in all_members.items():
            if member is class_:
                continue
            if not (member is type or member is object) and self.select(member_name, select_members):
                if member_name not in direct_members:
                    if self.select_inherited_members:
                        members[member_name] = member
                        inherited.add(member_name)
                else:
                    members[member_name] = member

        # Iterate on the selected members
        child: Object
        for member_name, member in members.items():
            child_node = ObjectNode(member, member_name, parent=node)
            if child_node.is_class():
                child = self.get_class_documentation(child_node)
            elif child_node.is_classmethod():
                child = self.get_classmethod_documentation(child_node)
            elif child_node.is_staticmethod():
                child = self.get_staticmethod_documentation(child_node)
            elif child_node.is_method():
                child = self.get_regular_method_documentation(child_node)
            elif child_node.is_property():
                child = self.get_property_documentation(child_node)
            elif member_name in attributes_data:
                child = self.get_attribute_documentation(child_node, attributes_data[member_name])
            else:
                continue
            if member_name in inherited:
                child.properties.append("inherited")
            root_object.add_child(child)

        for attr_name, properties, add_method in (
            ("__fields__", ["pydantic-model"], self.get_pydantic_field_documentation),
            ("_declared_fields", ["marshmallow-model"], self.get_marshmallow_field_documentation),
            ("_meta.get_fields", ["django-model"], self.get_django_field_documentation),
            ("__dataclass_fields__", ["dataclass"], self.get_annotated_dataclass_field),
        ):
            if self.detect_field_model(attr_name, direct_members, all_members):
                root_object.properties.extend(properties)
                self.add_fields(
                    node,
                    root_object,
                    attr_name,
                    all_members,
                    select_members,
                    class_,
                    add_method,
                )
                break

        return root_object

    def detect_field_model(self, attr_name: str, direct_members, all_members) -> bool:
        """
        Detect if an attribute is present in members.

        Arguments:
            attr_name: The name of the attribute to detect, can contain dots.
            direct_members: The direct members of the class.
            all_members: All members of the class.

        Returns:
            Whether the attribute is present.
        """

        first_order_attr_name, remainder = split_attr_name(attr_name)
        if not (
            first_order_attr_name in direct_members
            or (self.select_inherited_members and first_order_attr_name in all_members)
        ):
            return False

        if remainder and not attrgetter(remainder)(all_members[first_order_attr_name]):
            return False
        return True

    def add_fields(
        self,
        node: ObjectNode,
        root_object: Object,
        attr_name: str,
        members,
        select_members,
        base_class,
        add_method,
    ) -> None:
        """
        Add detected fields to the current object.

        Arguments:
            node: The current object node.
            root_object: The current object.
            attr_name: The fields attribute name.
            members: The members to pick the fields attribute in.
            select_members: The members to select.
            base_class: The class declaring the fields.
            add_method: The method to add the children object.
        """

        fields = get_fields(attr_name, members=members)

        for field_name, field in fields.items():
            select_field = self.select(field_name, select_members)  # type: ignore
            is_inherited = field_is_inherited(field_name, attr_name, base_class)

            if select_field and (self.select_inherited_members or not is_inherited):
                child_node = ObjectNode(obj=field, name=field_name, parent=node)
                root_object.add_child(add_method(child_node))

    def get_function_documentation(self, node: ObjectNode) -> Function:
        """
        Get the documentation for a function.

        Arguments:
            node: The node representing the function and its parents.

        Returns:
            The documented function object.
        """
        function = node.obj
        path = node.dotted_path
        source: Optional[Source]
        signature: Optional[inspect.Signature]

        try:
            signature = inspect.signature(function)
        except TypeError as error:
            signature = None

        try:
            source = Source(*inspect.getsourcelines(function))
        except OSError as error:
            source = None

        properties: List[str] = []
        if node.is_coroutine_function():
            properties.append("async")

        return Function(
            name=node.name,
            path=node.dotted_path,
            file_path=node.file_path,
            docstring=inspect.getdoc(function),
            signature=signature,
            source=source,
            properties=properties,
        )

    def get_property_documentation(self, node: ObjectNode) -> Attribute:
        """
        Get the documentation for a property.

        Arguments:
            node: The node representing the property and its parents.

        Returns:
            The documented attribute object (properties are considered attributes for now).
        """
        prop = node.obj
        path = node.dotted_path
        properties = ["property"]
        if node.is_cached_property():
            # cached_property is always writable, see the docs
            properties.extend(["writable", "cached"])
            sig_source_func = prop.func
        else:
            properties.append("readonly" if prop.fset is None else "writable")
            sig_source_func = prop.fget

        source: Optional[Source]

        try:
            signature = inspect.signature(sig_source_func)
        except (TypeError, ValueError) as error:
            attr_type = None
        else:
            attr_type = signature.return_annotation

        try:
            source = Source(*inspect.getsourcelines(sig_source_func))
        except (OSError, TypeError) as error:
            source = None

        return Attribute(
            name=node.name,
            path=path,
            file_path=node.file_path,
            docstring=inspect.getdoc(prop),
            attr_type=attr_type,
            properties=properties,
            source=source,
        )

    @staticmethod
    def get_pydantic_field_documentation(node: ObjectNode) -> Attribute:
        """
        Get the documentation for a Pydantic Field.

        Arguments:
            node: The node representing the Field and its parents.

        Returns:
            The documented attribute object.
        """
        prop = node.obj
        path = node.dotted_path
        properties = ["pydantic-field"]
        if prop.required:
            properties.append("required")

        return Attribute(
            name=node.name,
            path=path,
            file_path=node.file_path,
            docstring=prop.field_info.description,
            attr_type=prop.outer_type_,
            properties=properties,
        )

    @staticmethod
    def get_django_field_documentation(node: ObjectNode) -> Attribute:
        """
        Get the documentation for a Django Field.

        Arguments:
            node: The node representing the Field and its parents.

        Returns:
            The documented attribute object.
        """
        prop = node.obj
        path = node.dotted_path
        properties = ["django-field"]

        if prop.null:
            properties.append("nullable")
        if prop.blank:
            properties.append("blank")

        return Attribute(
            name=node.name,
            path=path,
            file_path=node.file_path,
            docstring=prop.verbose_name,
            attr_type=prop.__class__,
            properties=properties,
        )

    @staticmethod
    def get_marshmallow_field_documentation(node: ObjectNode) -> Attribute:
        """
        Get the documentation for a Marshmallow Field.

        Arguments:
            node: The node representing the Field and its parents.

        Returns:
            The documented attribute object.
        """
        prop = node.obj
        path = node.dotted_path
        properties = ["marshmallow-field"]
        if prop.required:
            properties.append("required")

        return Attribute(
            name=node.name,
            path=path,
            file_path=node.file_path,
            docstring=prop.metadata.get("description"),
            attr_type=type(prop),
            properties=properties,
        )

    @staticmethod
    def get_annotated_dataclass_field(node: ObjectNode, attribute_data: Optional[dict] = None) -> Attribute:
        """
        Get the documentation for a dataclass field.

        Arguments:
            node: The node representing the annotation and its parents.
            attribute_data: Docstring and annotation for this attribute.

        Returns:
            The documented attribute object.
        """
        if attribute_data is None:
            if node.parent_is_class():
                attribute_data = get_class_attributes(node.parent.obj).get(node.name, {})  # type: ignore
            else:
                attribute_data = get_module_attributes(node.root.obj).get(node.name, {})

        return Attribute(
            name=node.name,
            path=node.dotted_path,
            file_path=node.file_path,
            docstring=attribute_data["docstring"],
            attr_type=attribute_data["annotation"],
            properties=["dataclass-field"],
        )

    def get_classmethod_documentation(self, node: ObjectNode) -> Method:
        """
        Get the documentation for a class-method.

        Arguments:
            node: The node representing the class-method and its parents.

        Returns:
            The documented method object.
        """
        return self.get_method_documentation(node, ["classmethod"])

    def get_staticmethod_documentation(self, node: ObjectNode) -> Method:
        """
        Get the documentation for a static-method.

        Arguments:
            node: The node representing the static-method and its parents.

        Returns:
            The documented method object.
        """
        return self.get_method_documentation(node, ["staticmethod"])

    def get_regular_method_documentation(self, node: ObjectNode) -> Method:
        """
        Get the documentation for a regular method (not class- nor static-method).

        We do extra processing in this method to discard docstrings of `__init__` methods
        that were inherited from parent classes.

        Arguments:
            node: The node representing the method and its parents.

        Returns:
            The documented method object.
        """
        method = self.get_method_documentation(node)
        if node.parent:
            class_ = node.parent.obj
            if RE_SPECIAL.match(node.name):
                docstring = method.docstring
                parent_classes = class_.__mro__[1:]
                for parent_class in parent_classes:
                    try:
                        parent_method = getattr(parent_class, node.name)
                    except AttributeError:
                        continue
                    else:
                        if docstring == inspect.getdoc(parent_method):
                            method.docstring = ""
                        break
        return method

    def get_method_documentation(self, node: ObjectNode, properties: Optional[List[str]] = None) -> Method:
        """
        Get the documentation for a method or method descriptor.

        Arguments:
            node: The node representing the method and its parents.
            properties: A list of properties to apply to the method.

        Returns:
            The documented method object.
        """
        method = node.obj
        path = node.dotted_path
        signature: Optional[inspect.Signature]
        source: Optional[Source]

        try:
            source = Source(*inspect.getsourcelines(method))
        except OSError as error:
            source = None
        except TypeError:
            source = None

        if node.is_coroutine_function():
            if properties is None:
                properties = ["async"]
            else:
                properties.append("async")

        try:
            # for "built-in" functions, e.g. those implemented in C,
            # inspect.signature() uses the __text_signature__ attribute, which
            # provides a limited but still useful amount of signature information.
            # "built-in" functions with no __text_signature__ will
            # raise a ValueError().
            signature = inspect.signature(method)
        except ValueError as error:
            signature = None

        return Method(
            name=node.name,
            path=path,
            file_path=node.file_path,
            docstring=inspect.getdoc(method),
            signature=signature,
            properties=properties or [],
            source=source,
        )

    @staticmethod
    def get_attribute_documentation(node: ObjectNode, attribute_data: Optional[dict] = None) -> Attribute:
        """
        Get the documentation for an attribute.

        Arguments:
            node: The node representing the method and its parents.
            attribute_data: Docstring and annotation for this attribute.

        Returns:
            The documented attribute object.
        """
        if attribute_data is None:
            if node.parent_is_class():
                attribute_data = get_class_attributes(node.parent.obj).get(node.name, {})  # type: ignore
            else:
                attribute_data = get_module_attributes(node.root.obj).get(node.name, {})
        return Attribute(
            name=node.name,
            path=node.dotted_path,
            file_path=node.file_path,
            docstring=attribute_data.get("docstring", ""),
            attr_type=attribute_data.get("annotation", None),
        )

    def select(self, name: str, names: Set[str]) -> bool:
        """
        Tells whether we should select an object or not, given its name.

        If the set of names is not empty, we check against it, otherwise we check against filters.

        Arguments:
            name: The name of the object to select or not.
            names: An explicit list of names to select.

        Returns:
            Yes or no.
        """
        if names:
            return name in names
        return not self.filter_name_out(name)

    @lru_cache(maxsize=None)
    def filter_name_out(self, name: str) -> bool:
        """
        Filter a name based on the loader's filters.

        Arguments:
            name: The name to filter.

        Returns:
            True if the name was filtered out, False otherwise.
        """
        if not self.filters:
            return False
        keep = True
        for fltr, regex in self.filters:
            is_matching = bool(regex.search(name))
            if is_matching:
                if str(fltr).startswith("!"):
                    is_matching = not is_matching
                keep = is_matching
        return not keep


def field_is_inherited(field_name: str, fields_name: str, base_class: type) -> bool:
    """
    Check if a field with a certain name was inherited from parent classes.

    Arguments:
        field_name: The name of the field to check.
        fields_name: The name of the attribute in which the fields are stored.
        base_class: The base class in which the field appears.

    Returns:
        Whether the field was inherited.
    """
    # To tell if a field was inherited, we check if it exists in parent classes __fields__ attributes.
    # We don't check the current class, nor the top one (object), hence __mro__[1:-1]
    return field_name in set(
        chain(
            *(getattr(parent_class, fields_name, {}).keys() for parent_class in base_class.__mro__[1:-1]),
        ),
    )


def split_attr_name(attr_name: str) -> Tuple[str, Optional[str]]:
    """
    Split an attribute name into a first-order attribute name and remainder.

    Args:
        attr_name: Attribute name (a)

    Returns:
        Tuple containing:
            first_order_attr_name: Name of the first order attribute (a)
            remainder: The remainder (b.c)

    """
    first_order_attr_name, *remaining = attr_name.split(".", maxsplit=1)
    remainder = remaining[0] if remaining else None
    return first_order_attr_name, remainder


def get_fields(attr_name: str, *, members: Mapping[str, Any] = None, class_obj=None) -> Dict[str, Any]:
    if not (bool(members) ^ bool(class_obj)):
        raise ValueError("Either members or class_obj is required.")
    first_order_attr_name, remainder = split_attr_name(attr_name)
    fields = members[first_order_attr_name] if members else dict(vars(class_obj)).get(first_order_attr_name, {})
    if remainder:
        fields = attrgetter(remainder)(fields)

    if callable(fields):
        fields = fields()

    if not isinstance(fields, dict):
        # Support Django models
        fields = {getattr(f, "name", str(f)): f for f in fields if not getattr(f, "auto_created", False)}

    return fields
