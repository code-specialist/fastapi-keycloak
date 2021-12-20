"""
This module defines function to serialize objects.

These functions simply take objects as parameters and return dictionaries that can be dumped by `json.dumps`.
"""

import inspect
import re
from typing import Any, Match, Optional, Pattern

from pytkdocs.objects import Object, Source
from pytkdocs.parsers.docstrings.base import AnnotatedObject, Attribute, Parameter, Section

try:
    from typing import GenericMeta  # type: ignore
except ImportError:
    # in 3.7, GenericMeta doesn't exist but we don't need it
    class GenericMeta(type):  # type: ignore  # noqa: WPS440 (variable overlap)
        """GenericMeta type."""


RE_OPTIONAL: Pattern = re.compile(r"Union\[(.+), NoneType\]")
"""Regular expression to match optional annotations of the form `Union[T, NoneType]`."""

RE_FORWARD_REF: Pattern = re.compile(r"_?ForwardRef\('([^']+)'\)")
"""Regular expression to match forward-reference annotations of the form `_ForwardRef('T')`."""


def rebuild_optional(match: Match) -> str:
    """
    Rebuild `Union[T, None]` as `Optional[T]`.

    Arguments:
        match: The match object when matching against a regular expression (by the parent caller).

    Returns:
        The rebuilt type string.
    """
    group = match.group(1)
    brackets_level = 0
    for char in group:
        if char == "," and brackets_level == 0:
            return f"Union[{group}]"
        if char == "[":
            brackets_level += 1
        elif char == "]":
            brackets_level -= 1
    return f"Optional[{group}]"


def annotation_to_string(annotation: Any) -> str:
    """
    Return an annotation as a string.

    Arguments:
        annotation: The annotation to return as a string.

    Returns:
        The annotation as a string.
    """
    if annotation is inspect.Signature.empty:
        return ""

    if inspect.isclass(annotation) and not isinstance(annotation, GenericMeta):
        string = annotation.__name__
    else:
        string = str(annotation).replace("typing.", "")

    string = RE_FORWARD_REF.sub(lambda match: match.group(1), string)
    string = RE_OPTIONAL.sub(rebuild_optional, string)

    return string  # noqa: WPS331 (false-positive, string is not only used for the return)


def serialize_annotated_object(obj: AnnotatedObject) -> dict:
    """
    Serialize an instance of [`AnnotatedObject`][pytkdocs.parsers.docstrings.base.AnnotatedObject].

    Arguments:
        obj: The object to serialize.

    Returns:
        A JSON-serializable dictionary.
    """
    return {"description": obj.description, "annotation": annotation_to_string(obj.annotation)}


def serialize_attribute(attribute: Attribute) -> dict:
    """
    Serialize an instance of [`Attribute`][pytkdocs.parsers.docstrings.base.Attribute].

    Arguments:
        attribute: The attribute to serialize.

    Returns:
        A JSON-serializable dictionary.
    """
    return {
        "name": attribute.name,
        "description": attribute.description,
        "annotation": annotation_to_string(attribute.annotation),
    }


def serialize_parameter(parameter: Parameter) -> dict:
    """
    Serialize an instance of [`Parameter`][pytkdocs.parsers.docstrings.base.Parameter].

    Arguments:
        parameter: The parameter to serialize.

    Returns:
        A JSON-serializable dictionary.
    """
    serialized = serialize_annotated_object(parameter)
    serialized.update(
        {
            "name": parameter.name,
            "kind": str(parameter.kind),
            "default": parameter.default_string,
            "is_optional": parameter.is_optional,
            "is_required": parameter.is_required,
            "is_args": parameter.is_args,
            "is_kwargs": parameter.is_kwargs,
        },
    )
    return serialized


def serialize_signature_parameter(parameter: inspect.Parameter) -> dict:
    """
    Serialize an instance of `inspect.Parameter`.

    Arguments:
        parameter: The parameter to serialize.

    Returns:
        A JSON-serializable dictionary.
    """
    serialized = {"kind": str(parameter.kind), "name": parameter.name}
    if parameter.annotation is not parameter.empty:
        serialized["annotation"] = annotation_to_string(parameter.annotation)
    if parameter.default is not parameter.empty:
        serialized["default"] = repr(parameter.default)
    return serialized


def serialize_signature(signature: inspect.Signature) -> dict:
    """
    Serialize an instance of `inspect.Signature`.

    Arguments:
        signature: The signature to serialize.

    Returns:
        A JSON-serializable dictionary.
    """
    if signature is None:
        return {}
    serialized: dict = {
        "parameters": [serialize_signature_parameter(value) for name, value in signature.parameters.items()],
    }
    if signature.return_annotation is not inspect.Signature.empty:
        serialized["return_annotation"] = annotation_to_string(signature.return_annotation)
    return serialized


def serialize_docstring_section(section: Section) -> dict:  # noqa: WPS231 (not complex)
    """
    Serialize an instance of `inspect.Signature`.

    Arguments:
        section: The section to serialize.

    Returns:
        A JSON-serializable dictionary.
    """
    serialized = {"type": section.type}
    if section.type == section.Type.MARKDOWN:
        serialized.update({"value": section.value})  # type: ignore
    elif section.type == section.Type.RETURN:
        serialized.update({"value": serialize_annotated_object(section.value)})  # type: ignore
    elif section.type == section.Type.EXCEPTIONS:
        serialized.update({"value": [serialize_annotated_object(exc) for exc in section.value]})  # type: ignore
    elif section.type == section.Type.PARAMETERS:
        serialized.update({"value": [serialize_parameter(param) for param in section.value]})  # type: ignore
    elif section.type == section.Type.ATTRIBUTES:
        serialized.update({"value": [serialize_attribute(attr) for attr in section.value]})  # type: ignore
    elif section.type == section.Type.EXAMPLES:
        serialized.update({"value": section.value})  # type: ignore
    return serialized


def serialize_source(source: Optional[Source]) -> dict:
    """
    Serialize an instance of [`Source`][pytkdocs.objects.Source].

    Arguments:
        source: The source to serialize.

    Returns:
        A JSON-serializable dictionary.
    """
    if source:
        return {"code": source.code, "line_start": source.line_start}
    return {}


def serialize_object(obj: Object) -> dict:
    """
    Serialize an instance of a subclass of [`Object`][pytkdocs.objects.Object].

    Arguments:
        obj: The object to serialize.

    Returns:
        A JSON-serializable dictionary.
    """
    serialized = {
        "name": obj.name,
        "path": obj.path,
        "category": obj.category,
        "file_path": obj.file_path,
        "relative_file_path": obj.relative_file_path,
        "properties": sorted(set(obj.properties + obj.name_properties)),
        "parent_path": obj.parent_path,
        "has_contents": obj.has_contents(),
        "docstring": obj.docstring,
        "docstring_sections": [serialize_docstring_section(sec) for sec in obj.docstring_sections],
        "source": serialize_source(obj.source),
        "children": {child.path: serialize_object(child) for child in obj.children},
        "attributes": [attr.path for attr in obj.attributes],
        "methods": [meth.path for meth in obj.methods],
        "functions": [func.path for func in obj.functions],
        "modules": [mod.path for mod in obj.modules],
        "classes": [clas.path for clas in obj.classes],
    }
    if hasattr(obj, "type"):  # noqa: WPS421 (hasattr)
        serialized["type"] = annotation_to_string(obj.type)  # type: ignore
    if hasattr(obj, "signature"):  # noqa: WPS421 (hasattr)
        serialized["signature"] = serialize_signature(obj.signature)  # type: ignore
    if hasattr(obj, "bases"):  # noqa: WPS421 (hasattr)
        serialized["bases"] = obj.bases  # type: ignore
    return serialized
