"""This module defines functions and classes to parse docstrings into structured data."""
from collections import defaultdict
from dataclasses import dataclass, field
from inspect import Signature
from typing import Any, Callable, DefaultDict, Dict, FrozenSet, List, Optional, Tuple, Type, Union, cast  # noqa: WPS235

from pytkdocs.parsers.docstrings.base import AnnotatedObject, Attribute, Parameter, Parser, Section, empty

try:
    from typing import TypedDict  # type: ignore
except ImportError:
    from typing_extensions import TypedDict  # noqa: WPS440  # type: ignore
try:
    from typing import Literal  # type: ignore
except ImportError:
    # https://github.com/python/mypy/issues/8520
    from typing_extensions import Literal  # type: ignore # noqa: WPS440


# TODO: Examples: from the documentation, I'm not sure there is a standard format for examples
PARAM_NAMES = frozenset(("param", "parameter", "arg", "argument", "key", "keyword"))
PARAM_TYPE_NAMES = frozenset(("type",))
ATTRIBUTE_NAMES = frozenset(("var", "ivar", "cvar"))
ATTRIBUTE_TYPE_NAMES = frozenset(("vartype",))
RETURN_NAMES = frozenset(("returns", "return"))
RETURN_TYPE_NAMES = frozenset(("rtype",))
EXCEPTION_NAMES = frozenset(("raises", "raise", "except", "exception"))


@dataclass(frozen=True)
class FieldType:
    """Maps directive names to parser functions."""

    names: FrozenSet[str]
    reader: Callable[[List[str], int], int]

    def matches(self, line: str) -> bool:
        """
        Check if a line matches the field type.

        Args:
            line: Line to check against

        Returns:
            True if the line matches the field type, False otherwise.
        """
        return any(line.startswith(f":{name}") for name in self.names)


class AttributesDict(TypedDict):
    """Attribute details."""

    docstring: str
    annotation: Type  # TODO: Not positive this is correct


class ParseContext:
    """Typed replacement for context dictionary."""

    obj: Any  # I think this might be pytkdos.Object & subclasses
    attributes: DefaultDict[str, AttributesDict]
    signature: Optional[Signature]
    # Not sure real type yet. Maybe Optional[Union[Literal[Signature.empty],str,Type]]
    annotation: Any

    # This might be be better as the obj & optional attributes
    def __init__(self, context: Dict):
        """
        Initialize the object.

        Args:
            context: Context of parsing operation.
        """
        self.obj = context["obj"]
        self.attributes = defaultdict(cast(Callable[[], AttributesDict], dict))
        attributes = context.get("attributes")
        if attributes is not None:
            self.attributes.update(attributes)

        self.signature = getattr(self.obj, "signature", None)
        self.annotation = getattr(self.obj, "type", empty)


@dataclass
class ParsedDirective:
    """Directive information that has been parsed from a docstring."""

    line: str
    next_index: int
    directive_parts: List[str]
    value: str
    invalid: bool = False


@dataclass
class ParsedValues:
    """Values parsed from the docstring to be used to produce sections."""

    description: List[str] = field(default_factory=list)
    parameters: Dict[str, Parameter] = field(default_factory=dict)
    param_types: Dict[str, str] = field(default_factory=dict)
    attributes: Dict[str, Attribute] = field(default_factory=dict)
    attribute_types: Dict[str, str] = field(default_factory=dict)
    exceptions: List[AnnotatedObject] = field(default_factory=list)
    return_value: Optional[AnnotatedObject] = None
    return_type: Optional[str] = None


class RestructuredText(Parser):
    """A reStructuredText docstrings parser."""

    def __init__(self) -> None:
        """Initialize the object."""
        super().__init__()
        self._typed_context = ParseContext({"obj": None})
        self._parsed_values: ParsedValues = ParsedValues()
        # Ordering is significant so that directives like ":vartype" are checked before ":var"
        self.field_types = [
            FieldType(PARAM_TYPE_NAMES, self._read_parameter_type),  # type: ignore
            FieldType(PARAM_NAMES, self._read_parameter),  # type: ignore
            FieldType(ATTRIBUTE_TYPE_NAMES, self._read_attribute_type),  # type: ignore
            FieldType(ATTRIBUTE_NAMES, self._read_attribute),  # type: ignore
            FieldType(EXCEPTION_NAMES, self._read_exception),  # type: ignore
            FieldType(RETURN_NAMES, self._read_return),  # type: ignore
            FieldType(RETURN_TYPE_NAMES, self._read_return_type),  # type: ignore
        ]

    def parse_sections(self, docstring: str) -> List[Section]:  # noqa: D102
        self._typed_context = ParseContext(self.context)
        self._parsed_values = ParsedValues()

        lines = docstring.split("\n")
        curr_line_index = 0

        while curr_line_index < len(lines):
            line = lines[curr_line_index]
            for field_type in self.field_types:
                if field_type.matches(line):
                    # https://github.com/python/mypy/issues/5485
                    curr_line_index = field_type.reader(lines, curr_line_index)  # type: ignore
                    break
            else:
                self._parsed_values.description.append(line)

            curr_line_index += 1

        return self._parsed_values_to_sections()

    def _read_parameter(self, lines: List[str], start_index: int) -> int:
        """
        Parse a parameter value.

        Arguments:
            lines: The docstring lines.
            start_index: The line number to start at.

        Returns:
            Index at which to continue parsing.
        """
        parsed_directive = self._parse_directive(lines, start_index)
        if parsed_directive.invalid:
            return parsed_directive.next_index

        directive_type = None
        if len(parsed_directive.directive_parts) == 2:
            # no type info
            name = parsed_directive.directive_parts[1]
        elif len(parsed_directive.directive_parts) == 3:
            directive_type = parsed_directive.directive_parts[1]
            name = parsed_directive.directive_parts[2]
        else:
            self.error(f"Failed to parse field directive from '{parsed_directive.line}'")
            return parsed_directive.next_index

        if name in self._parsed_values.parameters:
            self.errors.append(f"Duplicate parameter entry for '{name}'")
            return parsed_directive.next_index

        annotation = self._determine_param_annotation(name, directive_type)
        default, kind = self._determine_param_details(name)

        self._parsed_values.parameters[name] = Parameter(
            name=name,
            annotation=annotation,
            description=parsed_directive.value,
            default=default,
            kind=kind,
        )

        return parsed_directive.next_index

    def _determine_param_details(self, name: str) -> Tuple[Any, Any]:
        default = empty
        kind = empty

        if self._typed_context.signature is not None:
            param_signature = self._typed_context.signature.parameters.get(name.lstrip("*"))
            # an error for param_signature being none is already reported by _determine_param_annotation()
            if param_signature is not None:
                if param_signature.default is not empty:
                    default = param_signature.default
                kind = param_signature.kind

        return default, kind

    def _determine_param_annotation(self, name: str, directive_type: Optional[str]) -> Any:
        # Annotation precedence:
        # - signature annotation
        # - in-line directive type
        # - "type" directive type
        # - empty
        annotation = empty

        parsed_param_type = self._parsed_values.param_types.get(name)
        if parsed_param_type is not None:
            annotation = parsed_param_type

        if directive_type is not None:
            annotation = directive_type

        if directive_type is not None and parsed_param_type is not None:
            self.error(f"Duplicate parameter information for '{name}'")

        if self._typed_context.signature is not None:
            try:
                param_signature = self._typed_context.signature.parameters[name.lstrip("*")]
            except KeyError:
                self.error(f"No matching parameter for '{name}'")
            else:
                if param_signature.annotation is not empty:
                    annotation = param_signature.annotation

        return annotation

    def _read_parameter_type(self, lines: List[str], start_index: int) -> int:
        """
        Parse a parameter type.

        Arguments:
            lines: The docstring lines.
            start_index: The line number to start at.

        Returns:
            Index at which to continue parsing.
        """
        parsed_directive = self._parse_directive(lines, start_index)
        if parsed_directive.invalid:
            return parsed_directive.next_index
        param_type = _consolidate_descriptive_type(parsed_directive.value.strip())

        if len(parsed_directive.directive_parts) == 2:
            param_name = parsed_directive.directive_parts[1]
        else:
            self.error(f"Failed to get parameter name from '{parsed_directive.line}'")
            return parsed_directive.next_index

        self._parsed_values.param_types[param_name] = param_type
        param = self._parsed_values.parameters.get(param_name)
        if param is not None:
            if param.annotation is empty:
                param.annotation = param_type
            else:
                self.error(f"Duplicate parameter information for '{param_name}'")
        return parsed_directive.next_index

    def _read_attribute(self, lines: List[str], start_index: int) -> int:
        """
        Parse an attribute value.

        Arguments:
            lines: The docstring lines.
            start_index: The line number to start at.

        Returns:
            Index at which to continue parsing.
        """
        parsed_directive = self._parse_directive(lines, start_index)
        if parsed_directive.invalid:
            return parsed_directive.next_index

        if len(parsed_directive.directive_parts) == 2:
            name = parsed_directive.directive_parts[1]
        else:
            self.error(f"Failed to parse field directive from '{parsed_directive.line}'")
            return parsed_directive.next_index

        annotation = empty

        # Annotation precedence:
        # - external context type TODO: spend time understanding where this comes from
        # - "vartype" directive type
        # - empty

        parsed_attribute_type = self._parsed_values.attribute_types.get(name)
        if parsed_attribute_type is not None:
            annotation = parsed_attribute_type

        context_attribute_annotation = self._typed_context.attributes[name].get("annotation")
        if context_attribute_annotation is not None:
            annotation = context_attribute_annotation

        if name in self._parsed_values.attributes:
            self.errors.append(f"Duplicate attribute entry for '{name}'")
        else:
            self._parsed_values.attributes[name] = Attribute(
                name=name,
                annotation=annotation,
                description=parsed_directive.value,
            )

        return parsed_directive.next_index

    def _read_attribute_type(self, lines: List[str], start_index: int) -> int:
        """
        Parse a parameter type.

        Arguments:
            lines: The docstring lines.
            start_index: The line number to start at.

        Returns:
            Index at which to continue parsing.
        """
        parsed_directive = self._parse_directive(lines, start_index)
        if parsed_directive.invalid:
            return parsed_directive.next_index
        attribute_type = _consolidate_descriptive_type(parsed_directive.value.strip())

        if len(parsed_directive.directive_parts) == 2:
            attribute_name = parsed_directive.directive_parts[1]
        else:
            self.error(f"Failed to get attribute name from '{parsed_directive.line}'")
            return parsed_directive.next_index

        self._parsed_values.attribute_types[attribute_name] = attribute_type
        attribute = self._parsed_values.attributes.get(attribute_name)
        if attribute is not None:
            if attribute.annotation is empty:
                attribute.annotation = attribute_type
            else:
                self.error(f"Duplicate attribute information for '{attribute_name}'")
        return parsed_directive.next_index

    def _read_exception(self, lines: List[str], start_index: int) -> int:
        """
        Parse an exceptions value.

        Arguments:
            lines: The docstring lines.
            start_index: The line number to start at.

        Returns:
            A tuple containing a `Section` (or `None`) and the index at which to continue parsing.
        """
        parsed_directive = self._parse_directive(lines, start_index)
        if parsed_directive.invalid:
            return parsed_directive.next_index

        if len(parsed_directive.directive_parts) == 2:
            ex_type = parsed_directive.directive_parts[1]
            self._parsed_values.exceptions.append(AnnotatedObject(ex_type, parsed_directive.value))
        else:
            self.error(f"Failed to parse exception directive from '{parsed_directive.line}'")

        return parsed_directive.next_index

    def _read_return(self, lines: List[str], start_index: int) -> int:
        """
        Parse an return value.

        Arguments:
            lines: The docstring lines.
            start_index: The line number to start at.

        Returns:
            Index at which to continue parsing.
        """
        parsed_directive = self._parse_directive(lines, start_index)
        if parsed_directive.invalid:
            return parsed_directive.next_index

        annotation = empty
        # Annotation precedence:
        # - signature annotation
        # - "rtype" directive type
        # - external context type TODO: spend time understanding where this comes from
        # - empty
        if self._typed_context.signature is not None and self._typed_context.signature.return_annotation is not empty:
            annotation = self._typed_context.signature.return_annotation
        elif self._parsed_values.return_type is not None:
            annotation = self._parsed_values.return_type
        else:
            annotation = self._typed_context.annotation

        self._parsed_values.return_value = AnnotatedObject(annotation, parsed_directive.value)

        return parsed_directive.next_index

    def _read_return_type(self, lines: List[str], start_index: int) -> int:
        """
        Parse an return type value.

        Arguments:
            lines: The docstring lines.
            start_index: The line number to start at.

        Returns:
            Index at which to continue parsing.
        """
        parsed_directive = self._parse_directive(lines, start_index)
        if parsed_directive.invalid:
            return parsed_directive.next_index

        return_type = _consolidate_descriptive_type(parsed_directive.value.strip())
        self._parsed_values.return_type = return_type
        return_value = self._parsed_values.return_value
        if return_value is not None:
            if return_value.annotation is empty:
                return_value.annotation = return_type
            else:
                self.error("Duplicate type information for return")

        return parsed_directive.next_index

    def _parsed_values_to_sections(self) -> List[Section]:
        markdown_text = "\n".join(_strip_blank_lines(self._parsed_values.description))
        result = [Section(Section.Type.MARKDOWN, markdown_text)]
        if self._parsed_values.parameters:
            param_values = list(self._parsed_values.parameters.values())
            result.append(Section(Section.Type.PARAMETERS, param_values))
        if self._parsed_values.attributes:
            attribute_values = list(self._parsed_values.attributes.values())
            result.append(Section(Section.Type.ATTRIBUTES, attribute_values))
        if self._parsed_values.return_value is not None:
            result.append(Section(Section.Type.RETURN, self._parsed_values.return_value))
        if self._parsed_values.exceptions:
            result.append(Section(Section.Type.EXCEPTIONS, self._parsed_values.exceptions))
        return result

    def _parse_directive(self, lines: List[str], start_index: int) -> ParsedDirective:
        line, next_index = _consolidate_continuation_lines(lines, start_index)
        try:
            _, directive, value = line.split(":", 2)
        except ValueError:
            self.error(f"Failed to get ':directive: value' pair from '{line}'")
            return ParsedDirective(line, next_index, [], "", invalid=True)  # type: ignore

        value = value.strip()
        return ParsedDirective(line, next_index, directive.split(" "), value)  # type: ignore


def _consolidate_continuation_lines(lines: List[str], start_index: int) -> Tuple[str, int]:
    """
    Convert a docstring field into a single line if a line continuation exists.

    Arguments:
        lines: The docstring lines.
        start_index: The line number to start at.

    Returns:
        A tuple containing the continued lines as a single string and the index at which to continue parsing.
    """
    curr_line_index = start_index
    block = [lines[curr_line_index].lstrip()]

    # start processing after first item
    curr_line_index += 1
    while curr_line_index < len(lines) and not lines[curr_line_index].startswith(":"):
        block.append(lines[curr_line_index].lstrip())
        curr_line_index += 1

    return " ".join(block).rstrip("\n"), curr_line_index - 1


def _consolidate_descriptive_type(descriptive_type: str) -> str:
    """
    Convert type descriptions with "or" into respective type signature.

    "x or None" or "None or x" -> "Optional[x]"
    "x or x" or "x or y[ or z [...]]" -> "Union[x, y, ...]"

    Args:
        descriptive_type: Descriptions of an item's type.

    Returns:
        Type signature for descriptive type.
    """
    types = descriptive_type.split("or")
    if len(types) == 1:
        return descriptive_type
    types = [pt.strip() for pt in types]
    if len(types) == 2:
        if types[0] == "None":
            return f"Optional[{types[1]}]"
        if types[1] == "None":
            return f"Optional[{types[0]}]"
    return f"Union[{','.join(types)}]"


def _strip_blank_lines(lines: List[str]) -> List[str]:
    """
    Remove lines with no text or only whitespace characters from the start and end of the list.

    Args:
        lines: Lines to be stripped.

    Returns:
        A list with the same contents, with any blank lines at the start or end removed.
    """
    if not lines:
        return lines

    # remove blank lines from the start and end
    content_found = False
    initial_content = 0
    final_content = 0
    for index, line in enumerate(lines):
        if line == "" or line.isspace():
            if not content_found:
                initial_content += 1
        else:
            content_found = True
            final_content = index
    return lines[initial_content : final_content + 1]
