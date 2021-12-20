"""This module defines functions and classes to parse docstrings into structured data."""
import re
from typing import Any, List, Optional, Pattern, Tuple

from pytkdocs.parsers.docstrings.base import AnnotatedObject, Attribute, Parameter, Parser, Section, empty

SECTIONS_TITLES = {
    "args:": Section.Type.PARAMETERS,
    "arguments:": Section.Type.PARAMETERS,
    "params:": Section.Type.PARAMETERS,
    "parameters:": Section.Type.PARAMETERS,
    "keyword args:": Section.Type.KEYWORD_ARGS,
    "keyword arguments:": Section.Type.KEYWORD_ARGS,
    "raise:": Section.Type.EXCEPTIONS,
    "raises:": Section.Type.EXCEPTIONS,
    "except:": Section.Type.EXCEPTIONS,
    "exceptions:": Section.Type.EXCEPTIONS,
    "return:": Section.Type.RETURN,
    "returns:": Section.Type.RETURN,
    "example:": Section.Type.EXAMPLES,
    "examples:": Section.Type.EXAMPLES,
    "attribute:": Section.Type.ATTRIBUTES,
    "attributes:": Section.Type.ATTRIBUTES,
}

RE_GOOGLE_STYLE_ADMONITION: Pattern = re.compile(r"^(?P<indent>\s*)(?P<type>[\w-]+):((?:\s+)(?P<title>.+))?$")
"""Regular expressions to match lines starting admonitions, of the form `TYPE: [TITLE]`."""


class Google(Parser):
    """A Google-style docstrings parser."""

    def __init__(self, replace_admonitions: bool = True) -> None:
        """
        Initialize the object.

        Arguments:
            replace_admonitions: Whether to replace admonitions by their Markdown equivalent.
        """
        super().__init__()
        self.replace_admonitions = replace_admonitions
        self.section_reader = {
            Section.Type.PARAMETERS: self.read_parameters_section,
            Section.Type.KEYWORD_ARGS: self.read_keyword_arguments_section,
            Section.Type.EXCEPTIONS: self.read_exceptions_section,
            Section.Type.EXAMPLES: self.read_examples_section,
            Section.Type.ATTRIBUTES: self.read_attributes_section,
            Section.Type.RETURN: self.read_return_section,
        }

    def parse_sections(self, docstring: str) -> List[Section]:  # noqa: D102
        if "signature" not in self.context:
            self.context["signature"] = getattr(self.context["obj"], "signature", None)
        if "annotation" not in self.context:
            self.context["annotation"] = getattr(self.context["obj"], "type", empty)
        if "attributes" not in self.context:
            self.context["attributes"] = {}

        sections = []
        current_section = []

        in_code_block = False

        lines = docstring.split("\n")
        i = 0

        while i < len(lines):
            line_lower = lines[i].lower()

            if in_code_block:
                if line_lower.lstrip(" ").startswith("```"):
                    in_code_block = False
                current_section.append(lines[i])

            elif line_lower in SECTIONS_TITLES:
                if current_section:
                    if any(current_section):
                        sections.append(Section(Section.Type.MARKDOWN, "\n".join(current_section)))
                    current_section = []
                section_reader = self.section_reader[SECTIONS_TITLES[line_lower]]
                section, i = section_reader(lines, i + 1)
                if section:
                    sections.append(section)

            elif line_lower.lstrip(" ").startswith("```"):
                in_code_block = True
                current_section.append(lines[i])

            else:
                if self.replace_admonitions and not in_code_block and i + 1 < len(lines):
                    match = RE_GOOGLE_STYLE_ADMONITION.match(lines[i])
                    if match:
                        groups = match.groupdict()
                        indent = groups["indent"]
                        if lines[i + 1].startswith(indent + " " * 4):
                            lines[i] = f"{indent}!!! {groups['type'].lower()}"
                            if groups["title"]:
                                lines[i] += f' "{groups["title"]}"'
                current_section.append(lines[i])

            i += 1

        if current_section:
            sections.append(Section(Section.Type.MARKDOWN, "\n".join(current_section)))

        return sections

    def read_block_items(self, lines: List[str], start_index: int) -> Tuple[List[str], int]:
        """
        Parse an indented block as a list of items.

        The first indentation level is used as a reference to determine if the next lines are new items
        or continuation lines.

        Arguments:
            lines: The block lines.
            start_index: The line number to start at.

        Returns:
            A tuple containing the list of concatenated lines and the index at which to continue parsing.
        """
        if start_index >= len(lines):
            return [], start_index

        i = start_index
        items: List[str] = []

        # skip first empty lines
        while is_empty_line(lines[i]):
            i += 1

        # get initial indent
        indent = len(lines[i]) - len(lines[i].lstrip())

        if indent == 0:
            # first non-empty line was not indented, abort
            return [], i - 1

        # start processing first item
        current_item = [lines[i][indent:]]
        i += 1

        # loop on next lines
        while i < len(lines):
            line = lines[i]

            if line.startswith(indent * 2 * " "):
                # continuation line
                current_item.append(line[indent * 2 :])

            elif line.startswith((indent + 1) * " "):
                # indent between initial and continuation: append but add error
                cont_indent = len(line) - len(line.lstrip())
                current_item.append(line[cont_indent:])
                self.error(
                    f"Confusing indentation for continuation line {i+1} in docstring, "
                    f"should be {indent} * 2 = {indent*2} spaces, not {cont_indent}"
                )

            elif line.startswith(indent * " "):
                # indent equal to initial one: new item
                items.append("\n".join(current_item))
                current_item = [line[indent:]]

            elif is_empty_line(line):
                # empty line: preserve it in the current item
                current_item.append("")

            else:
                # indent lower than initial one: end of section
                break

            i += 1

        if current_item:
            items.append("\n".join(current_item).rstrip("\n"))

        return items, i - 1

    def read_block(self, lines: List[str], start_index: int) -> Tuple[str, int]:
        """
        Parse an indented block.

        Arguments:
            lines: The block lines.
            start_index: The line number to start at.

        Returns:
            A tuple containing the list of lines and the index at which to continue parsing.
        """
        if start_index >= len(lines):
            return "", start_index

        i = start_index
        block: List[str] = []

        # skip first empty lines
        while is_empty_line(lines[i]):
            i += 1

        # get initial indent
        indent = len(lines[i]) - len(lines[i].lstrip())

        if indent == 0:
            # first non-empty line was not indented, abort
            return "", i - 1

        # start processing first item
        block.append(lines[i].lstrip())
        i += 1

        # loop on next lines
        while i < len(lines) and (lines[i].startswith(indent * " ") or is_empty_line(lines[i])):
            block.append(lines[i][indent:])
            i += 1

        return "\n".join(block).rstrip("\n"), i - 1

    def _parse_parameters_section(self, lines: List[str], start_index: int) -> Tuple[List[Parameter], int]:
        """
        Parse a "parameters" or "keyword args" section.

        Arguments:
            lines: The parameters block lines.
            start_index: The line number to start at.

        Returns:
            A tuple containing a `Section` (or `None`) and the index at which to continue parsing.
        """
        parameters = []
        type_: Any
        block, i = self.read_block_items(lines, start_index)

        for param_line in block:

            # Check that there is an annotation in the docstring
            try:
                name_with_type, description = param_line.split(":", 1)
            except ValueError:
                self.error(f"Failed to get 'name: description' pair from '{param_line}'")
                continue

            # Setting defaults
            default = empty
            annotation = empty
            kind = None
            # Can only get description from docstring - keep if no type was given
            description = description.lstrip()

            # If we have managed to find a type in the docstring use this
            if " " in name_with_type:
                name, type_ = name_with_type.split(" ", 1)
                annotation = type_.strip("()")
                if annotation.endswith(", optional"):  # type: ignore
                    annotation = annotation[:-10]  # type: ignore
            # Otherwise try to use the signature as `annotation` would still be empty
            else:
                name = name_with_type

            # Check in the signature to get extra details
            try:
                signature_param = self.context["signature"].parameters[name.lstrip("*")]  # type: ignore
            except (AttributeError, KeyError):
                self.error(f"No type annotation for parameter '{name}'")
            else:
                # If signature_param.X are empty it doesnt matter as defaults are empty anyway
                if annotation is empty:
                    annotation = signature_param.annotation
                default = signature_param.default
                kind = signature_param.kind

            parameters.append(
                Parameter(name=name, annotation=annotation, description=description, default=default, kind=kind)
            )

        return parameters, i

    def read_parameters_section(self, lines: List[str], start_index: int) -> Tuple[Optional[Section], int]:
        """
        Parse a "parameters" section.

        Arguments:
            lines: The parameters block lines.
            start_index: The line number to start at.

        Returns:
            A tuple containing a `Section` (or `None`) and the index at which to continue parsing.
        """
        parameters, i = self._parse_parameters_section(lines, start_index)

        if parameters:
            return Section(Section.Type.PARAMETERS, parameters), i

        self.error(f"Empty parameters section at line {start_index}")
        return None, i

    def read_keyword_arguments_section(self, lines: List[str], start_index: int) -> Tuple[Optional[Section], int]:
        """
        Parse a "keyword arguments" section.

        Arguments:
            lines: The parameters block lines.
            start_index: The line number to start at.

        Returns:
            A tuple containing a `Section` (or `None`) and the index at which to continue parsing.
        """
        parameters, i = self._parse_parameters_section(lines, start_index)

        if parameters:
            return Section(Section.Type.KEYWORD_ARGS, parameters), i

        self.error(f"Empty keyword arguments section at line {start_index}")
        return None, i

    def read_attributes_section(self, lines: List[str], start_index: int) -> Tuple[Optional[Section], int]:
        """
        Parse an "attributes" section.

        Arguments:
            lines: The parameters block lines.
            start_index: The line number to start at.

        Returns:
            A tuple containing a `Section` (or `None`) and the index at which to continue parsing.
        """
        attributes = []
        block, i = self.read_block_items(lines, start_index)

        for attr_line in block:
            try:
                name_with_type, description = attr_line.split(":", 1)
            except ValueError:
                self.error(f"Failed to get 'name: description' pair from '{attr_line}'")
                continue

            description = description.lstrip()

            if " " in name_with_type:
                name, annotation = name_with_type.split(" ", 1)
                annotation = annotation.strip("()")
                if annotation.endswith(", optional"):
                    annotation = annotation[:-10]
            else:
                name = name_with_type
                annotation = self.context["attributes"].get(name, {}).get("annotation", empty)

            attributes.append(Attribute(name=name, annotation=annotation, description=description))

        if attributes:
            return Section(Section.Type.ATTRIBUTES, attributes), i

        self.error(f"Empty attributes section at line {start_index}")
        return None, i

    def read_exceptions_section(self, lines: List[str], start_index: int) -> Tuple[Optional[Section], int]:
        """
        Parse an "exceptions" section.

        Arguments:
            lines: The exceptions block lines.
            start_index: The line number to start at.

        Returns:
            A tuple containing a `Section` (or `None`) and the index at which to continue parsing.
        """
        exceptions = []
        block, i = self.read_block_items(lines, start_index)

        for exception_line in block:
            try:
                annotation, description = exception_line.split(": ", 1)
            except ValueError:
                self.error(f"Failed to get 'exception: description' pair from '{exception_line}'")
            else:
                exceptions.append(AnnotatedObject(annotation, description.lstrip(" ")))

        if exceptions:
            return Section(Section.Type.EXCEPTIONS, exceptions), i

        self.error(f"Empty exceptions section at line {start_index}")
        return None, i

    def read_return_section(self, lines: List[str], start_index: int) -> Tuple[Optional[Section], int]:
        """
        Parse an "returns" section.

        Arguments:
            lines: The return block lines.
            start_index: The line number to start at.

        Returns:
            A tuple containing a `Section` (or `None`) and the index at which to continue parsing.
        """
        text, i = self.read_block(lines, start_index)

        # Early exit if there is no text in the return section
        if not text:
            self.error(f"Empty return section at line {start_index}")
            return None, i

        # First try to get the annotation and description from the docstring
        try:
            type_, text = text.split(":", 1)
        except ValueError:
            description = text
            annotation = self.context["annotation"]
            # If there was no annotation in the docstring then move to signature
            if annotation is empty and self.context["signature"]:
                annotation = self.context["signature"].return_annotation
        else:
            annotation = type_.lstrip()
            description = text.lstrip()

        # There was no type in the docstring and no annotation
        if annotation is empty:
            self.error("No return type/annotation in docstring/signature")

        return Section(Section.Type.RETURN, AnnotatedObject(annotation, description)), i

    def read_examples_section(self, lines: List[str], start_index: int) -> Tuple[Optional[Section], int]:
        """
        Parse an "examples" section.

        Arguments:
            lines: The examples block lines.
            start_index: The line number to start at.

        Returns:
            A tuple containing a `Section` (or `None`) and the index at which to continue parsing.
        """
        text, i = self.read_block(lines, start_index)

        sub_sections = []
        in_code_example = False
        in_code_block = False
        current_text: List[str] = []
        current_example: List[str] = []

        for line in text.split("\n"):
            if is_empty_line(line):
                if in_code_example:
                    if current_example:
                        sub_sections.append((Section.Type.EXAMPLES, "\n".join(current_example)))
                        current_example = []
                    in_code_example = False
                else:
                    current_text.append(line)

            elif in_code_example:
                current_example.append(line)

            elif line.startswith("```"):
                in_code_block = not in_code_block
                current_text.append(line)

            elif in_code_block:
                current_text.append(line)

            elif line.startswith(">>>"):
                if current_text:
                    sub_sections.append((Section.Type.MARKDOWN, "\n".join(current_text)))
                    current_text = []
                in_code_example = True
                current_example.append(line)

            else:
                current_text.append(line)

        if current_text:
            sub_sections.append((Section.Type.MARKDOWN, "\n".join(current_text)))
        elif current_example:
            sub_sections.append((Section.Type.EXAMPLES, "\n".join(current_example)))

        if sub_sections:
            return Section(Section.Type.EXAMPLES, sub_sections), i

        self.error(f"Empty examples section at line {start_index}")
        return None, i


def is_empty_line(line) -> bool:
    """
    Tell if a line is empty.

    Arguments:
        line: The line to check.

    Returns:
        True if the line is empty or composed of blanks only, False otherwise.
    """
    return not line.strip()
