"""This module defines functions and classes to parse docstrings into structured data."""
import re
from typing import List, Optional

from docstring_parser import parse
from docstring_parser.common import Docstring, DocstringMeta

from pytkdocs.parsers.docstrings.base import AnnotatedObject, Attribute, Parameter, Parser, Section, empty


class Numpy(Parser):
    """A Numpy-style docstrings parser."""

    def __init__(self) -> None:
        """
        Initialize the objects.
        """
        super().__init__()
        self.section_reader = {
            Section.Type.PARAMETERS: self.read_parameters_section,
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

        docstring_obj = parse(docstring)
        description_all = (
            none_str_cast(docstring_obj.short_description) + "\n\n" + none_str_cast(docstring_obj.long_description)
        ).strip()
        sections = [Section(Section.Type.MARKDOWN, description_all)] if description_all else []
        sections_other = [
            reader(docstring_obj)  # type: ignore
            if sec == Section.Type.RETURN
            else reader(docstring, docstring_obj)  # type: ignore
            for (sec, reader) in self.section_reader.items()
        ]
        sections.extend([sec for sec in sections_other if sec])
        return sections

    def read_parameters_section(
        self,
        docstring: str,
        docstring_obj: Docstring,
    ) -> Optional[Section]:
        """
        Parse a "parameters" section.

        Arguments:
            lines: The parameters block lines.
            start_index: The line number to start at.

        Returns:
            A tuple containing a `Section` (or `None`) and the index at which to continue parsing.
        """
        parameters = []

        docstring_params = [p for p in docstring_obj.params if p.args[0] == "param"]

        for param in docstring_params:
            name = param.arg_name
            kind = None
            type_name = param.type_name
            default = param.default or empty
            try:
                signature_param = self.context["signature"].parameters[name.lstrip("*")]  # type: ignore
            except (AttributeError, KeyError):
                self.error(f"No type annotation for parameter '{name}'")
            else:
                if signature_param.annotation is not empty:
                    type_name = signature_param.annotation
                if signature_param.default is not empty:
                    default = signature_param.default
                kind = signature_param.kind
            parameters.append(
                Parameter(
                    name=param.arg_name,
                    annotation=type_name,
                    description=param.description,
                    default=default,
                    kind=kind,
                )
            )

        if parameters:
            return Section(Section.Type.PARAMETERS, parameters)
        if re.search("Parameters\n", docstring):
            self.error("Empty parameter section")
        return None

    def read_attributes_section(
        self,
        docstring: str,
        docstring_obj: Docstring,
    ) -> Optional[Section]:
        """
        Parse an "attributes" section.

        Arguments:
            docstring_obj: Docstring object parsed by docstring_parser.

        Returns:
            A tuple containing a `Section` (or `None`).
        """
        attributes = []
        docstring_attributes = [p for p in docstring_obj.params if p.args[0] == "attribute"]

        for attr in docstring_attributes:
            attributes.append(
                Attribute(
                    name=attr.arg_name,
                    annotation=attr.type_name,
                    description=attr.description,
                )
            )

        if attributes:
            return Section(Section.Type.ATTRIBUTES, attributes)
        if re.search("Attributes\n", docstring):
            self.error("Empty attributes section")
        return None

    def read_exceptions_section(
        self,
        docstring: str,
        docstring_obj: Docstring,
    ) -> Optional[Section]:
        """
        Parse an "exceptions" section.

        Arguments:
            docstring_obj: Docstring object parsed by docstring_parser.

        Returns:
            A tuple containing a `Section` (or `None`) and the index at which to continue parsing.
        """
        exceptions = []
        except_obj = docstring_obj.raises

        for exception in except_obj:
            exceptions.append(AnnotatedObject(exception.type_name, exception.description))

        if exceptions:
            return Section(Section.Type.EXCEPTIONS, exceptions)
        if re.search("Raises\n", docstring):
            self.error("Empty exceptions section")
        return None

    def read_return_section(
        self,
        docstring_obj: Docstring,
    ) -> Optional[Section]:
        """
        Parse a "returns" section.

        Arguments:
            docstring_obj: Docstring object parsed by docstring_parser.

        Returns:
            A tuple containing a `Section` (or `None`).
        """
        return_obj = docstring_obj.returns if docstring_obj.returns else []
        text = return_obj.description if return_obj else ""

        if self.context["signature"]:
            annotation = self.context["signature"].return_annotation
        else:
            annotation = self.context["annotation"]

        if annotation is empty:
            if text:
                annotation = return_obj.type_name or empty
                text = return_obj.description
            elif return_obj and annotation is empty:
                self.error("No return type annotation")

        if return_obj and not text:
            self.error("Empty return description")
        if not return_obj or annotation is empty or not text:
            return None
        return Section(Section.Type.RETURN, AnnotatedObject(annotation, text))

    def read_examples_section(
        self,
        docstring: str,
        docstring_obj: Docstring,
    ) -> Optional[Section]:
        """
        Parse an "examples" section.

        Arguments:
            docstring_obj: Docstring object parsed by docstring_parser.

        Returns:
            A tuple containing a `Section` (or `None`).
        """
        text = next(
            (
                meta.description
                for meta in docstring_obj.meta
                if isinstance(meta, DocstringMeta) and meta.args[0] == "examples"
            ),
            "",
        )

        sub_sections = []
        in_code_example = False
        in_code_block = False
        current_text: List[str] = []
        current_example: List[str] = []

        if text:
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
            return Section(Section.Type.EXAMPLES, sub_sections)
        if re.search("Examples\n", docstring):
            self.error("Empty examples section")
        return None


def is_empty_line(line: str) -> bool:
    """
    Tell if a line is empty.

    Arguments:
        line: The line to check.

    Returns:
        True if the line is empty or composed of blanks only, False otherwise.
    """
    return not line.strip()


def none_str_cast(string: Optional[str]):
    return string or ""
