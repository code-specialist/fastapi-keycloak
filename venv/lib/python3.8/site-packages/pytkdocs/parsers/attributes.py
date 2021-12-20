"""Module containing functions to parse attributes in the source code."""

import ast
import inspect
from functools import lru_cache
from textwrap import dedent
from typing import get_type_hints

try:
    from ast import unparse  # type: ignore
except ImportError:
    from astunparse import unparse  # type: ignore

RECURSIVE_NODES = (ast.If, ast.IfExp, ast.Try, ast.With)


def get_nodes(obj):
    try:
        source = inspect.getsource(obj)
    except (OSError, TypeError):
        source = ""
    return ast.parse(dedent(source)).body


def recurse_on_node(node):
    if isinstance(node, ast.Try):
        yield from get_pairs(node.body)
        for handler in node.handlers:
            yield from get_pairs(handler.body)
        yield from get_pairs(node.orelse)
        yield from get_pairs(node.finalbody)
    elif isinstance(node, ast.If):
        yield from get_pairs(node.body)
        yield from get_pairs(node.orelse)
    else:
        yield from get_pairs(node.body)


def get_pairs(nodes):
    if len(nodes) < 2:
        return

    index = 0
    while index < len(nodes):
        node1 = nodes[index]
        if index < len(nodes) - 1:
            node2 = nodes[index + 1]
        else:
            node2 = None
        if isinstance(node1, (ast.Assign, ast.AnnAssign)):
            if isinstance(node2, ast.Expr) and isinstance(node2.value, ast.Str):
                yield node1, node2.value
                index += 2
            else:
                yield node1, None
                index += 1
        else:
            index += 1
            if isinstance(node1, RECURSIVE_NODES):
                yield from recurse_on_node(node1)
            if isinstance(node2, RECURSIVE_NODES):
                yield from recurse_on_node(node2)
                index += 1
            elif not isinstance(node2, (ast.Assign, ast.AnnAssign)):
                index += 1


def get_module_or_class_attributes(nodes):
    result = {}
    for assignment, string_node in get_pairs(nodes):
        string = inspect.cleandoc(string_node.s) if string_node else None
        if isinstance(assignment, ast.Assign):
            names = []
            for target in assignment.targets:
                if isinstance(target, ast.Name):
                    names.append(target.id)
                elif isinstance(target, ast.Tuple):
                    names.extend([name.id for name in target.elts])
        else:
            names = [assignment.target.id]
        for name in names:
            result[name] = string
    return result


def combine(docstrings, type_hints):
    return {
        name: {"annotation": type_hints.get(name, inspect.Signature.empty), "docstring": docstrings.get(name)}
        for name in set(docstrings.keys()) | set(type_hints.keys())
    }


def merge(base, extra):
    for attr_name, data in extra.items():
        if attr_name in base:
            if data["annotation"] is not inspect.Signature.empty:
                base[attr_name]["annotation"] = data["annotation"]
            if data["docstring"] is not None:
                base[attr_name]["docstring"] = data["docstring"]
        else:
            base[attr_name] = data


@lru_cache()
def get_module_attributes(module):
    return combine(get_module_or_class_attributes(get_nodes(module)), get_type_hints(module))


@lru_cache()
def get_class_attributes(cls):
    nodes = get_nodes(cls)
    if not nodes:
        return {}
    try:
        type_hints = get_type_hints(cls)
    except NameError:
        # The __config__ attribute (a class) of Pydantic models trigger this error:
        # NameError: name 'SchemaExtraCallable' is not defined
        type_hints = {}
    return combine(get_module_or_class_attributes(nodes[0].body), type_hints)


def pick_target(target):
    return isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and target.value.id == "self"


def unparse_annotation(node):
    code = unparse(node).rstrip("\n")
    return code.replace("(", "").replace(")", "")


@lru_cache()
def get_instance_attributes(func):
    nodes = get_nodes(func)
    if not nodes:
        return {}

    result = {}

    for assignment, string in get_pairs(nodes[0].body):
        annotation = names = None
        if isinstance(assignment, ast.AnnAssign):
            if pick_target(assignment.target):
                names = [assignment.target.attr]
                annotation = unparse_annotation(assignment.annotation)
        else:
            names = [target.attr for target in assignment.targets if pick_target(target)]

        if not names or (string is None and annotation is None):
            continue

        docstring = inspect.cleandoc(string.s) if string else None
        for name in names:
            result[name] = {"annotation": annotation, "docstring": docstring}

    return result
