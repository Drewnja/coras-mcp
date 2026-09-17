"""A small text notation for CORAS diagrams.

    diagram "Risk picture"

    threat      "Script kiddie"        kind=deliberate
    vulnerability "Weak password"      as weakpw
    scenario    "Password guessed"     as guess
    incident    "Customer data leaked" as leak
    asset       "Customer data"        as data
    stakeholder "The bank"             as bank
    treatment   "Enforce 2FA"          as mfa
    region      "Internet facing"      contains=guess,weakpw

    "Script kiddie" -> weakpw
    weakpw -> guess  "often"
    guess  -> leak   "likely"
    leak   -> data   "major"
    bank   -> data
    mfa    -> guess  strategy=ReduceLikelihood

Anything after ``#`` is a comment.  An element can be referred to by its
``as`` name or by its full name in quotes.  Relationship types are worked out
from the elements they connect, exactly the way the editor does it.
"""

import re

from . import spec
from .model import slugify
from .spec import SpecError

_KEYS = {
    "as", "id", "kind", "type", "color", "colour", "background", "font", "size",
    "x", "y", "width", "height", "w", "h", "contains", "strategy", "label",
    "pin", "pinned",
}
_ARROWS = ("-->", "->", "<--", "<-")


def _tokenize(line):
    tokens = []
    index = 0
    length = len(line)
    while index < length:
        char = line[index]
        if char.isspace():
            index += 1
            continue
        if char in "\"'":
            quote = char
            index += 1
            start = index
            buf = []
            while index < length:
                if line[index] == "\\" and index + 1 < length:
                    buf.append(line[index + 1])
                    index += 2
                    continue
                if line[index] == quote:
                    break
                buf.append(line[index])
                index += 1
            if index >= length:
                raise SpecError("unterminated quote in: %s" % line.strip())
            index += 1
            tokens.append(("quoted", "".join(buf)))
            continue
        start = index
        while index < length and not line[index].isspace() and line[index] not in "\"'":
            index += 1
        word = line[start:index]
        if index < length and line[index] in "\"'" and "=" in word and word.endswith("="):
            # key="value with spaces"
            quote = line[index]
            index += 1
            begin = index
            while index < length and line[index] != quote:
                index += 1
            if index >= length:
                raise SpecError("unterminated quote in: %s" % line.strip())
            tokens.append(("bare", word + line[begin:index]))
            index += 1
            continue
        tokens.append(("bare", word))
    return tokens


def _split_kv(tokens):
    """Pull key=value tokens and an `as <id>` clause out of a token list."""
    options = {}
    rest = []
    index = 0
    while index < len(tokens):
        kind, value = tokens[index]
        if kind == "bare" and value.lower() == "as" and index + 1 < len(tokens):
            options["as"] = tokens[index + 1][1]
            index += 2
            continue
        if kind == "bare" and "=" in value:
            key, _, raw = value.partition("=")
            key = key.strip().lower()
            if key in _KEYS:
                options[key] = raw
                index += 1
                continue
        rest.append((kind, value))
        index += 1
    return options, rest


def _name_from(rest, line):
    if not rest:
        return None
    if rest[0][0] == "quoted":
        return rest[0][1]
    words = []
    for kind, value in rest:
        if kind == "quoted":
            break
        words.append(value)
    return " ".join(words) if words else None


def parse(text):
    """Parse the notation into the JSON spec that build_model() understands."""
    diagrams = []
    current = None
    declared = {}
    options = {}

    def ensure_diagram():
        if not diagrams:
            diagrams.append({"name": "Diagram", "nodes": [], "edges": []})
        return diagrams[-1]

    for number, raw_line in enumerate(str(text).splitlines(), start=1):
        line = _strip_comment(raw_line).rstrip()
        if not line.strip():
            continue
        try:
            tokens = _tokenize(line)
        except SpecError as error:
            raise SpecError("line %d: %s" % (number, error))
        if not tokens:
            continue

        head = tokens[0][1]
        lowered = head.lower() if tokens[0][0] == "bare" else None

        try:
            if lowered in ("diagram", "page", "tab"):
                opts, rest = _split_kv(tokens[1:])
                name = _name_from(rest, line) or "Diagram %d" % (len(diagrams) + 1)
                diagrams.append({"name": name, "nodes": [], "edges": []})
                continue

            if lowered in ("layout", "direction"):
                opts, rest = _split_kv(tokens[1:])
                value = _name_from(rest, line)
                if value:
                    options["direction"] = value.strip().lower()
                continue

            arrow_index = _find_arrow(tokens)
            if arrow_index is not None:
                diagram = ensure_diagram()
                edge = _parse_edge(tokens, arrow_index, declared)
                diagram["edges"].append(edge)
                continue

            if lowered is None:
                raise SpecError("expected an element type or a relationship")

            node_type = spec.normalise_node_type(lowered)
            opts, rest = _split_kv(tokens[1:])
            name = _name_from(rest, line)
            if name is None:
                raise SpecError("%s needs a name" % lowered)
            node = _parse_node(node_type, lowered, name, opts)
            declared[name.strip().lower()] = node["id"]
            declared[node["id"].lower()] = node["id"]
            ensure_diagram()["nodes"].append(node)
        except SpecError as error:
            raise SpecError("line %d: %s" % (number, error))

    if not diagrams:
        raise SpecError("nothing to draw: the text has no elements")
    result = {"diagrams": diagrams}
    result.update(options)
    return result


def _strip_comment(line):
    """Cut a trailing # comment, ignoring # characters inside quotes."""
    quote = None
    skip = False
    for index, char in enumerate(line):
        if skip:
            skip = False
            continue
        if quote:
            if char == "\\":
                skip = True
            elif char == quote:
                quote = None
        elif char in "\"'":
            quote = char
        elif char == "#":
            return line[:index]
        elif char == "/" and line[index:index + 2] == "//":
            return line[:index]
    return line


def _find_arrow(tokens):
    for index, (kind, value) in enumerate(tokens):
        if kind == "bare" and value in _ARROWS:
            return index
    return None


def _parse_node(node_type, keyword, name, opts):
    node = {"type": node_type, "name": name}
    node["id"] = opts.get("as") or opts.get("id") or slugify(name, fallback=node_type)
    kind = opts.get("kind") or spec.threat_kind_from_type(keyword)
    if node_type == "threat" and kind:
        node["kind"] = kind
    for key, target in (("color", "color"), ("colour", "color"), ("background", "color")):
        if key in opts:
            node["color"] = opts[key]
    if "font" in opts or "size" in opts:
        font = {}
        if "font" in opts:
            font["name"] = opts["font"]
        if "size" in opts:
            font["size"] = int(opts["size"])
        node["font"] = font
    for key in ("x", "y"):
        if key in opts:
            node[key] = float(opts[key])
    for key, target in (("width", "width"), ("w", "width"), ("height", "height"), ("h", "height")):
        if key in opts:
            node[target] = float(opts[key])
    if "contains" in opts:
        node["contains"] = [part.strip() for part in opts["contains"].split(",") if part.strip()]
    if opts.get("pin") or opts.get("pinned"):
        node["pinned"] = True
    return node


def _parse_edge(tokens, arrow_index, declared):
    arrow = tokens[arrow_index][1]
    left = tokens[:arrow_index]
    right = tokens[arrow_index + 1:]
    if not left or not right:
        raise SpecError("a relationship needs an element on both sides of %s" % arrow)

    opts, right_rest = _split_kv(right)
    left_opts, left_rest = _split_kv(left)
    opts.update({k: v for k, v in left_opts.items() if k not in opts})

    source = _reference(left_rest, declared)
    if not right_rest:
        raise SpecError("a relationship needs a target")
    target = _reference(right_rest[:1], declared)
    label = None
    for kind, value in right_rest[1:]:
        if kind == "quoted":
            label = value
            break
        if label is None:
            label = value
        else:
            label += " " + value

    edge = {"from": source, "to": target}
    if arrow.startswith("<"):
        edge = {"from": target, "to": source}
    if "label" in opts:
        label = opts["label"]
    if label:
        edge["label"] = label
    if "type" in opts:
        edge["type"] = opts["type"]
    if "strategy" in opts:
        edge["strategy"] = opts["strategy"]
    return edge


def _reference(tokens, declared):
    if not tokens:
        raise SpecError("missing element reference")
    if tokens[0][0] == "quoted":
        name = tokens[0][1]
    else:
        name = " ".join(value for kind, value in tokens if kind == "bare")
    key = name.strip().lower()
    return declared.get(key, name.strip())


# --------------------------------------------------------------------------
# Emitting
# --------------------------------------------------------------------------

_KEYWORD = {
    "stakeholder": "stakeholder",
    "threat": "threat",
    "vulnerability": "vulnerability",
    "threat-scenario": "scenario",
    "unwanted-incident": "incident",
    "risk": "risk",
    "asset": "asset",
    "treatment": "treatment",
    "region": "region",
    "comment": "comment",
}


def _quote(value):
    value = str(value)
    if re.match(r"^[A-Za-z0-9_.\-]+$", value):
        return value
    return '"%s"' % value.replace('"', '\\"')


def to_dsl(model):
    """Render a Model back into the text notation."""
    lines = []
    for index, diagram in enumerate(model.diagrams):
        if index:
            lines.append("")
        lines.append("diagram %s" % _quote(diagram.name))
        lines.append("")
        width = max([len(_KEYWORD[n.element.type]) for n in diagram.nodes] or [6])
        for node in diagram.nodes:
            element = node.element
            parts = ["%-*s" % (width, _KEYWORD[element.type]), _quote(element.name or element.key)]
            if slugify(element.name or "") != element.key:
                parts.append("as %s" % element.key)
            if element.type == "threat" and element.threat_kind != spec.DEFAULT_THREAT_KIND:
                parts.append("kind=%s" % element.threat_kind)
            if node.contains:
                parts.append("contains=%s" % ",".join(node.contains))
            lines.append(" ".join(parts))
        if diagram.edges:
            lines.append("")
        for edge in diagram.edges:
            relationship = edge.relationship
            parts = ["%s -> %s" % (_quote(relationship.source), _quote(relationship.target))]
            if relationship.label:
                parts.append('"%s"' % str(relationship.label).replace('"', '\\"'))
            if relationship.type == "treat" and relationship.strategy != spec.DEFAULT_TREAT_STRATEGY:
                parts.append("strategy=%s" % relationship.strategy)
            lines.append(" ".join(parts))
    return "\n".join(lines) + "\n"
