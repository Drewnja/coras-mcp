"""The MCP tools: create, read, edit, render, validate and open CORAS diagrams."""

import base64
import json
import os
import shutil
import tempfile

from . import bridge, dgx, dsl, layout, spec
from .model import (EdgeView, NodeView, build_model, footprint, node_from_dict,
                    parse_color, parse_font, slugify)
from .spec import SpecError

VERSION = "1.0.0"
MAX_PREVIEW_BYTES = 4 * 1024 * 1024


class ToolError(Exception):
    """A failure that should be reported to the model, not crash the server."""


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _require(arguments, name):
    value = arguments.get(name)
    if value is None or (isinstance(value, str) and not value.strip()):
        raise ToolError("%r is required" % name)
    return value


def _resolve_path(path, must_exist=False, default_suffix=".dgx"):
    path = os.path.abspath(os.path.expanduser(str(path)))
    if default_suffix and not os.path.splitext(path)[1]:
        path += default_suffix
    if must_exist and not os.path.isfile(path):
        raise ToolError("no such file: %s" % path)
    return path


def _spec_from_arguments(arguments):
    raw_spec = arguments.get("spec")
    text = arguments.get("text") or arguments.get("dsl")
    if raw_spec is None and text is None:
        raise ToolError("give either 'spec' (structured) or 'text' (the CORAS notation)")
    if raw_spec is not None and text is not None:
        raise ToolError("give 'spec' or 'text', not both")
    if text is not None:
        return dsl.parse(text)
    if isinstance(raw_spec, str):
        try:
            raw_spec = json.loads(raw_spec)
        except ValueError as error:
            raise ToolError("'spec' is a string but not valid JSON: %s" % error)
    if not isinstance(raw_spec, dict):
        raise ToolError("'spec' must be an object")
    return raw_spec


def _summarise(model):
    lines = []
    for index, diagram in enumerate(model.diagrams):
        counts = {}
        for node in diagram.nodes:
            counts[node.element.type] = counts.get(node.element.type, 0) + 1
        breakdown = ", ".join("%d %s" % (count, name)
                              for name, count in sorted(counts.items()))
        lines.append("  %d. %r - %d elements (%s), %d relationships"
                     % (index + 1, diagram.name, len(diagram.nodes),
                        breakdown or "empty", len(diagram.edges)))
    return "\n".join(lines)


def _bounds(diagram):
    rects = []
    for node in diagram.nodes:
        if node.x is None:
            continue
        overhang, _, width, height = footprint(node)
        rects.append((node.x - overhang, node.y, width, height))
    if not rects:
        return (0, 0, 0, 0)
    left = min(r[0] for r in rects)
    top = min(r[1] for r in rects)
    return (left, top,
            max(r[0] + r[2] for r in rects) - left,
            max(r[1] + r[3] for r in rects) - top)


def _image_content(path):
    with open(path, "rb") as handle:
        data = handle.read()
    if len(data) > MAX_PREVIEW_BYTES:
        return None
    return {
        "type": "image",
        "data": base64.b64encode(data).decode("ascii"),
        "mimeType": "image/png",
    }


def _preview(path, diagram=None, scale=1.5, limit=3):
    """Render diagrams through the editor and return (content blocks, notes)."""
    content, notes = [], []
    directory = tempfile.mkdtemp(prefix="coras-preview-")
    try:
        result = bridge.render(path, directory, diagram=diagram, fmt="png", scale=scale)
        images = result.get("images", [])
        if len(images) > limit:
            notes.append("showing the first %d of %d diagrams" % (limit, len(images)))
            images = images[:limit]
        for image in images:
            block = _image_content(image["path"])
            if block is None:
                notes.append("the preview of %r was too large to include"
                             % image.get("diagram"))
                continue
            content.append({"type": "text",
                            "text": "Diagram %r as the editor draws it:" % image.get("diagram")})
            content.append(block)
    except bridge.BridgeError as error:
        notes.append("could not render a preview: %s" % error)
    finally:
        shutil.rmtree(directory, ignore_errors=True)
    return content, notes


def _java_note(error):
    return ("Java is not usable right now, so the file was written but not checked "
            "against the editor (%s)." % error)


# --------------------------------------------------------------------------
# coras_reference
# --------------------------------------------------------------------------

def reference(arguments):
    data = spec.reference()
    data["notation"] = dsl.__doc__.strip()
    data["spec_shape"] = {
        "diagrams": [{
            "name": "Risk picture",
            "nodes": [
                {"id": "hacker", "type": "threat", "name": "Script kiddie",
                 "kind": "deliberate"},
                {"id": "data", "type": "asset", "name": "Customer data"},
            ],
            "edges": [{"from": "hacker", "to": "data", "label": "optional text"}],
        }],
    }
    data["notes"] = [
        "Relationship types are inferred from the two elements; set 'type' only to "
        "override the inference.",
        "An edge label becomes the text drawn on the arrow (likelihood on an initiate "
        "arrow, consequence on a harm arrow).",
        "The same 'id' used in two diagrams means the same model element shown twice.",
        "A treatment cannot point at a risk - the file format rejects it. Point it at "
        "the threat, vulnerability, scenario or unwanted incident instead.",
        "The editor always reads a treat arrow back as ReduceLikelihood; the strategy "
        "is stored in the file but the 2007 editor does not display it.",
    ]
    return [{"type": "text", "text": json.dumps(data, indent=2, ensure_ascii=False)}]


# --------------------------------------------------------------------------
# coras_create_diagram
# --------------------------------------------------------------------------

def create_diagram(arguments):
    path = _resolve_path(_require(arguments, "path"))
    raw_spec = _spec_from_arguments(arguments)
    direction = arguments.get("direction") or raw_spec.get("direction") or "right"
    mode = arguments.get("layout") or raw_spec.get("layout") or "auto"
    if mode not in ("auto", "preserve", "manual"):
        raise ToolError("'layout' must be auto, preserve or manual")
    if os.path.exists(path) and not arguments.get("overwrite", True):
        raise ToolError("%s already exists (pass overwrite: true to replace it)" % path)

    model = build_model(raw_spec)
    warnings = list(model.warnings)
    warnings.extend(layout.layout_model(model, direction=direction, mode=mode))

    if arguments.get("dry_run"):
        report = ["Nothing written (dry run). The model is valid:",
                  _summarise(model)]
        if warnings:
            report.append("Warnings:\n  - " + "\n  - ".join(warnings))
        return [{"type": "text", "text": "\n".join(report)}]

    written = dgx.write(model, path)

    report = ["Wrote %s" % written,
              "Diagrams:", _summarise(model)]
    for diagram in model.diagrams:
        left, top, width, height = _bounds(diagram)
        report.append("  %r spans %dx%d px" % (diagram.name, round(width), round(height)))
    if warnings:
        report.append("Warnings:\n  - " + "\n  - ".join(warnings))

    content = [{"type": "text", "text": "\n".join(report)}]
    want_preview = arguments.get("preview", True)
    if want_preview:
        images, notes = _preview(written, scale=float(arguments.get("scale", 1.5)))
        content.extend(images)
        if notes:
            content.append({"type": "text", "text": "\n".join(notes)})
    elif arguments.get("validate", True):
        try:
            bridge.validate(written)
            content.append({"type": "text",
                            "text": "The editor loads the file without complaint."})
        except bridge.BridgeError as error:
            content.append({"type": "text", "text": _java_note(error)})
    return content


# --------------------------------------------------------------------------
# coras_read_diagram
# --------------------------------------------------------------------------

def read_diagram(arguments):
    path = _resolve_path(_require(arguments, "path"), must_exist=True)
    model = dgx.read(path)
    fmt = (arguments.get("format") or "both").lower()
    if fmt not in ("json", "text", "both", "summary"):
        raise ToolError("'format' must be json, text, both or summary")

    report = ["%s" % path, "Diagrams:", _summarise(model)]
    if model.warnings:
        report.append("Warnings:\n  - " + "\n  - ".join(model.warnings))
    content = [{"type": "text", "text": "\n".join(report)}]

    if fmt in ("json", "both"):
        content.append({"type": "text",
                        "text": "Structured spec:\n" + json.dumps(
                            model.to_dict(), indent=2, ensure_ascii=False)})
    if fmt in ("text", "both"):
        content.append({"type": "text", "text": "CORAS notation:\n" + dsl.to_dsl(model)})
    if arguments.get("preview"):
        images, notes = _preview(path, scale=float(arguments.get("scale", 1.5)))
        content.extend(images)
        if notes:
            content.append({"type": "text", "text": "\n".join(notes)})
    return content


# --------------------------------------------------------------------------
# coras_edit_diagram
# --------------------------------------------------------------------------

def _find_diagram(model, reference):
    if reference is None:
        if not model.diagrams:
            raise ToolError("the file has no diagrams")
        return model.diagrams[0]
    if isinstance(reference, int):
        diagram = model.diagram(reference)
    else:
        diagram = model.diagram(str(reference))
        if diagram is None:
            try:
                diagram = model.diagram(int(reference))
            except (TypeError, ValueError):
                diagram = None
    if diagram is None:
        raise ToolError("no diagram called %r; the file has: %s"
                        % (reference, ", ".join(repr(d.name) for d in model.diagrams)))
    return diagram


def _find_key(model, reference, what="element"):
    """Resolve a reference by id or by display name.

    A .dgx file has nowhere to store the short ids used when the diagram was
    written, so after a round trip elements are addressed by their name, or by
    the slug of it. The error lists what the file actually holds.
    """
    key = str(reference)
    if key in model.elements:
        return key
    lowered = key.strip().lower()
    for element in model.iter_elements():
        if (element.name or "").strip().lower() == lowered:
            return element.key
    slug = slugify(key)
    if slug in model.elements:
        return slug
    known = ["%s (%s)" % (e.key, e.name) if e.name and e.name != e.key else e.key
             for e in model.iter_elements()]
    raise ToolError("no %s called %r in this file. It holds: %s"
                    % (what, reference, "; ".join(known) or "nothing"))


def _apply_operation(model, operation, state):
    touched = state["touched"]
    if not isinstance(operation, dict):
        raise ToolError("every operation must be an object")
    op = str(operation.get("op") or operation.get("action") or "").strip().lower()
    if not op:
        raise ToolError("an operation needs an 'op' field")

    if op in ("add_node", "add_element", "add"):
        diagram = _find_diagram(model, operation.get("diagram"))
        payload = {k: v for k, v in operation.items()
                   if k not in ("op", "action", "diagram")}
        alias = {}
        for element in model.iter_elements():
            alias.setdefault((element.name or "").strip().lower(), element.key)
            alias.setdefault(element.key.lower(), element.key)
        element, view = node_from_dict(model, payload, alias)
        if diagram.has(element.key):
            existing = diagram.node(element.key)
            for field in ("x", "y", "width", "height"):
                value = getattr(view, field)
                if value is not None:
                    setattr(existing, field, value)
            touched.add(diagram.name)
            return "updated %r in %r" % (element.name, diagram.name)
        diagram.add_node(view)
        touched.add(diagram.name)
        return "added %s %r to %r" % (element.type, element.name, diagram.name)

    if op in ("add_edge", "add_relationship", "connect"):
        diagram = _find_diagram(model, operation.get("diagram"))
        source = _find_key(model, _require(operation, "from") if "from" in operation
                           else _require(operation, "source"))
        target = _find_key(model, _require(operation, "to") if "to" in operation
                           else _require(operation, "target"))
        relationship = model.add_relationship(
            source, target,
            spec.normalise_edge_type(operation.get("type")),
            label=operation.get("label"),
            strategy=operation.get("strategy"))
        for key in (source, target):
            if not diagram.has(key):
                diagram.add_node(NodeView(model.elements[key]))
        if not any(view.relationship is relationship for view in diagram.edges):
            diagram.edges.append(EdgeView(relationship))
        touched.add(diagram.name)
        return "connected %r -> %r (%s)" % (source, target, relationship.type)

    if op in ("remove_node", "remove_element", "delete"):
        key = _find_key(model, _require(operation, "id"))
        if operation.get("diagram") is not None:
            diagram = _find_diagram(model, operation.get("diagram"))
            _drop_from_diagram(model, diagram, key)
            touched.add(diagram.name)
            return "removed %r from %r" % (key, diagram.name)
        for diagram in model.diagrams:
            _drop_from_diagram(model, diagram, key)
            touched.add(diagram.name)
        dead = [r.key for r in model.iter_relationships()
                if r.source == key or r.target == key]
        for relationship_key in dead:
            model.relationships.pop(relationship_key, None)
            model.relationship_order.remove(relationship_key)
        model.elements.pop(key, None)
        model.element_order.remove(key)
        return "removed %r from the model" % key

    if op in ("remove_edge", "disconnect"):
        source = _find_key(model, _require(operation, "from") if "from" in operation
                           else _require(operation, "source"))
        target = _find_key(model, _require(operation, "to") if "to" in operation
                           else _require(operation, "target"))
        removed = []
        for relationship in list(model.iter_relationships()):
            if relationship.source == source and relationship.target == target:
                removed.append(relationship.key)
        if not removed:
            raise ToolError("there is no relationship from %r to %r" % (source, target))
        for key in removed:
            model.relationships.pop(key, None)
            model.relationship_order.remove(key)
        for diagram in model.diagrams:
            before = len(diagram.edges)
            diagram.edges = [e for e in diagram.edges if e.relationship.key not in removed]
            if len(diagram.edges) != before:
                touched.add(diagram.name)
        return "removed the relationship %r -> %r" % (source, target)

    if op in ("rename", "set_name"):
        key = _find_key(model, _require(operation, "id"))
        model.elements[key].name = str(_require(operation, "name"))
        for diagram in model.diagrams:
            if diagram.has(key):
                node = diagram.node(key)
                node.width = node.height = None
                touched.add(diagram.name)
        return "renamed %r" % key

    if op in ("set", "update", "style"):
        key = _find_key(model, _require(operation, "id"))
        element = model.elements[key]
        if operation.get("kind") and element.type == "threat":
            element.threat_kind = spec.normalise_threat_kind(operation["kind"])
        if operation.get("name"):
            element.name = str(operation["name"])
        for diagram in model.diagrams:
            node = diagram.node(key)
            if node is None:
                continue
            if "color" in operation or "colour" in operation:
                node.color = parse_color(operation.get("color", operation.get("colour")))
            if "font" in operation:
                node.font = parse_font(operation["font"])
            for field in ("x", "y", "width", "height"):
                if field in operation and operation[field] is not None:
                    setattr(node, field, float(operation[field]))
                    if field in ("x", "y"):
                        node.pinned = True
            if operation.get("name"):
                node.width = node.height = None
            touched.add(diagram.name)
        return "updated %r" % key

    if op in ("set_label", "label"):
        source = _find_key(model, _require(operation, "from") if "from" in operation
                           else _require(operation, "source"))
        target = _find_key(model, _require(operation, "to") if "to" in operation
                           else _require(operation, "target"))
        found = False
        for relationship in model.iter_relationships():
            if relationship.source == source and relationship.target == target:
                relationship.label = str(operation.get("label") or "") or None
                found = True
        if not found:
            raise ToolError("there is no relationship from %r to %r" % (source, target))
        return "labelled %r -> %r" % (source, target)

    if op in ("add_diagram", "new_diagram"):
        name = str(_require(operation, "name"))
        diagram = model.add_diagram(name)
        for key in operation.get("include", []) or []:
            resolved = _find_key(model, key)
            diagram.add_node(NodeView(model.elements[resolved]))
        if operation.get("include"):
            keys = set(n.element.key for n in diagram.nodes)
            for relationship in model.iter_relationships():
                if relationship.source in keys and relationship.target in keys:
                    diagram.edges.append(EdgeView(relationship))
        touched.add(name)
        return "added the diagram %r" % name

    if op in ("remove_diagram", "delete_diagram"):
        diagram = _find_diagram(model, operation.get("diagram") or operation.get("name"))
        model.diagrams.remove(diagram)
        return "removed the diagram %r" % diagram.name

    if op in ("rename_diagram",):
        diagram = _find_diagram(model, operation.get("diagram"))
        diagram.name = str(_require(operation, "name"))
        return "renamed the diagram to %r" % diagram.name

    if op in ("relayout", "layout"):
        diagram = (_find_diagram(model, operation["diagram"])
                   if operation.get("diagram") is not None else None)
        targets = [diagram] if diagram else list(model.diagrams)
        for target in targets:
            for node in target.nodes:
                node.pinned = False
                node.x = node.y = None
                if operation.get("resize", True):
                    node.width = node.height = None
            touched.add(target.name)
            state["relayout"].add(target.name)
        return "re-laid out %s" % (repr(diagram.name) if diagram else "every diagram")

    raise ToolError("unknown operation %r" % op)


def _drop_from_diagram(model, diagram, key):
    diagram.nodes = [n for n in diagram.nodes if n.element.key != key]
    diagram._by_key.pop(key, None)
    diagram.edges = [e for e in diagram.edges
                     if e.relationship.source != key and e.relationship.target != key]


def edit_diagram(arguments):
    path = _resolve_path(_require(arguments, "path"), must_exist=True)
    operations = arguments.get("operations") or arguments.get("ops")
    if not operations:
        raise ToolError("'operations' is required: a list of edits to apply")
    if isinstance(operations, dict):
        operations = [operations]

    model = dgx.read(path)
    state = {"touched": set(), "relayout": set()}
    applied = []
    for operation in operations:
        applied.append(_apply_operation(model, operation, state))

    mode = arguments.get("layout") or "preserve"
    if mode not in ("auto", "preserve", "manual"):
        raise ToolError("'layout' must be auto, preserve or manual")
    direction = arguments.get("direction") or "right"
    warnings = list(model.warnings)
    for diagram in model.diagrams:
        if mode == "auto" or diagram.name in state["relayout"]:
            use = "auto"
        elif diagram.name in state["touched"] or any(n.x is None for n in diagram.nodes):
            use = mode
        else:
            continue
        warnings.extend(layout.layout_diagram(model, diagram,
                                              direction=direction, mode=use))

    if arguments.get("backup", True) and os.path.isfile(path):
        shutil.copy2(path, path + ".bak")
    written = dgx.write(model, path)

    report = ["Applied %d edit(s) to %s:" % (len(applied), written)]
    report.extend("  - " + line for line in applied)
    report.append("Diagrams now:")
    report.append(_summarise(model))
    if warnings:
        report.append("Warnings:\n  - " + "\n  - ".join(warnings))
    content = [{"type": "text", "text": "\n".join(report)}]
    if arguments.get("preview", True):
        images, notes = _preview(written, scale=float(arguments.get("scale", 1.5)))
        content.extend(images)
        if notes:
            content.append({"type": "text", "text": "\n".join(notes)})
    return content


# --------------------------------------------------------------------------
# coras_render_diagram / coras_validate_file / coras_open_editor
# --------------------------------------------------------------------------

def render_diagram(arguments):
    path = _resolve_path(_require(arguments, "path"), must_exist=True)
    fmt = (arguments.get("format") or "png").lower()
    if fmt not in ("png", "svg"):
        raise ToolError("'format' must be png or svg")
    scale = float(arguments.get("scale", 2.0))
    diagram = arguments.get("diagram")
    out = arguments.get("out")
    keep = out is not None
    if out is None:
        out = tempfile.mkdtemp(prefix="coras-render-")
    else:
        out = os.path.abspath(os.path.expanduser(str(out)))

    try:
        result = bridge.render(path, out, diagram=diagram, fmt=fmt, scale=scale)
    except bridge.BridgeError as error:
        raise ToolError(str(error))

    lines = ["Rendered %d diagram(s) from %s:" % (len(result.get("images", [])), path)]
    content = []
    for image in result.get("images", []):
        lines.append("  - %r -> %s (%sx%s)" % (image.get("diagram"), image["path"],
                                               image.get("width"), image.get("height")))
        if fmt == "png" and arguments.get("inline", True):
            block = _image_content(image["path"])
            if block is not None:
                content.append({"type": "text", "text": "Diagram %r:" % image.get("diagram")})
                content.append(block)
    if not keep:
        lines.append("(written to a temporary folder; pass 'out' to keep the files)")
    return [{"type": "text", "text": "\n".join(lines)}] + content


def validate_file(arguments):
    path = _resolve_path(_require(arguments, "path"), must_exist=True)
    try:
        model = dgx.read(path)
        local = "The file parses: %d elements, %d relationships, %d diagram(s)." % (
            len(model.element_order), len(model.relationship_order), len(model.diagrams))
    except SpecError as error:
        raise ToolError(str(error))
    try:
        result = bridge.validate(path)
    except bridge.BridgeError as error:
        return [{"type": "text",
                 "text": local + "\nThe editor itself could not be asked: %s" % error}]
    lines = [local, "The Threat Modelling Tool loads it cleanly:"]
    for diagram in result.get("diagrams", []):
        box = diagram.get("bounds") or {}
        lines.append("  - %r: %d elements, %d relationships%s"
                     % (diagram.get("name"), diagram.get("nodes", 0), diagram.get("edges", 0),
                        (", %dx%d px" % (round(box.get("width", 0)), round(box.get("height", 0))))
                        if box else ""))
    return [{"type": "text", "text": "\n".join(lines)}]


def open_editor(arguments):
    path = arguments.get("path")
    if path:
        path = _resolve_path(path, must_exist=True)
    try:
        result = bridge.open_editor(path)
    except bridge.BridgeError as error:
        raise ToolError(str(error))
    if path:
        return [{"type": "text",
                 "text": "The Threat Modelling Tool is open with %s (pid %s)."
                         % (path, result.get("pid", "?"))}]
    return [{"type": "text", "text": "The Threat Modelling Tool is open (pid %s)."
                                     % result.get("pid", "?")}]


# --------------------------------------------------------------------------
# registry
# --------------------------------------------------------------------------

_NODE_SCHEMA = {
    "type": "object",
    "properties": {
        "id": {"type": "string",
               "description": "Short handle used by edges; defaults to a slug of the name. "
                              "The same id in two diagrams means one shared element."},
        "type": {"type": "string",
                 "enum": sorted(spec.NODE_TYPES),
                 "description": "Element type. Aliases such as 'scenario', 'incident', "
                                "'vuln', 'note' also work."},
        "name": {"type": "string", "description": "The text drawn on the element."},
        "kind": {"type": "string", "enum": sorted(spec.THREAT_KINDS),
                 "description": "Threat elements only: which threat icon to use."},
        "x": {"type": "number", "description": "Optional fixed position; pins the element."},
        "y": {"type": "number"},
        "width": {"type": "number", "description": "Optional fixed size."},
        "height": {"type": "number"},
        "color": {"type": "string", "description": "Fill colour, e.g. '#ffe9a8' or 'yellow'."},
        "contains": {"type": "array", "items": {"type": "string"},
                     "description": "Regions only: ids to wrap; the region is sized to fit them."},
    },
    "required": ["type", "name"],
    "additionalProperties": True,
}

_EDGE_SCHEMA = {
    "type": "object",
    "properties": {
        "from": {"type": "string", "description": "Source element id or name."},
        "to": {"type": "string", "description": "Target element id or name."},
        "label": {"type": "string",
                  "description": "Text drawn on the arrow: likelihood on an initiate "
                                 "arrow, consequence on a harm arrow."},
        "type": {"type": "string", "enum": sorted(spec.EDGE_TYPES),
                 "description": "Usually omitted: the relationship type is inferred from "
                                "the two elements exactly as the editor would."},
        "strategy": {"type": "string", "enum": list(spec.TREAT_STRATEGIES),
                     "description": "Treat arrows only."},
    },
    "required": ["from", "to"],
    "additionalProperties": True,
}

_DIAGRAM_SCHEMA = {
    "type": "object",
    "properties": {
        "name": {"type": "string", "description": "Tab name in the editor."},
        "nodes": {"type": "array", "items": _NODE_SCHEMA},
        "edges": {"type": "array", "items": _EDGE_SCHEMA},
    },
    "required": ["nodes"],
    "additionalProperties": False,
}

_SPEC_SCHEMA = {
    "type": "object",
    "description": "The model: one or more diagrams that may share elements.",
    "properties": {
        "diagrams": {"type": "array", "items": _DIAGRAM_SCHEMA, "minItems": 1},
        "elements": {"type": "array", "items": _NODE_SCHEMA,
                     "description": "Elements that exist in the model but are not drawn."},
    },
    "additionalProperties": True,
}

TOOLS = [
    {
        "name": "coras_reference",
        "description":
            "The CORAS language as this 2007 Threat Modelling Tool implements it: every "
            "element type, every relationship and which elements it may connect, the "
            "treatment strategies, and the text notation. Read this first when you are "
            "unsure whether an arrow is allowed - the editor refuses to open a file "
            "with an illegal relationship.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "handler": reference,
    },
    {
        "name": "coras_create_diagram",
        "description":
            "Build a CORAS diagram file (.dgx) from a description and lay it out "
            "automatically, then show you how the editor draws it. Give either a "
            "structured 'spec' or 'text' in the CORAS notation. Elements are placed in "
            "the canonical left-to-right order (stakeholder, threat, vulnerability, "
            "threat scenario, unwanted incident, risk, asset), sized to fit their "
            "labels, and relationship types are inferred from the elements they join. "
            "The resulting file opens in the Threat Modelling Tool as if it had been "
            "drawn by hand.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string",
                         "description": "Where to write the .dgx file."},
                "spec": _SPEC_SCHEMA,
                "text": {"type": "string",
                         "description": "The diagram in the CORAS text notation "
                                        "(see coras_reference). Use this or 'spec'."},
                "direction": {"type": "string", "enum": ["right", "down"],
                              "description": "Flow direction; 'right' is the CORAS norm."},
                "layout": {"type": "string", "enum": ["auto", "preserve", "manual"],
                           "description": "'auto' (default) positions everything; "
                                          "'manual' uses only the x/y you supply."},
                "preview": {"type": "boolean",
                            "description": "Render the result and return it as an image "
                                           "(default true). This also proves the editor "
                                           "can open the file."},
                "scale": {"type": "number", "description": "Preview scale, default 1.5."},
                "overwrite": {"type": "boolean",
                              "description": "Replace an existing file (default true)."},
                "dry_run": {"type": "boolean",
                            "description": "Validate and lay out without writing anything."},
            },
            "required": ["path"],
            "additionalProperties": False,
        },
        "handler": create_diagram,
    },
    {
        "name": "coras_read_diagram",
        "description":
            "Read an existing .dgx file and return it as a structured spec and as the "
            "CORAS text notation, so it can be inspected or rewritten. Optionally "
            "renders it so you can see the current state.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "The .dgx file to read."},
                "format": {"type": "string", "enum": ["json", "text", "both", "summary"],
                           "description": "What to return, default 'both'."},
                "preview": {"type": "boolean", "description": "Also render it as an image."},
                "scale": {"type": "number"},
            },
            "required": ["path"],
            "additionalProperties": False,
        },
        "handler": read_diagram,
    },
    {
        "name": "coras_edit_diagram",
        "description":
            "Change an existing .dgx file in place: add or remove elements and arrows, "
            "rename things, recolour, move, add or drop whole diagrams, or re-run the "
            "automatic layout. Existing positions are kept unless you ask for a "
            "relayout, and a .bak copy is made first.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "The .dgx file to change."},
                "operations": {
                    "type": "array",
                    "description":
                        "Edits, applied in order. Each has an 'op': add_node, add_edge, "
                        "remove_node, remove_edge, rename, set, set_label, add_diagram, "
                        "remove_diagram, rename_diagram, relayout. add_node takes the "
                        "same fields as a node in coras_create_diagram; add_edge takes "
                        "from/to/label/type/strategy; set takes id plus any of name, "
                        "kind, color, font, x, y, width, height.",
                    "items": {"type": "object", "additionalProperties": True},
                },
                "layout": {"type": "string", "enum": ["auto", "preserve", "manual"],
                           "description": "'preserve' (default) keeps hand positions and "
                                          "only places new elements; 'auto' re-lays out "
                                          "every diagram that changed."},
                "direction": {"type": "string", "enum": ["right", "down"]},
                "preview": {"type": "boolean", "description": "Return an image (default true)."},
                "scale": {"type": "number"},
                "backup": {"type": "boolean", "description": "Write a .bak copy (default true)."},
            },
            "required": ["path", "operations"],
            "additionalProperties": False,
        },
        "handler": edit_diagram,
    },
    {
        "name": "coras_render_diagram",
        "description":
            "Render a .dgx file to PNG or SVG using the editor's own renderer, so the "
            "image is pixel-identical to what the tool shows. Returns the picture inline "
            "and writes it to disk.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "The .dgx file to render."},
                "out": {"type": "string",
                        "description": "Output file, or a folder when rendering every "
                                       "diagram. Omit to use a temporary folder."},
                "diagram": {"type": "string",
                            "description": "Name or 0-based index of one diagram; "
                                           "omit for all of them."},
                "format": {"type": "string", "enum": ["png", "svg"]},
                "scale": {"type": "number", "description": "Default 2.0."},
                "inline": {"type": "boolean",
                           "description": "Return the PNG in the reply (default true)."},
            },
            "required": ["path"],
            "additionalProperties": False,
        },
        "handler": render_diagram,
    },
    {
        "name": "coras_validate_file",
        "description":
            "Check that a .dgx file is well formed and that the Threat Modelling Tool "
            "itself can load it, reporting what it found in each diagram.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
            "additionalProperties": False,
        },
        "handler": validate_file,
    },
    {
        "name": "coras_open_editor",
        "description":
            "Launch the Threat Modelling Tool GUI, optionally with a .dgx file already "
            "open, so the diagram can be looked at and edited by hand. The editor keeps "
            "running after this returns.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string",
                         "description": "Optional .dgx file to open on start-up."},
            },
            "additionalProperties": False,
        },
        "handler": open_editor,
    },
]

HANDLERS = {tool["name"]: tool["handler"] for tool in TOOLS}
DESCRIPTORS = [{k: v for k, v in tool.items() if k != "handler"} for tool in TOOLS]
