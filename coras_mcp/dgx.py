"""Reading and writing .dgx files (the CORAS profile XML the editor saves).

The writer reproduces the JAXB output of the editor element for element and
attribute for attribute -- same namespace prefix, same nesting, same attribute
order -- so a generated file is indistinguishable from one the editor saved
itself.
"""

import os
import xml.etree.ElementTree as ET

from . import spec
from .model import (BLACK, WHITE, YELLOW, DEFAULT_FONT, EdgeView, Model, NodeView,
                    slugify)
from .spec import SpecError

NS = spec.NAMESPACE
PREFIX = spec.PREFIX
_Q = "{%s}" % NS

_MODEL_ELEMENT_TO_TYPE = {info["model_element"]: key for key, info in spec.NODE_TYPES.items()}
_DIAGRAM_NODE_TO_TYPE = {info["diagram_node"]: key for key, info in spec.NODE_TYPES.items()}
_MODEL_REL_TO_TYPE = {info["model_element"]: key for key, info in spec.EDGE_TYPES.items()}
_DIAGRAM_EDGE_TO_TYPE = {info["diagram_edge"]: key for key, info in spec.EDGE_TYPES.items()}
_STEREOTYPE_TO_KIND = {v: k for k, v in spec.THREAT_KINDS.items()}


# --------------------------------------------------------------------------
# Writing
# --------------------------------------------------------------------------

def _num(value):
    """Format a double the way Java's Double.toString would."""
    value = float(value)
    if value != value or value in (float("inf"), float("-inf")):
        raise SpecError("coordinate is not a finite number")
    if value == int(value) and abs(value) < 1e15:
        return "%d.0" % int(value)
    return repr(value)


def _attr(value):
    return (str(value)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("\r", "&#13;")
            .replace("\n", "&#10;")
            .replace("\t", "&#9;"))


def _text(value):
    return (str(value)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;"))


def to_xml(model):
    """Serialise a Model as .dgx XML text."""
    out = []
    out.append('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>')
    out.append('<%s:model xmlns:%s="%s">' % (PREFIX, PREFIX, NS))
    out.append("    <%s:modelElements>" % PREFIX)

    for element in model.iter_elements():
        info = spec.NODE_TYPES[element.type]
        attrs = []
        if element.type == "threat":
            attrs.append('stereotype="%s"' % _attr(
                spec.stereotype_of("threat", element.threat_kind)))
        if element.name is not None:
            attrs.append('name="%s"' % _attr(element.name))
        attrs.append('id="%s"' % _attr(element.xml_id))
        out.append("        <%s:%s %s/>" % (PREFIX, info["model_element"], " ".join(attrs)))

    for relationship in model.iter_relationships():
        info = spec.EDGE_TYPES[relationship.type]
        source = model.elements[relationship.source]
        target = model.elements[relationship.target]
        attrs = []
        if relationship.type == "treat":
            attrs.append('strategy="%s"' % _attr(
                relationship.strategy or spec.DEFAULT_TREAT_STRATEGY))
        attrs.append('target="%s"' % _attr(target.xml_id))
        attrs.append('source="%s"' % _attr(source.xml_id))
        attrs.append('id="%s"' % _attr(relationship.xml_id))
        head = "        <%s:%s %s" % (PREFIX, info["model_element"], " ".join(attrs))
        if relationship.label:
            out.append(head + ">")
            out.append("            <consequence>%s</consequence>" % _text(relationship.label))
            out.append("        </%s:%s>" % (PREFIX, info["model_element"]))
        else:
            out.append(head + "/>")

    out.append("    </%s:modelElements>" % PREFIX)
    out.append("    <%s:diagrams>" % PREFIX)

    for diagram in model.diagrams:
        out.append('        <%s:diagram name="%s" id="%s">'
                   % (PREFIX, _attr(diagram.name or ""), _attr(diagram.xml_id)))
        out.append("            <%s:diagramElements>" % PREFIX)

        for node in diagram.nodes:
            tag = spec.NODE_TYPES[node.element.type]["diagram_node"]
            out.append('                <%s:%s modelElement="%s">'
                       % (PREFIX, tag, _attr(node.element.xml_id)))
            font = node.font or DEFAULT_FONT
            out.append('                    <%s:font size="%d" style="%d" name="%s"/>'
                       % (PREFIX, int(font.get("size", 12)), int(font.get("style", 0)),
                          _attr(font.get("name", "SansSerif"))))
            x, y = node.x or 0.0, node.y or 0.0
            width, height = node.width, node.height
            if width is None or height is None:
                width, height = spec.default_size(node.element.type)
            out.append('                    <%s:bounds height="%s" width="%s" y="%s" x="%s"/>'
                       % (PREFIX, _num(height), _num(width), _num(y), _num(x)))
            red, green, blue = node.color
            out.append('                    <%s:backgroundColor blue="%d" green="%d" red="%d"/>'
                       % (PREFIX, blue, green, red))
            out.append("                </%s:%s>" % (PREFIX, tag))

        for edge in diagram.edges:
            tag = spec.EDGE_TYPES[edge.relationship.type]["diagram_edge"]
            out.append('                <%s:%s modelElement="%s">'
                       % (PREFIX, tag, _attr(edge.relationship.xml_id)))
            if edge.path:
                out.append("                    <%s:path>" % PREFIX)
                for x, y in edge.path:
                    out.append('                        <%s:point y="%s" x="%s"/>'
                               % (PREFIX, _num(y), _num(x)))
                out.append("                    </%s:path>" % PREFIX)
            red, green, blue = edge.color
            out.append('                    <%s:lineColor blue="%d" green="%d" red="%d"/>'
                       % (PREFIX, blue, green, red))
            out.append("                </%s:%s>" % (PREFIX, tag))

        out.append("            </%s:diagramElements>" % PREFIX)
        out.append("        </%s:diagram>" % PREFIX)

    out.append("    </%s:diagrams>" % PREFIX)
    out.append("</%s:model>" % PREFIX)
    out.append("")
    return "\n".join(out)


def write(model, path):
    """Write a Model to *path* as .dgx. Returns the absolute path written."""
    path = os.path.abspath(os.path.expanduser(str(path)))
    if not path.lower().endswith(".dgx"):
        path += ".dgx"
    directory = os.path.dirname(path)
    if directory and not os.path.isdir(directory):
        os.makedirs(directory)
    data = to_xml(model)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(data)
    return path


# --------------------------------------------------------------------------
# Reading
# --------------------------------------------------------------------------

def _local(tag):
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _color(node, default):
    if node is None:
        return default
    try:
        return (int(node.get("red", 255)), int(node.get("green", 255)), int(node.get("blue", 255)))
    except (TypeError, ValueError):
        return default


def read(path):
    """Parse a .dgx file into a Model. Raises SpecError on anything unreadable."""
    path = os.path.abspath(os.path.expanduser(str(path)))
    if not os.path.isfile(path):
        raise SpecError("no such file: %s" % path)
    try:
        tree = ET.parse(path)
    except ET.ParseError as error:
        raise SpecError("%s is not valid XML: %s" % (path, error))
    root = tree.getroot()
    if _local(root.tag) == "java":
        raise SpecError(
            "%s is an old version 1 (.dgm) file. Open it in the Threat Modelling Tool "
            "and save it again to get a .dgx before editing it here." % path)
    if _local(root.tag) != "model":
        raise SpecError("%s is not a CORAS model file (root element is %r)"
                        % (path, _local(root.tag)))

    model = Model()
    by_xml_id = {}
    used_keys = {}

    def unique_key(base):
        base = slugify(base, fallback="element")
        if base not in used_keys:
            used_keys[base] = 1
            return base
        used_keys[base] += 1
        return "%s-%d" % (base, used_keys[base])

    model_elements = root.find(_Q + "modelElements")
    if model_elements is None:
        model_elements = []
    pending_relationships = []
    for child in model_elements:
        tag = _local(child.tag)
        xml_id = child.get("id")
        if tag in _MODEL_ELEMENT_TO_TYPE:
            node_type = _MODEL_ELEMENT_TO_TYPE[tag]
            name = child.get("name")
            kind = None
            if node_type == "threat":
                kind = _STEREOTYPE_TO_KIND.get(child.get("stereotype"), spec.DEFAULT_THREAT_KIND)
            key = unique_key(name or node_type)
            element = model.add_element(key, node_type, name, kind, xml_id=xml_id)
            by_xml_id[xml_id] = element
        elif tag in _MODEL_REL_TO_TYPE:
            consequence = None
            for grandchild in child:
                if _local(grandchild.tag) == "consequence":
                    consequence = (grandchild.text or "").strip() or None
            pending_relationships.append({
                "type": _MODEL_REL_TO_TYPE[tag],
                "id": xml_id,
                "source": child.get("source"),
                "target": child.get("target"),
                "strategy": child.get("strategy"),
                "label": consequence,
            })
        else:
            model.warnings.append("ignoring unknown model element <%s>" % tag)

    relationship_by_xml_id = {}
    for raw in pending_relationships:
        source = by_xml_id.get(raw["source"])
        target = by_xml_id.get(raw["target"])
        if source is None or target is None:
            model.warnings.append(
                "dropping a %s relationship whose endpoints are missing from the file"
                % raw["type"])
            continue
        relationship = model.add_relationship(
            source.key, target.key, raw["type"],
            label=raw["label"], strategy=raw["strategy"], xml_id=raw["id"])
        relationship.xml_id = raw["id"] or relationship.xml_id
        relationship_by_xml_id[raw["id"]] = relationship

    diagrams = root.find(_Q + "diagrams")
    for raw_diagram in (diagrams if diagrams is not None else []):
        if _local(raw_diagram.tag) != "diagram":
            continue
        diagram = model.add_diagram(raw_diagram.get("name") or "Diagram",
                                    xml_id=raw_diagram.get("id"))
        container = raw_diagram.find(_Q + "diagramElements")
        for child in (container if container is not None else []):
            tag = _local(child.tag)
            reference = child.get("modelElement")
            if tag in _DIAGRAM_NODE_TO_TYPE:
                element = by_xml_id.get(reference)
                if element is None:
                    model.warnings.append("diagram %r refers to a missing element"
                                          % diagram.name)
                    continue
                font = dict(DEFAULT_FONT)
                bounds = None
                color = YELLOW if element.type == "comment" else WHITE
                for grandchild in child:
                    name = _local(grandchild.tag)
                    if name == "font":
                        font = {
                            "name": grandchild.get("name", "SansSerif"),
                            "style": int(grandchild.get("style", 0) or 0),
                            "size": int(grandchild.get("size", 12) or 12),
                        }
                    elif name == "bounds":
                        bounds = tuple(float(grandchild.get(k, 0) or 0)
                                       for k in ("x", "y", "width", "height"))
                    elif name == "backgroundColor":
                        color = _color(grandchild, color)
                if bounds is None:
                    bounds = (0.0, 0.0) + spec.default_size(element.type)
                diagram.add_node(NodeView(
                    element, x=bounds[0], y=bounds[1], width=bounds[2], height=bounds[3],
                    color=color, font=font, pinned=True))
            elif tag in _DIAGRAM_EDGE_TO_TYPE:
                relationship = relationship_by_xml_id.get(reference)
                if relationship is None:
                    model.warnings.append("diagram %r refers to a missing relationship"
                                          % diagram.name)
                    continue
                path = []
                color = BLACK
                for grandchild in child:
                    name = _local(grandchild.tag)
                    if name == "path":
                        for point in grandchild:
                            if _local(point.tag) == "point":
                                path.append((float(point.get("x", 0) or 0),
                                             float(point.get("y", 0) or 0)))
                    elif name == "lineColor":
                        color = _color(grandchild, BLACK)
                diagram.edges.append(EdgeView(relationship, path, color))
            else:
                model.warnings.append("ignoring unknown diagram element <%s>" % tag)

    return model
