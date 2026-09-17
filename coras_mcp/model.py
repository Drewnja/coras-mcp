"""In-memory CORAS model: elements, relationships and the diagrams that show them.

The shape mirrors a .dgx file exactly.  A *model element* (an asset, a threat,
...) exists once; a *diagram* holds a view of it with its own position, size,
font and colour.  The same element can therefore appear in several diagrams,
which is how the editor itself works.
"""

import re
import uuid

from . import metrics, spec
from .spec import SpecError

DEFAULT_FONT = {"name": "SansSerif", "style": 0, "size": 12}
WHITE = (255, 255, 255)
BLACK = (0, 0, 0)
YELLOW = (255, 255, 0)


def new_xml_id():
    """An id in the same shape the editor writes (jug UUID with an 'I' prefix)."""
    return "I" + str(uuid.uuid4())


def slugify(text, fallback="element"):
    slug = re.sub(r"[^a-z0-9]+", "-", str(text).strip().lower()).strip("-")
    return slug or fallback


def parse_color(value, default=WHITE):
    """Accept '#rrggbb', 'rgb(r,g,b)', [r,g,b], 'white', ... -> (r, g, b)."""
    if value is None:
        return default
    if isinstance(value, (list, tuple)) and len(value) == 3:
        return tuple(max(0, min(255, int(round(float(c))))) for c in value)
    if isinstance(value, dict):
        return (
            max(0, min(255, int(value.get("red", 255)))),
            max(0, min(255, int(value.get("green", 255)))),
            max(0, min(255, int(value.get("blue", 255)))),
        )
    text = str(value).strip().lower()
    named = {
        "white": (255, 255, 255), "black": (0, 0, 0), "yellow": (255, 255, 0),
        "red": (255, 0, 0), "green": (0, 160, 0), "blue": (0, 0, 255),
        "orange": (255, 165, 0), "grey": (190, 190, 190), "gray": (190, 190, 190),
        "lightgrey": (225, 225, 225), "lightgray": (225, 225, 225),
        "pink": (255, 192, 203), "cyan": (0, 255, 255), "magenta": (255, 0, 255),
        "lightblue": (173, 216, 230), "lightgreen": (200, 240, 200),
        "lightyellow": (255, 255, 200),
    }
    if text in named:
        return named[text]
    match = re.match(r"^#?([0-9a-f]{6})$", text)
    if match:
        digits = match.group(1)
        return (int(digits[0:2], 16), int(digits[2:4], 16), int(digits[4:6], 16))
    match = re.match(r"^#?([0-9a-f]{3})$", text)
    if match:
        digits = match.group(1)
        return tuple(int(c * 2, 16) for c in digits)
    match = re.match(r"^rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)", text)
    if match:
        return tuple(max(0, min(255, int(match.group(i)))) for i in (1, 2, 3))
    raise SpecError("cannot read colour %r; use #rrggbb, [r,g,b] or a colour name" % (value,))


def color_to_hex(rgb):
    return "#%02x%02x%02x" % tuple(rgb)


def parse_font(value):
    if value is None:
        return dict(DEFAULT_FONT)
    if isinstance(value, str):
        return {"name": value, "style": 0, "size": 12}
    font = dict(DEFAULT_FONT)
    if isinstance(value, dict):
        if value.get("name"):
            font["name"] = str(value["name"])
        if value.get("size"):
            font["size"] = int(value["size"])
        style = value.get("style", 0)
        if isinstance(style, str):
            style_map = {"plain": 0, "bold": 1, "italic": 2, "bolditalic": 3, "bold-italic": 3}
            font["style"] = style_map.get(style.strip().lower(), 0)
        else:
            font["style"] = int(style)
    return font


class Element(object):
    """A model element: exists once, may be shown in many diagrams."""

    __slots__ = ("key", "type", "name", "threat_kind", "xml_id")

    def __init__(self, key, type_, name, threat_kind=None, xml_id=None):
        self.key = key
        self.type = type_
        self.name = name
        self.threat_kind = threat_kind
        self.xml_id = xml_id or new_xml_id()

    @property
    def stereotype(self):
        return spec.stereotype_of(self.type, self.threat_kind)

    def to_dict(self):
        data = {"id": self.key, "type": self.type, "name": self.name}
        if self.type == "threat":
            data["kind"] = self.threat_kind or spec.DEFAULT_THREAT_KIND
        return data


class Relationship(object):
    """A model relationship: source -> target with a CORAS relationship type."""

    __slots__ = ("key", "type", "source", "target", "label", "strategy", "xml_id")

    def __init__(self, key, type_, source, target, label=None, strategy=None, xml_id=None):
        self.key = key
        self.type = type_
        self.source = source
        self.target = target
        self.label = label
        self.strategy = strategy
        self.xml_id = xml_id or new_xml_id()

    def to_dict(self):
        data = {"from": self.source, "to": self.target, "type": self.type}
        if self.label:
            data["label"] = self.label
        if self.type == "treat":
            data["strategy"] = self.strategy or spec.DEFAULT_TREAT_STRATEGY
        return data


class NodeView(object):
    """How one element looks in one diagram."""

    __slots__ = ("element", "x", "y", "width", "height", "color", "font", "pinned", "contains")

    def __init__(self, element, x=None, y=None, width=None, height=None,
                 color=None, font=None, pinned=False, contains=None):
        self.element = element
        self.x = x
        self.y = y
        self.width = width
        self.height = height
        self.color = color if color is not None else (
            YELLOW if element.type == "comment" else WHITE)
        self.font = font or dict(DEFAULT_FONT)
        self.pinned = pinned
        self.contains = list(contains or ())

    @property
    def bounds(self):
        return (self.x, self.y, self.width, self.height)

    def to_dict(self):
        data = self.element.to_dict()
        if self.x is not None:
            data["x"] = round(self.x, 2)
            data["y"] = round(self.y, 2)
            data["width"] = round(self.width, 2)
            data["height"] = round(self.height, 2)
        if tuple(self.color) != (YELLOW if self.element.type == "comment" else WHITE):
            data["color"] = color_to_hex(self.color)
        if self.font != DEFAULT_FONT:
            data["font"] = dict(self.font)
        if self.contains:
            data["contains"] = list(self.contains)
        return data


class EdgeView(object):
    """How one relationship looks in one diagram."""

    __slots__ = ("relationship", "path", "color")

    def __init__(self, relationship, path=None, color=None):
        self.relationship = relationship
        self.path = list(path or ())
        self.color = color if color is not None else BLACK

    def to_dict(self):
        data = self.relationship.to_dict()
        if self.path:
            data["path"] = [[round(x, 2), round(y, 2)] for x, y in self.path]
        if tuple(self.color) != BLACK:
            data["color"] = color_to_hex(self.color)
        return data


class Diagram(object):
    def __init__(self, name, xml_id=None):
        self.name = name
        self.xml_id = xml_id or new_xml_id()
        self.nodes = []          # [NodeView]
        self.edges = []          # [EdgeView]
        self._by_key = {}

    def add_node(self, view):
        self.nodes.append(view)
        self._by_key[view.element.key] = view
        return view

    def node(self, key):
        return self._by_key.get(key)

    def has(self, key):
        return key in self._by_key

    def to_dict(self):
        return {
            "name": self.name,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
        }


class Model(object):
    def __init__(self):
        self.elements = {}         # key -> Element
        self.element_order = []    # [key]
        self.relationships = {}    # key -> Relationship
        self.relationship_order = []
        self.diagrams = []
        self.warnings = []

    # -- elements ---------------------------------------------------------

    def add_element(self, key, type_, name, threat_kind=None, xml_id=None):
        if key in self.elements:
            existing = self.elements[key]
            if existing.type != type_:
                raise SpecError(
                    "element %r is declared as both %s and %s"
                    % (key, existing.type, type_))
            if name and existing.name != name and name != key:
                existing.name = name
            if type_ == "threat" and threat_kind:
                existing.threat_kind = threat_kind
            return existing
        element = Element(key, type_, name, threat_kind, xml_id)
        self.elements[key] = element
        self.element_order.append(key)
        return element

    def element(self, key):
        return self.elements.get(key)

    def iter_elements(self):
        for key in self.element_order:
            yield self.elements[key]

    def iter_relationships(self):
        for key in self.relationship_order:
            yield self.relationships[key]

    # -- relationships ----------------------------------------------------

    def add_relationship(self, source_key, target_key, type_=None, label=None,
                         strategy=None, xml_id=None):
        source = self.elements.get(source_key)
        target = self.elements.get(target_key)
        if source is None:
            raise SpecError("relationship source %r is not a declared element" % (source_key,))
        if target is None:
            raise SpecError("relationship target %r is not a declared element" % (target_key,))
        if source_key == target_key:
            raise SpecError("element %r cannot point at itself" % (source_key,))

        if type_ is None:
            type_ = spec.infer_edge_type(source.type, target.type)
            if type_ is None:
                raise SpecError(
                    "%s -> %s is not allowed: %s"
                    % (source.name or source_key, target.name or target_key,
                       spec.explain_illegal_edge(source.type, target.type)))
        elif not spec.edge_allows(type_, source.type, target.type):
            raise SpecError(
                "a %s relationship cannot go from %s (%s) to %s (%s); %s"
                % (type_, source.name or source_key, source.type,
                   target.name or target_key, target.type,
                   spec.explain_illegal_edge(source.type, target.type)))

        if type_ == "treat":
            strategy = spec.normalise_strategy(strategy) if strategy else spec.DEFAULT_TREAT_STRATEGY
        else:
            strategy = None

        key = "%s|%s|%s" % (source_key, type_, target_key)
        existing = self.relationships.get(key)
        if existing is not None:
            if label and existing.label and label != existing.label:
                self.warnings.append(
                    "%s -> %s already has the label %r; keeping it and ignoring %r"
                    % (source_key, target_key, existing.label, label))
            elif label:
                existing.label = label
            if strategy and existing.strategy != strategy:
                existing.strategy = strategy
            return existing

        relationship = Relationship(key, type_, source_key, target_key, label, strategy, xml_id)
        self.relationships[key] = relationship
        self.relationship_order.append(key)
        return relationship

    # -- diagrams ---------------------------------------------------------

    def add_diagram(self, name, xml_id=None):
        diagram = Diagram(name, xml_id)
        self.diagrams.append(diagram)
        return diagram

    def diagram(self, name_or_index):
        if isinstance(name_or_index, int):
            if 0 <= name_or_index < len(self.diagrams):
                return self.diagrams[name_or_index]
            return None
        for diagram in self.diagrams:
            if diagram.name == name_or_index:
                return diagram
        return None

    def to_dict(self):
        used = set()
        for diagram in self.diagrams:
            for node in diagram.nodes:
                used.add(node.element.key)
        orphans = [self.elements[k].to_dict() for k in self.element_order if k not in used]
        data = {"diagrams": [d.to_dict() for d in self.diagrams]}
        if orphans:
            data["elements"] = orphans
        return data


# --------------------------------------------------------------------------
# Building a model from the JSON spec an MCP client sends
# --------------------------------------------------------------------------

_NODE_KEYS = {
    "id", "key", "type", "name", "label", "title", "kind", "threat_kind", "threatKind",
    "x", "y", "width", "height", "w", "h", "color", "colour", "background",
    "font", "contains", "pin", "pinned",
}
_EDGE_KEYS = {
    "from", "source", "src", "to", "target", "dst", "type", "kind", "relationship",
    "label", "text", "likelihood", "consequence", "strategy", "path", "waypoints",
    "color", "colour",
}


def _pick(data, *names, **kwargs):
    for name in names:
        if name in data and data[name] is not None:
            return data[name]
    return kwargs.get("default")


def _number(value, what):
    try:
        return float(value)
    except (TypeError, ValueError):
        raise SpecError("%s must be a number, got %r" % (what, value))


def build_model(data):
    """Turn the tool-call payload into a Model. Raises SpecError on bad input."""
    if not isinstance(data, dict):
        raise SpecError("the diagram spec must be an object")

    model = Model()
    diagrams_data = data.get("diagrams")
    if diagrams_data is None:
        # Allow the convenient single-diagram shape: {"name":..,"nodes":..,"edges":..}
        if "nodes" in data or "edges" in data:
            diagrams_data = [{
                "name": data.get("name") or data.get("title") or "Diagram",
                "nodes": data.get("nodes", []),
                "edges": data.get("edges", []),
            }]
        else:
            raise SpecError("the spec needs a 'diagrams' list (or 'nodes' and 'edges')")
    if isinstance(diagrams_data, dict):
        diagrams_data = [diagrams_data]
    if not isinstance(diagrams_data, list) or not diagrams_data:
        raise SpecError("'diagrams' must be a non-empty list")

    # Model-level elements that are not shown in any diagram.
    for raw in data.get("elements", []) or []:
        _element_from_dict(model, raw, {})

    alias = {}  # display name (lower) -> element key, so edges can use names
    for index, raw_diagram in enumerate(diagrams_data):
        if not isinstance(raw_diagram, dict):
            raise SpecError("diagram #%d must be an object" % (index + 1,))
        name = _pick(raw_diagram, "name", "title", default=None) or (
            "Diagram" if index == 0 else "Diagram %d" % (index + 1))
        diagram = model.add_diagram(str(name))

        raw_nodes = raw_diagram.get("nodes") or raw_diagram.get("elements") or []
        if not isinstance(raw_nodes, list):
            raise SpecError("diagram %r: 'nodes' must be a list" % (name,))
        for raw_node in raw_nodes:
            element, view = _node_from_dict(model, raw_node, alias)
            if diagram.has(element.key):
                model.warnings.append(
                    "diagram %r lists %r twice; keeping the first one" % (name, element.key))
                continue
            diagram.add_node(view)

        raw_edges = raw_diagram.get("edges") or raw_diagram.get("relationships") or []
        if not isinstance(raw_edges, list):
            raise SpecError("diagram %r: 'edges' must be a list" % (name,))
        for raw_edge in raw_edges:
            _edge_from_dict(model, diagram, raw_edge, alias)

    _check_containment(model)
    return model


def _resolve_key(model, alias, value, what):
    if value is None:
        raise SpecError("%s is missing" % what)
    key = str(value).strip()
    if key in model.elements:
        return key
    lowered = key.lower()
    if lowered in alias:
        return alias[lowered]
    slug = slugify(key)
    if slug in model.elements:
        return slug
    raise SpecError("%s refers to %r, which is not a declared element" % (what, value))


def _element_from_dict(model, raw, alias):
    if isinstance(raw, str):
        raw = {"type": "unwanted-incident", "name": raw}
    if not isinstance(raw, dict):
        raise SpecError("an element must be an object, got %r" % (raw,))

    unknown = set(raw) - _NODE_KEYS
    if unknown:
        raise SpecError(
            "unknown field(s) %s on element %r; allowed: %s"
            % (", ".join(sorted(unknown)), raw.get("name") or raw.get("id"),
               ", ".join(sorted(_NODE_KEYS))))

    raw_type = _pick(raw, "type")
    node_type = spec.normalise_node_type(raw_type)
    threat_kind = None
    if node_type == "threat":
        explicit = _pick(raw, "kind", "threat_kind", "threatKind")
        threat_kind = spec.normalise_threat_kind(
            explicit if explicit is not None else spec.threat_kind_from_type(raw_type))

    name = _pick(raw, "name", "label", "title")
    key = _pick(raw, "id", "key")
    if name is None and key is None:
        raise SpecError("an element needs at least a 'name'")
    if name is None:
        name = str(key)
    name = str(name)
    key = str(key) if key is not None else slugify(name, fallback=node_type)

    element = model.add_element(key, node_type, name, threat_kind)
    alias.setdefault(name.strip().lower(), key)
    alias.setdefault(key.strip().lower(), key)
    return element


def node_from_dict(model, raw, alias):
    """Public entry point used by the edit tool."""
    return _node_from_dict(model, raw, alias)


def _node_from_dict(model, raw, alias):
    element = _element_from_dict(model, raw if isinstance(raw, dict) else {"name": raw},
                                 alias)
    raw = raw if isinstance(raw, dict) else {}

    x = _pick(raw, "x")
    y = _pick(raw, "y")
    width = _pick(raw, "width", "w")
    height = _pick(raw, "height", "h")
    pinned = bool(_pick(raw, "pin", "pinned", default=False))
    if x is not None or y is not None:
        if x is None or y is None:
            raise SpecError("element %r has only one of x/y; give both or neither" % element.key)
        x = _number(x, "x")
        y = _number(y, "y")
        pinned = True
    view = NodeView(
        element,
        x=x, y=y,
        width=_number(width, "width") if width is not None else None,
        height=_number(height, "height") if height is not None else None,
        color=parse_color(_pick(raw, "color", "colour", "background"),
                          default=YELLOW if element.type == "comment" else WHITE),
        font=parse_font(_pick(raw, "font")),
        pinned=pinned,
        contains=_pick(raw, "contains", default=None),
    )
    if view.contains and element.type != "region":
        raise SpecError("'contains' only works on a region, not on %r" % element.key)
    return element, view


def _edge_from_dict(model, diagram, raw, alias):
    if isinstance(raw, str):
        raw = _edge_from_string(raw)
    if not isinstance(raw, dict):
        raise SpecError("a relationship must be an object or an 'a -> b' string")

    unknown = set(raw) - _EDGE_KEYS
    if unknown:
        raise SpecError(
            "unknown field(s) %s on a relationship; allowed: %s"
            % (", ".join(sorted(unknown)), ", ".join(sorted(_EDGE_KEYS))))

    source_key = _resolve_key(model, alias, _pick(raw, "from", "source", "src"),
                              "relationship 'from'")
    target_key = _resolve_key(model, alias, _pick(raw, "to", "target", "dst"),
                              "relationship 'to'")
    edge_type = spec.normalise_edge_type(_pick(raw, "type", "kind", "relationship"))
    label = _pick(raw, "label", "text", "likelihood", "consequence")
    strategy = _pick(raw, "strategy")

    for key in (source_key, target_key):
        if not diagram.has(key):
            element = model.elements[key]
            diagram.add_node(NodeView(element))
            model.warnings.append(
                "added %r to diagram %r because a relationship refers to it"
                % (element.name or key, diagram.name))

    relationship = model.add_relationship(
        source_key, target_key, edge_type,
        label=str(label) if label is not None else None,
        strategy=strategy)

    for existing in diagram.edges:
        if existing.relationship is relationship:
            return existing

    path = _pick(raw, "path", "waypoints")
    points = []
    for point in path or ():
        if isinstance(point, dict):
            points.append((_number(point.get("x"), "path x"), _number(point.get("y"), "path y")))
        elif isinstance(point, (list, tuple)) and len(point) == 2:
            points.append((_number(point[0], "path x"), _number(point[1], "path y")))
        else:
            raise SpecError("a path point must be [x, y] or {x:.., y:..}, got %r" % (point,))

    view = EdgeView(relationship, points, parse_color(_pick(raw, "color", "colour"), default=BLACK))
    diagram.edges.append(view)
    return view


_ARROW = re.compile(r"^(?P<a>.+?)\s*(?P<arrow>->|-->|<-|<--)\s*(?P<b>[^\"']+?)\s*(?:[\"'](?P<label>.*)[\"'])?\s*$")


def _edge_from_string(text):
    match = _ARROW.match(text.strip())
    if not match:
        raise SpecError("cannot read %r as a relationship; write it as 'a -> b'" % text)
    a, b = match.group("a").strip(), match.group("b").strip()
    if match.group("arrow").startswith("<"):
        a, b = b, a
    data = {"from": a.strip("\"'"), "to": b.strip("\"'")}
    if match.group("label"):
        data["label"] = match.group("label")
    return data


def _check_containment(model):
    for diagram in model.diagrams:
        for node in diagram.nodes:
            if not node.contains:
                continue
            resolved = []
            for ref in node.contains:
                key = str(ref)
                if key not in model.elements:
                    key = slugify(key)
                if key not in model.elements:
                    raise SpecError(
                        "region %r contains %r, which is not a declared element"
                        % (node.element.key, ref))
                if not diagram.has(key):
                    raise SpecError(
                        "region %r contains %r, which is not in diagram %r"
                        % (node.element.key, ref, diagram.name))
                resolved.append(key)
            node.contains = resolved


# --------------------------------------------------------------------------
# Sizing
# --------------------------------------------------------------------------

def _fit_wrapped(text, min_width, max_width, size, bold, aspect):
    """Pick a label width, and report the lines the renderer will actually draw.

    Swing wraps an <html> label at the width of the label, which for these cells
    is the width of the cell itself, so the lines have to be measured at the
    width we are about to choose -- not at some other trial width.
    """
    best = None
    width = float(min_width)
    while width <= max_width:
        lines = metrics.wrap(text, width, size, bold)
        height = len(lines) * metrics.line_height(size)
        widest = max((metrics.text_width(line, size, bold) for line in lines), default=0.0)
        if widest / float(max(height, 1)) >= aspect:
            return width, lines
        best = (width, lines)
        width += 10.0
    if best is None:
        best = (float(max_width), metrics.wrap(text, max_width, size, bold))
    return best


def preferred_size(node_view):
    """Cell size that fits the label the way the editor renders it.

    The editor draws labels as centred HTML inside the cell (an ellipse, a box)
    or underneath it (the icon shapes), so the numbers differ per shape.
    """
    element = node_view.element
    shape = spec.shape_of(element.type)
    font_size = node_view.font.get("size", 12)
    bold = bool(node_view.font.get("style", 0) & 1)
    line_h = metrics.line_height(font_size)
    text = element.name or ""

    if shape == "icon":
        # The icon keeps its fixed size; the label floats underneath it.
        return spec.default_size(element.type)

    if shape == "ellipse":
        # An oval is narrower than its bounding box away from the middle, and
        # Swing would wrap the text at the full cell width, so the cell is made
        # wide enough for the longest line it will draw.  Explicit newlines in
        # the name are hard breaks and are never re-joined.
        lines = text.split("\n")
        widest = max((metrics.text_width(line, font_size, bold) for line in lines),
                     default=0.0)
        cell_w = max(120.0, round(widest * 1.30 + 22))
        # Two extra lines come from the <br> padding, 10px from the picture strip.
        cell_h = max(60.0, (len(lines) + 2) * line_h + (16 if len(lines) > 1 else 10))
        return (float(cell_w), float(cell_h))

    if shape == "box":
        # Unwanted incident: rectangle with a 25px picture in the top right.
        width, lines = _fit_wrapped(text, 110, 230, font_size, bold, aspect=3.0)
        cell_w = max(120.0, round(width + 30))
        cell_h = max(60.0, (len(lines) + 2) * line_h + 10)
        return (float(cell_w), float(cell_h))

    if shape == "plain":
        # Comment: plain rectangle, label fills it.
        width, lines = _fit_wrapped(text, 100, 200, font_size, bold, aspect=2.6)
        cell_w = max(100.0, round(width + 16))
        cell_h = max(44.0, (len(lines) + 2) * line_h)
        return (float(cell_w), float(cell_h))

    # region
    return spec.default_size(element.type)


def label_block(node_view):
    """(width, height) of the label drawn under an icon shape."""
    element = node_view.element
    font_size = node_view.font.get("size", 12)
    bold = bool(node_view.font.get("style", 0) & 1)
    line_h = metrics.line_height(font_size)
    lines = str(element.name or "").split("\n")
    width = max((metrics.text_width(line, font_size, bold) for line in lines), default=0.0)
    # IconGraphCellView pads the label by 20px and adds the two <br> lines.
    return width + 20.0, (len(lines) + 2) * line_h


def footprint(node_view):
    """The rectangle a node really occupies on screen, labels included.

    Returns (left_overhang, top, width, height) relative to the cell's own
    x/y, so the layout can keep labels from colliding.
    """
    element = node_view.element
    shape = spec.shape_of(element.type)
    width = node_view.width or preferred_size(node_view)[0]
    height = node_view.height or preferred_size(node_view)[1]
    if shape != "icon":
        return (0.0, 0.0, width, height)
    label_w, label_h = label_block(node_view)
    total_w = max(width, label_w)
    overhang = max((label_w - width) / 2.0, 0.0)
    return (overhang, 0.0, total_w, height + label_h)
