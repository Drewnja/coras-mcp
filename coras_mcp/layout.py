"""Automatic layout for CORAS diagrams.

A layered (Sugiyama style) layout with one CORAS-specific twist: every element
type has a preferred column, so a diagram reads in the canonical order

    stakeholder -> threat -> vulnerability -> threat scenario
                -> unwanted incident -> risk -> asset

even before the arrows are taken into account.  Empty columns are removed
afterwards, so an asset diagram of just stakeholders and assets ends up with
two tidy columns rather than seven.

Treatments are pulled one column to the left of whatever they treat, comments
are parked next to the element they annotate, and regions are sized to wrap
their contents.
"""

from . import metrics, spec
from .model import footprint, preferred_size

H_GAP = 90.0        # space between columns, enough for an arrow label
V_GAP = 38.0        # space between nodes inside a column
MARGIN = 30.0       # space around the whole diagram
GRID = 10.0         # the editor's snap grid
WAYPOINT = 12.0     # size reserved for an invisible arrow waypoint

#: The part of the language that makes a diagram a risk picture rather than an
#: asset picture.
RISK_FLOW_TYPES = ("threat", "vulnerability", "threat-scenario",
                   "unwanted-incident", "risk")


def _snap(value):
    return round(value / GRID) * GRID


#: A label longer than this (in pixels) gets broken over several lines rather
#: than stretching its shape across the page.  Ovals need it most: Swing wraps
#: an <html> label at the full cell width, but an oval is much narrower than
#: that near its top and bottom, so a long line would spill out of the shape.
WRAP_LIMIT = {"ellipse": 300.0, "icon": 190.0}
WRAP_TARGET = {"ellipse": 190.0, "icon": 130.0}


def prepare_labels(model, wrap_labels=True):
    """Break over-long names onto several lines, the way a user would by hand."""
    warnings = []
    if not wrap_labels:
        return warnings
    for element in model.iter_elements():
        shape = spec.shape_of(element.type)
        limit = WRAP_LIMIT.get(shape)
        name = element.name or ""
        if limit is None or not name or "\n" in name:
            continue
        width = metrics.text_width(name)
        if width <= limit:
            continue
        target = WRAP_TARGET[shape]
        count = max(2, int(width / target) + 1)
        lines = metrics.wrap(name, max(target, (width / count) * 1.18))
        if len(lines) < 2:
            continue
        element.name = "\n".join(lines)
        warnings.append("split the label %r over %d lines so it fits its shape"
                        % (name, len(lines)))
    return warnings


def layout_model(model, direction="right", mode="auto", wrap_labels=True):
    """Position every node of every diagram in *model*. Returns warnings."""
    warnings = prepare_labels(model, wrap_labels)
    for diagram in model.diagrams:
        warnings.extend(layout_diagram(model, diagram, direction=direction, mode=mode,
                                       wrap_labels=False))
    return warnings


def layout_diagram(model, diagram, direction="right", mode="auto", wrap_labels=True):
    warnings = prepare_labels(model, wrap_labels)
    direction = (direction or "right").lower()
    if direction in ("right", "horizontal", "lr", "left-to-right"):
        direction = "right"
    elif direction in ("down", "vertical", "tb", "top-to-bottom"):
        direction = "down"
    else:
        warnings.append("unknown layout direction %r, using 'right'" % direction)
        direction = "right"

    # ---- sizes ---------------------------------------------------------
    for node in diagram.nodes:
        if node.width is None or node.height is None:
            width, height = preferred_size(node)
            node.width = node.width if node.width is not None else width
            node.height = node.height if node.height is not None else height

    if mode == "preserve":
        placed = [n for n in diagram.nodes if n.x is not None]
        missing = [n for n in diagram.nodes if n.x is None]
        if missing:
            _place_loose(placed, missing)
        _size_regions(diagram)
        return warnings

    if mode == "manual":
        for node in diagram.nodes:
            if node.x is None:
                node.x, node.y = 0.0, 0.0
        _size_regions(diagram)
        return warnings

    # ---- split the diagram up ------------------------------------------
    flow, comments, regions, pinned = [], [], [], []
    for node in diagram.nodes:
        if node.pinned and node.x is not None:
            pinned.append(node)
        elif node.element.type == "region":
            regions.append(node)
        elif node.element.type == "comment":
            comments.append(node)
        else:
            flow.append(node)

    # In a pure asset diagram stakeholders belong in the flow, to the left of
    # what they own.  Once threats and incidents are in the picture the arrows
    # harming an asset come in from the left, so a stakeholder sitting there
    # gets crossed through: park it above its asset instead.
    stakeholders = []
    if any(node.element.type in RISK_FLOW_TYPES for node in flow):
        stakeholders = [n for n in flow if n.element.type == "stakeholder"]
        flow = [n for n in flow if n.element.type != "stakeholder"]

    if flow:
        _layer_and_place(model, diagram, flow, direction,
                         soft_dependency=bool(stakeholders) or any(
                             n.element.type in RISK_FLOW_TYPES for n in flow))
    elif not comments and not regions and not stakeholders:
        return warnings

    _place_stakeholders(model, diagram, stakeholders, flow + pinned)
    _place_comments(model, diagram, comments, flow + stakeholders + pinned)
    _place_regions(diagram, regions, flow + stakeholders + comments + pinned)

    if pinned:
        _avoid_pinned([n for n in diagram.nodes if n not in pinned], pinned)

    _normalise(diagram)
    return warnings


# --------------------------------------------------------------------------
# Layering
# --------------------------------------------------------------------------

def _flow_edges(model, diagram, nodes, soft_dependency=False):
    """Relationships between the given nodes, split into ranking and soft edges."""
    keys = set(n.element.key for n in nodes)
    soft_types = ["treat", "comment", "ownership"]
    if soft_dependency:
        # In a risk picture the assets belong together in the last column, with
        # the incidents fanning out to them; a dependency chain would otherwise
        # push them into several columns and drag the arrows across each other.
        soft_types.append("dependency")
    ranking, soft = [], []
    for view in diagram.edges:
        relationship = view.relationship
        if relationship.source not in keys or relationship.target not in keys:
            continue
        if relationship.type in soft_types:
            # These do not drive the left-to-right story: a treatment belongs
            # just left of what it treats and a stakeholder just left of the
            # asset it owns, rather than at the head of the whole chain.
            soft.append((relationship.source, relationship.target))
        else:
            ranking.append((relationship.source, relationship.target))
    return ranking, soft


def _break_cycles(nodes, edges):
    """Drop the back edges of a depth-first search so the rest is a DAG."""
    successors = {key: [] for key in nodes}
    for source, target in edges:
        successors[source].append(target)
    colour = {key: 0 for key in nodes}   # 0 white, 1 grey, 2 black
    kept = []
    dropped = set()

    for root in nodes:
        if colour[root]:
            continue
        stack = [(root, iter(successors[root]))]
        colour[root] = 1
        while stack:
            node, children = stack[-1]
            advanced = False
            for child in children:
                if colour[child] == 1:
                    dropped.add((node, child))
                    continue
                if colour[child] == 0:
                    colour[child] = 1
                    stack.append((child, iter(successors[child])))
                    advanced = True
                    break
            if not advanced:
                colour[node] = 2
                stack.pop()
    for edge in edges:
        if edge not in dropped:
            kept.append(edge)
    return kept


def _assign_layers(model, nodes, ranking_edges, soft_edges):
    keys = [n.element.key for n in nodes]
    by_key = {n.element.key: n for n in nodes}
    base = {}
    for key in keys:
        rank = spec.NODE_TYPES[by_key[key].element.type]["rank"]
        base[key] = 0 if rank is None else rank

    acyclic = _break_cycles(keys, ranking_edges)
    incoming = {key: [] for key in keys}
    outdegree = {key: 0 for key in keys}
    for source, target in acyclic:
        incoming[target].append(source)
        outdegree[source] += 1

    # Topological order (Kahn) over the acyclic edge set.
    indegree = {key: len(incoming[key]) for key in keys}
    queue = [key for key in keys if indegree[key] == 0]
    order = []
    successors = {key: [] for key in keys}
    for source, target in acyclic:
        successors[source].append(target)
    while queue:
        key = queue.pop(0)
        order.append(key)
        for target in successors[key]:
            indegree[target] -= 1
            if indegree[target] == 0:
                queue.append(target)
    for key in keys:                       # anything left over (shouldn't happen)
        if key not in order:
            order.append(key)

    layer = {}
    for key in order:
        value = base[key]
        for source in incoming[key]:
            if source in layer:
                value = max(value, layer[source] + 1)
        layer[key] = value

    # A treatment sits one column left of what it treats; a stakeholder one
    # column left of the asset it owns, so the ownership line stays short
    # instead of crossing the whole picture.
    pulled = {}
    for source, target in soft_edges:
        if by_key[source].element.type in ("treatment", "stakeholder"):
            pulled.setdefault(source, []).append(target)
    for key, targets in pulled.items():
        known = [layer[t] for t in targets if t in layer]
        if known:
            layer[key] = min(known) - 1
    for key in keys:
        if by_key[key].element.type == "treatment" and key not in pulled:
            layer[key] = 0

    # Compact: drop unused columns, then renumber from zero.
    used = sorted(set(layer.values()))
    remap = {value: index for index, value in enumerate(used)}
    return {key: remap[value] for key, value in layer.items()}


# --------------------------------------------------------------------------
# Ordering inside a layer
# --------------------------------------------------------------------------

def _count_crossings(layers, position, adjacency):
    crossings = 0
    for index in range(len(layers) - 1):
        pairs = []
        for key in layers[index]:
            for other in adjacency.get(key, ()):
                if other in position and other in set(layers[index + 1]):
                    pairs.append((position[key], position[other]))
        for i in range(len(pairs)):
            for j in range(i + 1, len(pairs)):
                a, b = pairs[i], pairs[j]
                if (a[0] - b[0]) * (a[1] - b[1]) < 0:
                    crossings += 1
    return crossings


def _order_layers(layers, down, up):
    """Median heuristic sweeps, keeping the best ordering found."""
    position = {}
    for layer in layers:
        for index, key in enumerate(layer):
            position[key] = index

    best = [list(layer) for layer in layers]
    best_score = _count_crossings(layers, position, down)

    current = [list(layer) for layer in layers]
    for iteration in range(8):
        if iteration % 2 == 0:
            sweep = range(1, len(current))
            neighbours, side = up, -1
        else:
            sweep = range(len(current) - 2, -1, -1)
            neighbours, side = down, 1
        for index in sweep:
            reference = current[index + side]
            reference_pos = {key: i for i, key in enumerate(reference)}
            keyed = []
            for order_index, key in enumerate(current[index]):
                values = sorted(reference_pos[n] for n in neighbours.get(key, ())
                                if n in reference_pos)
                if values:
                    middle = len(values) // 2
                    median = (values[middle] if len(values) % 2
                              else (values[middle - 1] + values[middle]) / 2.0)
                else:
                    median = order_index
                keyed.append((median, order_index, key))
            keyed.sort(key=lambda item: (item[0], item[1]))
            current[index] = [item[2] for item in keyed]

        position = {}
        for layer in current:
            for i, key in enumerate(layer):
                position[key] = i
        score = _count_crossings(current, position, down)
        if score < best_score:
            best_score = score
            best = [list(layer) for layer in current]
    return best


# --------------------------------------------------------------------------
# Coordinates
# --------------------------------------------------------------------------

def _layer_and_place(model, diagram, nodes, direction, soft_dependency=False):
    by_key = {n.element.key: n for n in nodes}
    ranking, soft = _flow_edges(model, diagram, nodes, soft_dependency)
    layer_of = _assign_layers(model, nodes, ranking, soft)

    # An arrow that skips a column gets an invisible waypoint in each column it
    # crosses.  The waypoints take part in the ordering and in the vertical
    # placement, which reserves a lane for the arrow instead of letting it cut
    # through whatever happens to sit in the way.
    extents = {}
    for node in nodes:
        overhang, _, fw, fh = footprint(node)
        extents[node.element.key] = ((fw, fh, overhang) if direction == "right"
                                     else (fh, fw, overhang))

    chains = {}
    segments = []
    for source, target in list(ranking) + list(soft):
        start_layer, end_layer = layer_of[source], layer_of[target]
        if start_layer == end_layer:
            continue
        step = 1 if end_layer > start_layer else -1
        previous = source
        chain = []
        for index in range(start_layer + step, end_layer, step):
            key = "\x00%d:%s>%s" % (index, source, target)
            layer_of[key] = index
            extents[key] = (WAYPOINT, WAYPOINT, 0.0)
            chain.append(key)
            segments.append((previous, key))
            previous = key
        segments.append((previous, target))
        if chain:
            chains[(source, target)] = chain

    count = max(layer_of.values()) + 1
    layers = [[] for _ in range(count)]
    for node in nodes:                       # declaration order inside a layer
        layers[layer_of[node.element.key]].append(node.element.key)
    for key in layer_of:
        if key.startswith("\x00"):
            layers[layer_of[key]].append(key)

    down, up = {}, {}
    for source, target in segments:
        a, b = ((source, target) if layer_of[source] < layer_of[target]
                else (target, source))
        down.setdefault(a, []).append(b)
        up.setdefault(b, []).append(a)

    layers = _order_layers(layers, down, up)

    # Position along the primary axis: one column (or row) per layer.
    # Rows need less room between them than columns, because a column has to
    # fit an arrow label between the shapes while a row does not.
    gap = H_GAP if direction == "right" else 55.0
    primary = {}
    offset = MARGIN
    for layer in layers:
        size = max([extents[key][0] for key in layer] or [0.0])
        for key in layer:
            primary[key] = offset + (size - extents[key][0]) / 2.0
        offset += size + gap

    # Position along the secondary axis: stack, then pull towards neighbours.
    secondary = {}
    for layer in layers:
        position = MARGIN
        for key in layer:
            secondary[key] = position
            position += extents[key][1] + V_GAP

    for iteration in range(10):
        sweep = range(1, len(layers)) if iteration % 2 == 0 else range(len(layers) - 2, -1, -1)
        neighbours = up if iteration % 2 == 0 else down
        for index in sweep:
            layer = layers[index]
            desired = {}
            for key in layer:
                centres = []
                for other in neighbours.get(key, ()):
                    if other in secondary:
                        centres.append(secondary[other] + extents[other][1] / 2.0)
                if centres:
                    desired[key] = sum(centres) / float(len(centres)) - extents[key][1] / 2.0
                else:
                    desired[key] = secondary[key]
            _pack(layer, desired, secondary, extents)

    # Centre every column on the middle of the diagram.
    span = {}
    for index, layer in enumerate(layers):
        if not layer:
            continue
        low = min(secondary[key] for key in layer)
        high = max(secondary[key] + extents[key][1] for key in layer)
        span[index] = (low, high)
    if span:
        middle = (min(v[0] for v in span.values()) + max(v[1] for v in span.values())) / 2.0
        for index, layer in enumerate(layers):
            if index not in span:
                continue
            low, high = span[index]
            shift = middle - (low + high) / 2.0
            for key in layer:
                secondary[key] += shift

    def point(key):
        centre_primary = primary[key] + extents[key][0] / 2.0
        centre_secondary = secondary[key] + extents[key][1] / 2.0
        if direction == "right":
            return (centre_primary, centre_secondary)
        return (centre_secondary, centre_primary)

    for node in nodes:
        key = node.element.key
        overhang = extents[key][2]
        if direction == "right":
            node.x = _snap(primary[key] + overhang)
            node.y = _snap(secondary[key])
        else:
            node.x = _snap(secondary[key] + overhang)
            node.y = _snap(primary[key])

    for view in diagram.edges:
        relationship = view.relationship
        chain = chains.get((relationship.source, relationship.target))
        if chain and not view.path:
            view.path = [point(key) for key in chain]


def _pack(layer, desired, secondary, extents):
    """Move nodes towards *desired* without breaking their order or overlapping.

    The order inside the layer is the crossing-minimal one worked out earlier,
    so it is never changed here: nodes are packed downwards against their
    wishes, then the whole column slides so that it sits centrally among the
    positions its neighbours would like it to have.
    """
    if not layer:
        return
    bottom = None
    for key in layer:
        want = desired[key]
        if bottom is not None and want < bottom:
            want = bottom
        secondary[key] = want
        bottom = want + extents[key][1] + V_GAP

    deltas = sorted(desired[key] - secondary[key] for key in layer)
    count = len(deltas)
    shift = (deltas[count // 2] if count % 2
             else (deltas[count // 2 - 1] + deltas[count // 2]) / 2.0)
    if abs(shift) > 0.5:
        for key in layer:
            secondary[key] += shift


# --------------------------------------------------------------------------
# Comments, regions, leftovers
# --------------------------------------------------------------------------

def _rect(node):
    overhang, _, fw, fh = footprint(node)
    return (node.x - overhang, node.y, fw, fh)


def _overlaps(a, b, pad=12.0):
    return not (a[0] + a[2] + pad <= b[0] or b[0] + b[2] + pad <= a[0] or
                a[1] + a[3] + pad <= b[1] or b[1] + b[3] + pad <= a[1])


def _place_stakeholders(model, diagram, stakeholders, others):
    """Park each stakeholder above the asset it owns."""
    if not stakeholders:
        return
    owned = {}
    for view in diagram.edges:
        relationship = view.relationship
        if relationship.type == "ownership":
            owned.setdefault(relationship.source, []).append(relationship.target)

    by_key = {n.element.key: n for n in diagram.nodes}
    placed = [_rect(n) for n in others if n.x is not None]
    spare_x = min([r[0] for r in placed] or [MARGIN])

    for node in stakeholders:
        anchors = [by_key[k] for k in owned.get(node.element.key, ())
                   if k in by_key and by_key[k].x is not None]
        overhang, _, width, height = footprint(node)
        if anchors:
            rects = [_rect(a) for a in anchors]
            centre = sum(r[0] + r[2] / 2.0 for r in rects) / float(len(rects))
            # Sit a little to the left of the assets, so the ownership lines fan
            # out instead of running straight down through the asset icons.
            x = centre - width / 2.0 - (70.0 if len(rects) > 1 else 0.0)
            y = min(r[1] for r in rects) - height - 45.0
        else:
            x, y = spare_x, MARGIN
            spare_x += width + H_GAP
        candidate = (x, y, width, height)
        guard = 0
        while any(_overlaps(candidate, other) for other in placed) and guard < 80:
            y -= 28.0
            candidate = (x, y, width, height)
            guard += 1
        node.x, node.y = _snap(candidate[0] + overhang), _snap(candidate[1])
        placed.append(_rect(node))


def _segment_hits(start, end, rect, pad=4.0):
    """Does the straight line from *start* to *end* cross *rect*?"""
    left, top = rect[0] - pad, rect[1] - pad
    right, bottom = rect[0] + rect[2] + pad, rect[1] + rect[3] + pad
    x0, y0 = start
    x1, y1 = end
    # Liang-Barsky clipping: the segment hits the box if any of it survives.
    dx, dy = x1 - x0, y1 - y0
    t0, t1 = 0.0, 1.0
    for p, q in ((-dx, x0 - left), (dx, right - x0), (-dy, y0 - top), (dy, bottom - y0)):
        if p == 0:
            if q < 0:
                return False
            continue
        t = q / p
        if p < 0:
            if t > t1:
                return False
            t0 = max(t0, t)
        else:
            if t < t0:
                return False
            t1 = min(t1, t)
    return t0 <= t1


def _park(node, anchor_rect, placed, obstacles):
    """Find a spot for a satellite box near *anchor_rect* with a clean sight line."""
    overhang, _, width, height = footprint(node)
    ax, ay = anchor_rect[0] + anchor_rect[2] / 2.0, anchor_rect[1] + anchor_rect[3] / 2.0
    offsets = [
        (anchor_rect[0] + anchor_rect[2] / 2.0 - width / 2.0,
         anchor_rect[1] + anchor_rect[3] + 45.0, 0.0, 30.0),      # below
        (anchor_rect[0] + anchor_rect[2] + 55.0,
         anchor_rect[1] + anchor_rect[3] / 2.0 - height / 2.0, 0.0, 30.0),   # right
        (anchor_rect[0] - width - 55.0,
         anchor_rect[1] + anchor_rect[3] / 2.0 - height / 2.0, 0.0, 30.0),   # left
        (anchor_rect[0] + anchor_rect[2] / 2.0 - width / 2.0,
         anchor_rect[1] - height - 45.0, 0.0, -30.0),             # above
    ]
    fallback = None
    for x, y, dx, dy in offsets:
        for step in range(12):
            candidate = (x + dx * step, y + dy * step, width, height)
            if any(_overlaps(candidate, other) for other in placed):
                continue
            centre = (candidate[0] + width / 2.0, candidate[1] + height / 2.0)
            if any(_segment_hits((ax, ay), centre, other) for other in obstacles):
                if fallback is None:
                    fallback = candidate
                continue
            return candidate
    return fallback or (offsets[0][0], offsets[0][1], width, height)


def _place_comments(model, diagram, comments, others):
    if not comments:
        return
    targets = {}
    for view in diagram.edges:
        relationship = view.relationship
        if relationship.type == "comment":
            targets.setdefault(relationship.source, []).append(relationship.target)

    placed = [_rect(n) for n in others if n.x is not None]
    by_key = {n.element.key: n for n in diagram.nodes}
    fallback_y = max([r[1] + r[3] for r in placed] or [MARGIN]) + 60.0
    fallback_x = MARGIN

    for comment in comments:
        anchors = [by_key[t] for t in targets.get(comment.element.key, ())
                   if t in by_key and by_key[t].x is not None]
        overhang, _, width, height = footprint(comment)
        if anchors:
            anchor_rect = _rect(anchors[0])
            obstacles = [r for r in placed if r != anchor_rect]
            spot = _park(comment, anchor_rect, placed, obstacles)
        else:
            spot = (fallback_x, fallback_y, width, height)
            fallback_x += width + 40.0
        comment.x, comment.y = _snap(spot[0] + overhang), _snap(spot[1])
        placed.append(_rect(comment))


def _place_regions(diagram, regions, others):
    if not regions:
        return
    by_key = {n.element.key: n for n in diagram.nodes}
    placed = [_rect(n) for n in others if n.x is not None]
    bottom = max([r[1] + r[3] for r in placed] or [MARGIN])
    loose_x = MARGIN

    for region in regions:
        members = [by_key[k] for k in region.contains if k in by_key and by_key[k].x is not None]
        if members:
            rects = [_rect(n) for n in members]
            left = min(r[0] for r in rects) - 22.0
            top = min(r[1] for r in rects) - 34.0
            right = max(r[0] + r[2] for r in rects) + 22.0
            low = max(r[1] + r[3] for r in rects) + 22.0
            region.x, region.y = _snap(left), _snap(top)
            region.width = _snap(right - left)
            region.height = _snap(low - top)
        else:
            region.x, region.y = _snap(loose_x), _snap(bottom + 60.0)
            loose_x += region.width + 40.0


def _place_loose(placed, missing):
    """Drop nodes that have no coordinates below whatever is already placed."""
    rects = [_rect(n) for n in placed if n.x is not None]
    y = max([r[1] + r[3] for r in rects] or [MARGIN]) + 60.0
    x = MARGIN
    row_height = 0.0
    for node in missing:
        node.x, node.y = _snap(x), _snap(y)
        _, _, fw, fh = footprint(node)
        x += fw + H_GAP
        row_height = max(row_height, fh)
        if x > 1200.0:
            x = MARGIN
            y += row_height + V_GAP
            row_height = 0.0


def _avoid_pinned(auto_nodes, pinned):
    """Shift the automatically placed block clear of hand-placed nodes."""
    auto = [n for n in auto_nodes if n.x is not None]
    if not auto or not pinned:
        return
    auto_rects = [_rect(n) for n in auto]
    pin_rects = [_rect(n) for n in pinned if n.x is not None]
    if not pin_rects:
        return
    if not any(_overlaps(a, p) for a in auto_rects for p in pin_rects):
        return
    shift = max(p[0] + p[2] for p in pin_rects) + H_GAP - min(a[0] for a in auto_rects)
    for node in auto:
        node.x += shift


def _size_regions(diagram):
    by_key = {n.element.key: n for n in diagram.nodes}
    for region in diagram.nodes:
        if region.element.type != "region" or not region.contains:
            continue
        members = [by_key[k] for k in region.contains if k in by_key and by_key[k].x is not None]
        if not members:
            continue
        rects = [_rect(n) for n in members]
        left = min(r[0] for r in rects) - 22.0
        top = min(r[1] for r in rects) - 34.0
        region.x, region.y = _snap(left), _snap(top)
        region.width = _snap(max(r[0] + r[2] for r in rects) + 22.0 - left)
        region.height = _snap(max(r[1] + r[3] for r in rects) + 22.0 - top)


def _normalise(diagram):
    """Slide the whole diagram so it starts at the top left margin."""
    rects = [_rect(n) for n in diagram.nodes if n.x is not None]
    if not rects:
        return
    dx = MARGIN - min(r[0] for r in rects)
    dy = MARGIN - min(r[1] for r in rects)
    if abs(dx) < 0.01 and abs(dy) < 0.01:
        return
    for node in diagram.nodes:
        if node.x is not None:
            node.x = _snap(node.x + dx)
            node.y = _snap(node.y + dy)
    for edge in diagram.edges:
        if edge.path:
            edge.path = [(x + dx, y + dy) for x, y in edge.path]
