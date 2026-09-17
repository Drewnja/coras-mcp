"""The CORAS language as the Threat Modelling Tool implements it.

Everything in this module was read off the editor's own classes
(``coras.profile.model.*``, ``com.vikash.firsttool.ProfileImpl.ToolModel``),
so the rules here are exactly the rules the editor enforces when it loads a
file.  Breaking them does not produce an ugly diagram, it produces a file the
editor refuses to open, which is why generation validates against them.
"""

NAMESPACE = "http://coras.sourceforge.net/profile/1.0"
PREFIX = "cp"

# --------------------------------------------------------------------------
# Node types
# --------------------------------------------------------------------------
# shape:
#   icon    - picture with the label underneath (label can be wider than the cell)
#   ellipse - oval with the label inside and a small picture on top
#   box     - rectangle with the label inside and a picture in the top right
#   plain   - rectangle, label inside (comment)
#   region  - rectangle drawn behind everything, label in the top left corner
#
# rank is the column a node wants to sit in, left to right: the canonical
# reading order of a CORAS risk diagram
#     stakeholder -> threat -> vulnerability -> threat scenario
#                 -> unwanted incident -> risk -> asset

NODE_TYPES = {
    "stakeholder": {
        "model_element": "stakeholder",
        "diagram_node": "stakeholderNode",
        "stereotype": "Stakeholder",
        "shape": "icon",
        "size": (50.0, 50.0),
        "rank": 0,
        "aliases": ("stakeholders", "party", "owner"),
        "doc": "Someone with an interest in an asset (a person or an organisation).",
    },
    "threat": {
        "model_element": "threat",
        "diagram_node": "threatNode",
        "stereotype": None,  # comes from the threat kind
        "shape": "icon",
        "size": (50.0, 50.0),
        "rank": 1,
        "aliases": ("threat-agent", "threatagent", "agent", "actor", "attacker"),
        "doc": "A threat agent: deliberate human, accidental human or non-human.",
    },
    "vulnerability": {
        "model_element": "vulnerability",
        "diagram_node": "vulnerabilityNode",
        "stereotype": "Vulnerability",
        "shape": "icon",
        "size": (30.0, 30.0),
        "rank": 2,
        "aliases": ("vuln", "weakness"),
        "doc": "A weakness that a threat can exploit. Drawn as a small open padlock.",
    },
    "threat-scenario": {
        "model_element": "threatScenario",
        "diagram_node": "threatScenarioNode",
        "stereotype": "ThreatScenario",
        "shape": "ellipse",
        "size": (120.0, 60.0),
        "rank": 3,
        "aliases": ("scenario", "threatscenario", "threat_scenario", "ts"),
        "doc": "A chain of events caused by a threat, which may lead to an incident.",
    },
    "unwanted-incident": {
        "model_element": "unwantedIncident",
        "diagram_node": "unwantedIncidentNode",
        "stereotype": "UnwantedIncident",
        "shape": "box",
        "size": (120.0, 60.0),
        "rank": 4,
        "aliases": ("incident", "unwantedincident", "unwanted_incident", "ui"),
        "doc": "The event that actually harms an asset.",
    },
    "risk": {
        "model_element": "risk",
        "diagram_node": "riskNode",
        "stereotype": "Risk",
        "shape": "icon",
        "size": (50.0, 50.0),
        "rank": 5,
        "aliases": ("risks",),
        "doc": "An incident together with its likelihood and consequence; used in risk diagrams.",
    },
    "asset": {
        "model_element": "asset",
        "diagram_node": "assetNode",
        "stereotype": "Asset",
        "shape": "icon",
        "size": (35.0, 35.0),
        "rank": 6,
        "aliases": ("assets", "value"),
        "doc": "Something of value that must be protected.",
    },
    "treatment": {
        "model_element": "treatment",
        "diagram_node": "treatmentNode",
        "stereotype": "Treatment",
        "shape": "ellipse",
        "size": (120.0, 60.0),
        "rank": None,  # placed just left of whatever it treats
        "aliases": ("control", "mitigation", "countermeasure", "measure"),
        "doc": "A countermeasure. Points at what it treats with a dashed arrow.",
    },
    "region": {
        "model_element": "region",
        "diagram_node": "regionNode",
        "stereotype": "Region",
        "shape": "region",
        "size": (240.0, 120.0),
        "rank": None,
        "aliases": ("zone", "boundary", "group", "area"),
        "doc": "A labelled rectangle drawn behind the other elements, to group them.",
    },
    "comment": {
        "model_element": "comment",
        "diagram_node": "commentNode",
        "stereotype": "Comment",
        "shape": "plain",
        "size": (120.0, 60.0),
        "rank": None,
        "aliases": ("note", "annotation"),
        "doc": "A yellow sticky note. May be attached to any other element.",
    },
}

#: Types that are part of the left-to-right flow of a diagram.
FLOW_TYPES = tuple(k for k, v in NODE_TYPES.items() if v["shape"] != "region" and k != "comment")

_TYPE_ALIASES = {}
for _key, _info in NODE_TYPES.items():
    _TYPE_ALIASES[_key] = _key
    _TYPE_ALIASES[_key.replace("-", "")] = _key
    _TYPE_ALIASES[_key.replace("-", "_")] = _key
    for _alias in _info["aliases"]:
        _TYPE_ALIASES[_alias] = _key
del _key, _info, _alias

# --------------------------------------------------------------------------
# Threat kinds
# --------------------------------------------------------------------------

THREAT_KINDS = {
    "deliberate": "ThreatHumanDeliberate",
    "accidental": "ThreatHumanAccidental",
    "non-human": "ThreatNonHuman",
}

_THREAT_KIND_ALIASES = {
    "deliberate": "deliberate",
    "human-deliberate": "deliberate",
    "humandeliberate": "deliberate",
    "threathumandeliberate": "deliberate",
    "malicious": "deliberate",
    "attacker": "deliberate",
    "accidental": "accidental",
    "human-accidental": "accidental",
    "humanaccidental": "accidental",
    "threathumanaccidental": "accidental",
    "mistake": "accidental",
    "non-human": "non-human",
    "nonhuman": "non-human",
    "non_human": "non-human",
    "threatnonhuman": "non-human",
    "system": "non-human",
    "technical": "non-human",
    "malware": "non-human",
}

DEFAULT_THREAT_KIND = "deliberate"

# --------------------------------------------------------------------------
# Relationship types
# --------------------------------------------------------------------------
# Each entry: the legal (source type, target type) pairs, taken from the
# acceptSourceTarget() methods in coras.profile.model.*.

EDGE_TYPES = {
    "dependency": {
        "model_element": "dependencyRelationship",
        "diagram_edge": "dependencyEdge",
        "sources": ("asset",),
        "targets": ("asset",),
        "doc": "One asset depends on another. Solid arrow.",
    },
    "ownership": {
        "model_element": "ownershipRelationship",
        "diagram_edge": "ownershipEdge",
        "sources": ("stakeholder",),
        "targets": ("asset",),
        "doc": "A stakeholder owns an asset. Plain line, no arrow head.",
    },
    "exploit": {
        "model_element": "exploitRelationship",
        "diagram_edge": "exploitEdge",
        "sources": ("threat", "vulnerability", "threat-scenario"),
        "targets": ("vulnerability",),
        "doc": "Something exploits a vulnerability. Solid arrow.",
    },
    "initiate": {
        "model_element": "initiateRelationship",
        "diagram_edge": "initiateEdge",
        "sources": ("threat", "vulnerability", "threat-scenario", "unwanted-incident"),
        "targets": ("vulnerability", "threat-scenario", "unwanted-incident", "risk"),
        "doc": "One element leads to another. Solid arrow; the label is the likelihood.",
        # The editor is pickier than a plain source x target product:
        "pairs": {
            "threat": ("vulnerability", "threat-scenario", "risk"),
            "vulnerability": ("vulnerability", "threat-scenario", "unwanted-incident"),
            "threat-scenario": ("vulnerability", "threat-scenario", "unwanted-incident"),
            "unwanted-incident": ("unwanted-incident", "threat-scenario", "risk"),
        },
    },
    "harm": {
        "model_element": "harmRelationship",
        "diagram_edge": "harmEdge",
        "sources": ("unwanted-incident", "risk"),
        "targets": ("asset",),
        "doc": "An incident or risk harms an asset. The label is the consequence.",
    },
    "treat": {
        "model_element": "treatRelationship",
        "diagram_edge": "treatEdge",
        "sources": ("treatment",),
        "targets": ("threat", "vulnerability", "threat-scenario", "unwanted-incident"),
        "doc": "A treatment addresses a threat, vulnerability, scenario or incident. Dashed arrow.",
    },
    "comment": {
        "model_element": "commentRelationship",
        "diagram_edge": "commentEdge",
        "sources": ("comment",),
        "targets": tuple(k for k in NODE_TYPES if k != "comment"),
        "doc": "Attaches a note to an element. Dashed line, no arrow head.",
    },
}

#: The order the editor itself tries relationship types in when it has to work
#: out what an arrow between two elements means (ToolModel.getStereotype).
EDGE_INFERENCE_ORDER = ("dependency", "ownership", "exploit", "initiate", "harm", "treat", "comment")

_EDGE_ALIASES = {
    "depends": "dependency",
    "depends-on": "dependency",
    "dependson": "dependency",
    "owns": "ownership",
    "own": "ownership",
    "exploits": "exploit",
    "initiates": "initiate",
    "leads-to": "initiate",
    "leadsto": "initiate",
    "causes": "initiate",
    "harms": "harm",
    "impacts": "harm",
    "treats": "treat",
    "mitigates": "treat",
    "notes": "comment",
    "note": "comment",
}
for _key in EDGE_TYPES:
    _EDGE_ALIASES[_key] = _key
del _key

#: Treatment strategies (ToolEdge.EdgeType). The editor only ever writes
#: these four for a treat arrow.
TREAT_STRATEGIES = ("ReduceLikelihood", "ReduceConsequence", "Avoid", "Transfer")
DEFAULT_TREAT_STRATEGY = "ReduceLikelihood"

_STRATEGY_ALIASES = {}
for _s in TREAT_STRATEGIES:
    _STRATEGY_ALIASES[_s.lower()] = _s
_STRATEGY_ALIASES.update({
    "reduce-likelihood": "ReduceLikelihood",
    "reduce_likelihood": "ReduceLikelihood",
    "likelihood": "ReduceLikelihood",
    "reduce-consequence": "ReduceConsequence",
    "reduce_consequence": "ReduceConsequence",
    "consequence": "ReduceConsequence",
    "avoid": "Avoid",
    "transfer": "Transfer",
})
del _s


class SpecError(ValueError):
    """Raised for anything the editor would refuse to load."""


def normalise_node_type(value):
    """Map any reasonable spelling of a node type onto its canonical key."""
    if value is None:
        raise SpecError("node type is missing")
    key = str(value).strip().lower().replace(" ", "-")
    if key in _TYPE_ALIASES:
        return _TYPE_ALIASES[key]
    # "threat-deliberate", "threat:non-human", ...
    for sep in ("-", ":", "/"):
        if sep in key:
            head, _, tail = key.partition(sep)
            if _TYPE_ALIASES.get(head) == "threat" and tail in _THREAT_KIND_ALIASES:
                return "threat"
    raise SpecError(
        "unknown element type %r; known types: %s"
        % (value, ", ".join(sorted(NODE_TYPES)))
    )


def threat_kind_from_type(value):
    """Pull a threat kind out of a compound type such as 'threat-non-human'."""
    key = str(value).strip().lower().replace(" ", "-")
    if key in _THREAT_KIND_ALIASES and _TYPE_ALIASES.get(key) != "threat":
        return _THREAT_KIND_ALIASES[key]
    for sep in ("-", ":", "/"):
        if sep in key:
            head, _, tail = key.partition(sep)
            if _TYPE_ALIASES.get(head) == "threat" and tail in _THREAT_KIND_ALIASES:
                return _THREAT_KIND_ALIASES[tail]
    return None


def normalise_threat_kind(value):
    if value is None:
        return DEFAULT_THREAT_KIND
    key = str(value).strip().lower().replace(" ", "-")
    if key in _THREAT_KIND_ALIASES:
        return _THREAT_KIND_ALIASES[key]
    raise SpecError(
        "unknown threat kind %r; use one of: %s" % (value, ", ".join(THREAT_KINDS))
    )


def normalise_edge_type(value):
    if value is None:
        return None
    key = str(value).strip().lower().replace(" ", "-")
    if key in ("auto", ""):
        return None
    if key in _EDGE_ALIASES:
        return _EDGE_ALIASES[key]
    raise SpecError(
        "unknown relationship type %r; known types: %s"
        % (value, ", ".join(sorted(EDGE_TYPES)))
    )


def normalise_strategy(value):
    if value is None:
        return None
    key = str(value).strip().lower().replace(" ", "")
    key = key.replace("-", "").replace("_", "")
    for candidate in TREAT_STRATEGIES:
        if candidate.lower() == key:
            return candidate
    key2 = str(value).strip().lower()
    if key2 in _STRATEGY_ALIASES:
        return _STRATEGY_ALIASES[key2]
    raise SpecError(
        "unknown treatment strategy %r; use one of: %s"
        % (value, ", ".join(TREAT_STRATEGIES))
    )


def edge_allows(edge_type, source_type, target_type):
    """Does the editor accept this relationship between these two elements?"""
    info = EDGE_TYPES[edge_type]
    pairs = info.get("pairs")
    if pairs is not None:
        return target_type in pairs.get(source_type, ())
    return source_type in info["sources"] and target_type in info["targets"]


def infer_edge_type(source_type, target_type):
    """Work out what an arrow between two elements means.

    Uses the same order of tests as ToolModel.getStereotype, so an inferred
    relationship is the one the editor would have created had you drawn the
    arrow by hand.  Returns None if no relationship is legal.
    """
    for edge_type in EDGE_INFERENCE_ORDER:
        if edge_allows(edge_type, source_type, target_type):
            return edge_type
    return None


def explain_illegal_edge(source_type, target_type):
    """A short, actionable message for an arrow the editor would reject."""
    options = []
    for edge_type in EDGE_INFERENCE_ORDER:
        info = EDGE_TYPES[edge_type]
        pairs = info.get("pairs")
        if pairs is not None:
            allowed = pairs.get(source_type, ())
        else:
            allowed = info["targets"] if source_type in info["sources"] else ()
        for target in allowed:
            options.append(target)
    if options:
        unique = []
        for target in options:
            if target not in unique:
                unique.append(target)
        article = "an" if source_type[0] in "aeiou" else "a"
        return (
            "%s cannot point at %s in CORAS; from %s %s you can only draw an arrow to: %s"
            % (source_type, target_type, article, source_type, ", ".join(unique))
        )
    return (
        "%s cannot be the source of a relationship in CORAS; only a stakeholder, "
        "threat, vulnerability, threat scenario, unwanted incident, risk, asset, "
        "treatment or comment can" % (source_type,)
    )


def default_size(node_type):
    return NODE_TYPES[node_type]["size"]


def shape_of(node_type):
    return NODE_TYPES[node_type]["shape"]


def stereotype_of(node_type, threat_kind=None):
    if node_type == "threat":
        return THREAT_KINDS[normalise_threat_kind(threat_kind)]
    return NODE_TYPES[node_type]["stereotype"]


def reference():
    """A machine readable summary of the language, for the MCP schema tool."""
    nodes = {}
    for key, info in NODE_TYPES.items():
        entry = {
            "shape": info["shape"],
            "default_size": list(info["size"]),
            "description": info["doc"],
            "aliases": list(info["aliases"]),
        }
        if key == "threat":
            entry["kinds"] = list(THREAT_KINDS)
            entry["default_kind"] = DEFAULT_THREAT_KIND
        nodes[key] = entry
    edges = {}
    for key, info in EDGE_TYPES.items():
        entry = {"description": info["doc"]}
        pairs = info.get("pairs")
        if pairs is not None:
            entry["allowed"] = {k: list(v) for k, v in pairs.items()}
        else:
            entry["allowed"] = {s: list(info["targets"]) for s in info["sources"]}
        if key == "treat":
            entry["strategies"] = list(TREAT_STRATEGIES)
            entry["default_strategy"] = DEFAULT_TREAT_STRATEGY
        edges[key] = entry
    return {
        "file_format": ".dgx (CORAS profile XML, namespace %s)" % NAMESPACE,
        "elements": nodes,
        "relationships": edges,
        "relationship_inference_order": list(EDGE_INFERENCE_ORDER),
        "canonical_left_to_right_order": [
            "stakeholder", "threat", "vulnerability", "threat-scenario",
            "unwanted-incident", "risk", "asset",
        ],
    }
