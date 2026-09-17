"""Tests for the CORAS MCP server.

Run with:  python3 -m unittest discover -s tests   (from the coras-mcp folder)
or simply: python3 tests/test_coras_mcp.py

The tests that need the Threat Modelling Tool's own jars and a JRE are skipped
automatically when Java is not available.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from coras_mcp import bridge, dgx, dsl, layout, metrics, spec, tools  # noqa: E402
from coras_mcp.model import build_model, footprint, preferred_size    # noqa: E402
from coras_mcp.spec import SpecError                                  # noqa: E402

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SAMPLE = """
diagram "Sample"
stakeholder "The bank"            as bank
asset       "Customer data"       as data
threat      "Script kiddie"       as kiddie
vulnerability "Weak password"     as weakpw
scenario    "Password guessed"    as guess
incident    "Records leaked"      as leak
treatment   "Enforce 2FA"         as mfa
comment     "checked in September" as note
region      "Internet facing"     as zone contains=weakpw,guess

bank   -> data
kiddie -> weakpw
weakpw -> guess "often"
guess  -> leak  "likely"
leak   -> data  "major"
mfa    -> guess
note   -> leak
"""


def java_ready():
    if not bridge.java_available():
        return False
    try:
        bridge.find_tool_dir()
    except bridge.BridgeError:
        return False
    return True


needs_java = unittest.skipUnless(java_ready(), "no Java or no Threat Modelling Tool jars")


class TestMetrics(unittest.TestCase):
    def test_measured_widths_match_the_jvm(self):
        # Values measured with java.awt.FontMetrics for SansSerif 12.
        self.assertEqual(metrics.text_width("Customer data"), 85)
        self.assertEqual(metrics.text_width("Password guessed"), 107)
        self.assertEqual(metrics.text_width("Hacker"), 41)
        self.assertEqual(metrics.text_width("Утечка персональных данных"), 184)
        self.assertEqual(metrics.line_height(), 15)

    def test_wrap_respects_the_limit(self):
        lines = metrics.wrap("one two three four five six seven", 60)
        self.assertTrue(all(metrics.text_width(line) <= 60 for line in lines))
        self.assertGreater(len(lines), 1)

    def test_wrap_breaks_a_word_that_cannot_fit(self):
        lines = metrics.wrap("Supercalifragilisticexpialidocious", 40)
        self.assertGreater(len(lines), 1)
        self.assertTrue(all(metrics.text_width(line) <= 40 for line in lines))

    def test_wrap_keeps_explicit_newlines(self):
        self.assertEqual(metrics.wrap("a\nb", 500), ["a", "b"])


class TestSpecRules(unittest.TestCase):
    def test_type_aliases(self):
        for value, expected in (("incident", "unwanted-incident"), ("ui", "unwanted-incident"),
                                ("scenario", "threat-scenario"), ("vuln", "vulnerability"),
                                ("note", "comment"), ("threat-non-human", "threat"),
                                ("Asset", "asset")):
            self.assertEqual(spec.normalise_node_type(value), expected, value)

    def test_threat_kind_from_a_compound_type(self):
        self.assertEqual(spec.threat_kind_from_type("threat-non-human"), "non-human")
        self.assertEqual(spec.threat_kind_from_type("threat-accidental"), "accidental")
        self.assertIsNone(spec.threat_kind_from_type("threat"))

    def test_inference_matches_the_editor(self):
        self.assertEqual(spec.infer_edge_type("threat", "vulnerability"), "exploit")
        self.assertEqual(spec.infer_edge_type("threat", "threat-scenario"), "initiate")
        self.assertEqual(spec.infer_edge_type("unwanted-incident", "asset"), "harm")
        self.assertEqual(spec.infer_edge_type("stakeholder", "asset"), "ownership")
        self.assertEqual(spec.infer_edge_type("asset", "asset"), "dependency")
        self.assertEqual(spec.infer_edge_type("treatment", "threat-scenario"), "treat")
        self.assertEqual(spec.infer_edge_type("comment", "asset"), "comment")

    def test_illegal_pairs_are_rejected(self):
        for source, target in (("asset", "threat"), ("treatment", "risk"),
                               ("risk", "threat-scenario"), ("comment", "comment"),
                               ("threat", "unwanted-incident"), ("region", "asset")):
            self.assertIsNone(spec.infer_edge_type(source, target), "%s->%s" % (source, target))

    def test_partial_checks_the_editor_makes_while_loading(self):
        """Every legal pair must also pass the one-ended checks JAXB triggers."""
        for edge_type, info in spec.EDGE_TYPES.items():
            pairs = info.get("pairs")
            combos = ([(s, t) for s, targets in pairs.items() for t in targets] if pairs
                      else [(s, t) for s in info["sources"] for t in info["targets"]])
            for source, target in combos:
                self.assertTrue(spec.edge_allows(edge_type, source, target))
                if edge_type == "initiate":
                    # setTarget() runs before setSource() with source still null.
                    self.assertIn(target, ("vulnerability", "threat-scenario",
                                           "unwanted-incident", "risk"))
                    self.assertIn(source, ("threat", "vulnerability", "threat-scenario",
                                           "unwanted-incident"))


class TestDsl(unittest.TestCase):
    def test_round_trip(self):
        model = build_model(dsl.parse(SAMPLE))
        self.assertEqual(len(model.diagrams), 1)
        self.assertEqual(len(model.element_order), 9)
        self.assertEqual(len(model.relationship_order), 7)
        types = {r.type for r in model.iter_relationships()}
        self.assertEqual(types, {"ownership", "exploit", "initiate", "harm",
                                 "treat", "comment"})

    def test_comments_and_quotes(self):
        spec_data = dsl.parse('diagram "D"   # trailing comment\n'
                              'asset "A # not a comment" as a\n'
                              'asset "B" as b\n'
                              'a -> b "needs # care"\n')
        names = [n["name"] for n in spec_data["diagrams"][0]["nodes"]]
        self.assertEqual(names, ["A # not a comment", "B"])
        self.assertEqual(spec_data["diagrams"][0]["edges"][0]["label"], "needs # care")

    def test_reverse_arrow(self):
        spec_data = dsl.parse('diagram "D"\nasset "A" as a\nasset "B" as b\nb <- a\n')
        edge = spec_data["diagrams"][0]["edges"][0]
        self.assertEqual((edge["from"], edge["to"]), ("a", "b"))

    def test_bad_line_reports_its_number(self):
        with self.assertRaises(SpecError) as caught:
            dsl.parse('diagram "D"\nasset "A" as a\nwombat "B"\n')
        self.assertIn("line 3", str(caught.exception))

    def test_emitting_is_parsable_again(self):
        model = build_model(dsl.parse(SAMPLE))
        again = build_model(dsl.parse(dsl.to_dsl(model)))
        self.assertEqual(len(again.element_order), len(model.element_order))
        self.assertEqual(len(again.relationship_order), len(model.relationship_order))


class TestModel(unittest.TestCase):
    def test_unknown_field_is_reported(self):
        with self.assertRaises(SpecError) as caught:
            build_model({"diagrams": [{"nodes": [{"type": "asset", "name": "A",
                                                  "colour_": "red"}]}]})
        self.assertIn("unknown field", str(caught.exception))

    def test_edges_pull_missing_elements_into_the_diagram(self):
        model = build_model({
            "elements": [{"id": "a", "type": "asset", "name": "A"}],
            "diagrams": [{"name": "D",
                          "nodes": [{"id": "b", "type": "asset", "name": "B"}],
                          "edges": [{"from": "b", "to": "a"}]}],
        })
        self.assertTrue(model.diagrams[0].has("a"))
        self.assertTrue(any("because a relationship refers to it" in w
                            for w in model.warnings))

    def test_same_id_in_two_diagrams_is_one_element(self):
        model = build_model({"diagrams": [
            {"name": "One", "nodes": [{"id": "a", "type": "asset", "name": "A"}]},
            {"name": "Two", "nodes": [{"id": "a", "type": "asset", "name": "A"}]},
        ]})
        self.assertEqual(len(model.element_order), 1)
        self.assertIs(model.diagrams[0].nodes[0].element,
                      model.diagrams[1].nodes[0].element)

    def test_self_loop_rejected(self):
        with self.assertRaises(SpecError):
            build_model({"diagrams": [{"nodes": [{"id": "a", "type": "asset", "name": "A"}],
                                       "edges": [{"from": "a", "to": "a"}]}]})

    def test_colour_parsing(self):
        from coras_mcp.model import parse_color
        self.assertEqual(parse_color("#ff8800"), (255, 136, 0))
        self.assertEqual(parse_color("yellow"), (255, 255, 0))
        self.assertEqual(parse_color([1, 2, 3]), (1, 2, 3))
        with self.assertRaises(SpecError):
            parse_color("not a colour")

    def test_label_fits_inside_its_shape(self):
        """An oval must be wide enough that its single line stays inside it."""
        model = build_model({"diagrams": [{"nodes": [
            {"id": "s", "type": "scenario", "name": "Password guessed by brute force"},
        ]}]})
        node = model.diagrams[0].nodes[0]
        width, height = preferred_size(node)
        text = metrics.text_width(node.element.name)
        self.assertGreaterEqual(width, text * 1.25)
        self.assertEqual(len(metrics.wrap(node.element.name, width)), 1)


class TestLayout(unittest.TestCase):
    def build(self, text=SAMPLE, **kwargs):
        model = build_model(dsl.parse(text))
        layout.layout_model(model, **kwargs)
        return model

    def rects(self, diagram):
        out = []
        for node in diagram.nodes:
            if node.element.type == "region":
                continue
            overhang, _, width, height = footprint(node)
            out.append((node.element.key, node.x - overhang, node.y, width, height))
        return out

    def test_everything_is_placed(self):
        model = self.build()
        for node in model.diagrams[0].nodes:
            self.assertIsNotNone(node.x, node.element.key)
            self.assertIsNotNone(node.width, node.element.key)

    def test_nothing_overlaps(self):
        model = self.build()
        rects = self.rects(model.diagrams[0])
        for i in range(len(rects)):
            for j in range(i + 1, len(rects)):
                a, b = rects[i], rects[j]
                overlap = not (a[1] + a[3] <= b[1] or b[1] + b[3] <= a[1] or
                               a[2] + a[4] <= b[2] or b[2] + b[4] <= a[2])
                self.assertFalse(overlap, "%s overlaps %s" % (a[0], b[0]))

    def test_canonical_left_to_right_order(self):
        model = self.build()
        by_key = {n.element.key: n for n in model.diagrams[0].nodes}
        order = ["kiddie", "weakpw", "guess", "leak", "data"]
        xs = [by_key[key].x for key in order]
        self.assertEqual(xs, sorted(xs), "columns are not left to right: %s" % xs)

    def test_region_wraps_its_contents(self):
        model = self.build()
        by_key = {n.element.key: n for n in model.diagrams[0].nodes}
        region = by_key["zone"]
        for key in ("weakpw", "guess"):
            node = by_key[key]
            self.assertGreaterEqual(node.x, region.x)
            self.assertGreaterEqual(node.y, region.y)
            self.assertLessEqual(node.x + node.width, region.x + region.width)
            self.assertLessEqual(node.y + node.height, region.y + region.height)

    def test_long_arrow_gets_waypoints(self):
        model = self.build('diagram "D"\n'
                           'threat "T" as t\nrisk "R" as r\n'
                           'vulnerability "V" as v\nscenario "S" as s\n'
                           't -> r\nt -> v\nv -> s\n')
        for edge in model.diagrams[0].edges:
            if edge.relationship.target == "r":
                self.assertTrue(edge.path, "the long arrow t->r has no waypoints")

    def test_downward_layout(self):
        model = self.build(direction="down")
        by_key = {n.element.key: n for n in model.diagrams[0].nodes}
        ys = [by_key[k].y for k in ("kiddie", "weakpw", "guess", "leak", "data")]
        self.assertEqual(ys, sorted(ys))

    def test_pinned_positions_are_kept(self):
        model = build_model({"diagrams": [{"nodes": [
            {"id": "a", "type": "asset", "name": "A", "x": 500, "y": 400},
            {"id": "t", "type": "threat", "name": "T"},
        ]}]})
        layout.layout_model(model)
        by_key = {n.element.key: n for n in model.diagrams[0].nodes}
        self.assertEqual((by_key["a"].x, by_key["a"].y), (500, 400))

    def test_long_labels_are_split(self):
        model = self.build('diagram "D"\n'
                           'scenario "An attacker slowly exfiltrates the whole customer '
                           'database over several weeks" as s\n')
        self.assertIn("\n", model.diagrams[0].nodes[0].element.name)


class TestDgxFile(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="coras-test-")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def path(self, name="model.dgx"):
        return os.path.join(self.dir, name)

    def test_written_xml_matches_the_editor_shape(self):
        model = build_model(dsl.parse(SAMPLE))
        layout.layout_model(model)
        text = dgx.to_xml(model)
        self.assertIn('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>', text)
        self.assertIn('<cp:model xmlns:cp="http://coras.sourceforge.net/profile/1.0">', text)
        self.assertIn("<cp:modelElements>", text)
        self.assertIn("<cp:diagramElements>", text)
        self.assertIn('<cp:threat stereotype="ThreatHumanDeliberate"', text)
        self.assertIn("<consequence>often</consequence>", text)
        self.assertIn('<cp:treatRelationship strategy="ReduceLikelihood"', text)
        self.assertIn('<cp:font size="12" style="0" name="SansSerif"/>', text)

    def test_special_characters_survive(self):
        model = build_model({"diagrams": [{"name": 'Say "hi" & <goodbye>', "nodes": [
            {"id": "a", "type": "asset", "name": 'R&D "data" <secret>'},
            {"id": "b", "type": "asset", "name": "Данные клиентов"},
        ], "edges": [{"from": "a", "to": "b", "label": "<1% & rising"}]}]})
        layout.layout_model(model)
        path = dgx.write(model, self.path())
        again = dgx.read(path)
        names = [e.name for e in again.iter_elements()]
        self.assertIn('R&D "data" <secret>', names)
        self.assertIn("Данные клиентов", names)
        self.assertEqual(again.diagrams[0].name, 'Say "hi" & <goodbye>')
        self.assertEqual(list(again.iter_relationships())[0].label, "<1% & rising")

    def test_read_back_is_faithful(self):
        model = build_model(dsl.parse(SAMPLE))
        layout.layout_model(model)
        path = dgx.write(model, self.path())
        again = dgx.read(path)
        self.assertEqual(len(again.element_order), len(model.element_order))
        self.assertEqual(len(again.relationship_order), len(model.relationship_order))
        self.assertEqual(len(again.diagrams), len(model.diagrams))
        first = model.diagrams[0].nodes[0]
        copy = again.diagrams[0].nodes[0]
        self.assertEqual((copy.x, copy.y, copy.width, copy.height),
                         (first.x, first.y, first.width, first.height))
        self.assertEqual(copy.element.name, first.element.name)

    def test_writing_twice_is_stable(self):
        model = build_model(dsl.parse(SAMPLE))
        layout.layout_model(model)
        path = dgx.write(model, self.path())
        with open(path, encoding="utf-8") as handle:
            first = handle.read()
        second = dgx.to_xml(dgx.read(path))
        self.assertEqual(first, second)

    def test_reads_a_file_the_editor_itself_wrote(self):
        """The fixture came out of the editor's own DgmToProfileMapper."""
        fixture = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "fixtures", "editor-saved.dgx")
        model = dgx.read(fixture)
        self.assertEqual(model.warnings, [])
        self.assertEqual(len(model.element_order), 15)
        self.assertEqual(len(model.relationship_order), 17)
        self.assertEqual(len(model.diagrams), 1)
        kinds = {r.type for r in model.iter_relationships()}
        self.assertEqual(kinds, {"ownership", "dependency", "exploit", "initiate",
                                 "harm", "treat", "comment"})
        labels = [r.label for r in model.iter_relationships() if r.label]
        self.assertIn("likely", labels)
        node = model.diagrams[0].nodes[0]
        self.assertIsNotNone(node.x)
        self.assertGreater(node.width, 0)

    def test_old_dgm_file_is_explained(self):
        path = self.path("old.dgx")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write('<?xml version="1.0"?><java version="1.5.0"></java>')
        with self.assertRaises(SpecError) as caught:
            dgx.read(path)
        self.assertIn("version 1", str(caught.exception))

    def test_extension_is_added(self):
        model = build_model(dsl.parse(SAMPLE))
        layout.layout_model(model)
        path = dgx.write(model, os.path.join(self.dir, "noext"))
        self.assertTrue(path.endswith(".dgx"))


class TestToolDiscovery(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="coras-where-")
        self.saved_config = bridge.CONFIG_FILE
        bridge.CONFIG_FILE = os.path.join(self.dir, "tool-dir")
        self.saved_env = os.environ.pop("CORAS_TOOL_DIR", None)

    def tearDown(self):
        bridge.CONFIG_FILE = self.saved_config
        if self.saved_env is not None:
            os.environ["CORAS_TOOL_DIR"] = self.saved_env
        shutil.rmtree(self.dir, ignore_errors=True)

    def fake_tool_dir(self):
        path = os.path.join(self.dir, "app")
        os.makedirs(os.path.join(path, "lib"))
        open(os.path.join(path, "diagram-editor-2.0-SNAPSHOT.jar"), "w").close()
        return path

    def test_remembering_a_path(self):
        path = self.fake_tool_dir()
        bridge.remember_tool_dir(path)
        self.assertEqual(bridge.remembered_tool_dir(), path)
        self.assertEqual(bridge.find_tool_dir(), path)

    def test_a_wrong_path_is_refused(self):
        with self.assertRaises(bridge.BridgeError):
            bridge.remember_tool_dir(self.dir)

    def test_the_environment_wins(self):
        path = self.fake_tool_dir()
        os.environ["CORAS_TOOL_DIR"] = path
        try:
            self.assertEqual(bridge.find_tool_dir(), path)
        finally:
            del os.environ["CORAS_TOOL_DIR"]

    def test_missing_tool_explains_how_to_fix_it(self):
        found = None
        try:
            found = bridge.find_tool_dir()
        except bridge.BridgeError as error:
            self.assertIn("--set-tool-dir", str(error))
        if found is not None:
            # The tool really is next to us; that is the normal case.
            self.assertTrue(os.path.isdir(os.path.join(found, "lib")))


class TestTools(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="coras-tools-")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def path(self, name="m.dgx"):
        return os.path.join(self.dir, name)

    def text_of(self, content):
        return "\n".join(b["text"] for b in content if b["type"] == "text")

    def test_reference_lists_every_type(self):
        data = json.loads(tools.reference({})[0]["text"])
        self.assertEqual(set(data["elements"]), set(spec.NODE_TYPES))
        self.assertEqual(set(data["relationships"]), set(spec.EDGE_TYPES))

    def test_create_then_read_then_edit(self):
        path = self.path()
        content = tools.create_diagram({"path": path, "text": SAMPLE, "preview": False,
                                        "validate": False})
        self.assertTrue(os.path.isfile(path))
        self.assertIn("Wrote", self.text_of(content))

        content = tools.read_diagram({"path": path, "format": "json"})
        data = json.loads(self.text_of(content).split("Structured spec:\n", 1)[1])
        self.assertEqual(len(data["diagrams"][0]["nodes"]), 9)

        content = tools.edit_diagram({
            "path": path, "preview": False,
            "operations": [
                {"op": "add_node", "type": "risk", "name": "R1", "id": "r1"},
                {"op": "add_edge", "from": "Records leaked", "to": "r1"},
                {"op": "rename", "id": "The bank", "name": "The savings bank"},
                {"op": "set", "id": "r1", "color": "#ffdddd"},
            ]})
        self.assertIn("added risk", self.text_of(content))
        again = dgx.read(path)
        self.assertIn("The savings bank", [e.name for e in again.iter_elements()])
        self.assertTrue(os.path.isfile(path + ".bak"))

    def test_create_rejects_an_illegal_arrow(self):
        with self.assertRaises(SpecError):
            tools.create_diagram({"path": self.path(), "preview": False,
                                  "text": 'diagram "d"\nasset "A" as a\nthreat "T" as t\n'
                                          'a -> t\n'})

    def test_dry_run_writes_nothing(self):
        path = self.path()
        tools.create_diagram({"path": path, "text": SAMPLE, "dry_run": True})
        self.assertFalse(os.path.exists(path))

    def test_spec_or_text_but_not_both(self):
        with self.assertRaises(tools.ToolError):
            tools.create_diagram({"path": self.path(), "text": SAMPLE, "spec": {}})
        with self.assertRaises(tools.ToolError):
            tools.create_diagram({"path": self.path()})

    def test_relayout_operation(self):
        path = self.path()
        tools.create_diagram({"path": path, "text": SAMPLE, "preview": False,
                              "validate": False})
        before = dgx.read(path)
        moved = before.diagrams[0].nodes[0]
        moved.x, moved.y = 999.0, 999.0
        dgx.write(before, path)
        tools.edit_diagram({"path": path, "preview": False,
                            "operations": [{"op": "relayout"}]})
        after = dgx.read(path)
        self.assertNotEqual(after.diagrams[0].nodes[0].x, 999.0)


class TestMcpProtocol(unittest.TestCase):
    """Drive the real server over stdio, the way an MCP client would."""

    @classmethod
    def setUpClass(cls):
        cls.process = subprocess.Popen(
            [sys.executable, "-m", "coras_mcp"], cwd=PROJECT,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1)
        cls.counter = 0

    @classmethod
    def tearDownClass(cls):
        try:
            cls.process.stdin.close()
            cls.process.wait(timeout=5)
        except Exception:
            cls.process.kill()

    def rpc(self, method, params=None, notify=False):
        message = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        if not notify:
            TestMcpProtocol.counter += 1
            message["id"] = TestMcpProtocol.counter
        self.process.stdin.write(json.dumps(message) + "\n")
        self.process.stdin.flush()
        if notify:
            return None
        line = self.process.stdout.readline()
        self.assertTrue(line, "the server closed its output")
        return json.loads(line)

    def test_01_initialize(self):
        reply = self.rpc("initialize", {"protocolVersion": "2024-11-05",
                                        "capabilities": {},
                                        "clientInfo": {"name": "t", "version": "1"}})
        self.assertEqual(reply["result"]["protocolVersion"], "2024-11-05")
        self.assertIn("tools", reply["result"]["capabilities"])
        self.rpc("notifications/initialized", {}, notify=True)

    def test_02_tools_list(self):
        reply = self.rpc("tools/list")
        names = [t["name"] for t in reply["result"]["tools"]]
        self.assertIn("coras_create_diagram", names)
        for tool in reply["result"]["tools"]:
            self.assertIn("inputSchema", tool)
            self.assertEqual(tool["inputSchema"]["type"], "object")

    def test_03_call_tool(self):
        directory = tempfile.mkdtemp(prefix="coras-rpc-")
        try:
            reply = self.rpc("tools/call", {
                "name": "coras_create_diagram",
                "arguments": {"path": os.path.join(directory, "x.dgx"),
                              "text": SAMPLE, "preview": False, "validate": False}})
            self.assertFalse(reply["result"]["isError"])
            self.assertTrue(os.path.isfile(os.path.join(directory, "x.dgx")))
        finally:
            shutil.rmtree(directory, ignore_errors=True)

    def test_04_tool_failure_is_reported_not_raised(self):
        reply = self.rpc("tools/call", {"name": "coras_read_diagram",
                                        "arguments": {"path": "/nope/missing.dgx"}})
        self.assertTrue(reply["result"]["isError"])

    def test_05_unknown_method(self):
        reply = self.rpc("nonsense/method")
        self.assertEqual(reply["error"]["code"], -32601)

    def test_06_ping(self):
        self.assertEqual(self.rpc("ping")["result"], {})


@needs_java
class TestAgainstTheEditor(unittest.TestCase):
    """The real proof: the 2007 editor loads and draws what we generate."""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix="coras-java-")
        model = build_model(dsl.parse(SAMPLE))
        layout.layout_model(model)
        cls.path = dgx.write(model, os.path.join(cls.dir, "sample.dgx"))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir, ignore_errors=True)

    def test_editor_loads_the_file(self):
        result = bridge.validate(self.path)
        self.assertTrue(result["ok"])
        self.assertEqual(len(result["diagrams"]), 1)
        self.assertEqual(result["diagrams"][0]["nodes"], 9)
        self.assertEqual(result["diagrams"][0]["edges"], 7)

    def test_editor_renders_the_file(self):
        out = os.path.join(self.dir, "png")
        result = bridge.render(self.path, out, scale=1.0)
        for image in result["images"]:
            self.assertTrue(os.path.isfile(image["path"]))
            self.assertGreater(os.path.getsize(image["path"]), 1000)

    def test_every_legal_relationship_survives_a_round_trip(self):
        """Build one diagram holding every allowed pair and load it in the editor."""
        nodes, edges, seen = [], [], set()
        for edge_type, info in spec.EDGE_TYPES.items():
            pairs = info.get("pairs")
            combos = ([(s, t) for s, targets in pairs.items() for t in targets] if pairs
                      else [(s, t) for s in info["sources"] for t in info["targets"]])
            for source, target in combos:
                if source == "region" or target == "region":
                    continue
                for role, node_type in (("s", source), ("t", target)):
                    key = "%s-%s-%s-%s" % (edge_type, source, target, role)
                    nodes.append({"id": key, "type": node_type, "name": key})
                edges.append({"from": "%s-%s-%s-s" % (edge_type, source, target),
                              "to": "%s-%s-%s-t" % (edge_type, source, target)})
                seen.add((source, target))
        model = build_model({"diagrams": [{"name": "All", "nodes": nodes, "edges": edges}]})
        layout.layout_model(model)
        path = dgx.write(model, os.path.join(self.dir, "all.dgx"))
        result = bridge.validate(path)
        self.assertEqual(result["modelRelationships"], len(edges))
        self.assertGreater(len(seen), 20)


if __name__ == "__main__":
    unittest.main(verbosity=2)
