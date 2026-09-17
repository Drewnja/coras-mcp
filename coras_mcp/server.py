"""A dependency-free MCP server, speaking JSON-RPC 2.0 over stdio.

Written against the MCP stdio transport directly so the server runs on a bare
Python 3.8+ with nothing to install: no virtualenv, no pip, no network.  Only
JSON-RPC messages are ever written to stdout; everything else goes to stderr.
"""

import json
import os
import sys
import traceback

from . import bridge, tools
from .bridge import BridgeError
from .spec import SpecError

SERVER_NAME = "coras-threat-modelling"
SERVER_VERSION = tools.VERSION
SUPPORTED_PROTOCOLS = ("2025-06-18", "2025-03-26", "2024-11-05")
DEFAULT_PROTOCOL = "2025-06-18"

INSTRUCTIONS = (
    "Draws CORAS risk and threat diagrams for the 2007 SINTEF Threat Modelling Tool "
    "(the CORAS diagram editor). Describe a diagram in words and coras_create_diagram "
    "turns it into a .dgx file that the tool opens natively, laid out the way a CORAS "
    "diagram is meant to read: stakeholders and threat agents on the left, then "
    "vulnerabilities, threat scenarios, unwanted incidents, risks, and the assets they "
    "harm on the right. Call coras_reference when unsure which arrows are legal - the "
    "editor rejects a file with an illegal relationship. coras_render_diagram shows "
    "what the tool will draw, and coras_open_editor opens the tool itself."
)

# JSON-RPC error codes
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


def log(message):
    sys.stderr.write("[coras-mcp] %s\n" % message)
    sys.stderr.flush()


class Server(object):
    def __init__(self, stdin=None, stdout=None):
        self.stdin = stdin or sys.stdin
        self.stdout = stdout or sys.stdout
        self.protocol = DEFAULT_PROTOCOL
        self.running = True

    # -- transport --------------------------------------------------------

    def send(self, message):
        self.stdout.write(json.dumps(message, ensure_ascii=False) + "\n")
        self.stdout.flush()

    def reply(self, request_id, result):
        self.send({"jsonrpc": "2.0", "id": request_id, "result": result})

    def error(self, request_id, code, message, data=None):
        payload = {"code": code, "message": message}
        if data is not None:
            payload["data"] = data
        self.send({"jsonrpc": "2.0", "id": request_id, "error": payload})

    def serve_forever(self):
        while self.running:
            try:
                line = self.stdin.readline()
            except KeyboardInterrupt:
                break
            except Exception as error:                      # pragma: no cover
                log("read failed: %s" % error)
                break
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except ValueError as error:
                self.error(None, PARSE_ERROR, "invalid JSON: %s" % error)
                continue
            try:
                self.dispatch(message)
            except Exception as error:                      # pragma: no cover
                log("unhandled error: %s\n%s" % (error, traceback.format_exc()))
                if isinstance(message, dict) and message.get("id") is not None:
                    self.error(message.get("id"), INTERNAL_ERROR, str(error))

    # -- dispatch ---------------------------------------------------------

    def dispatch(self, message):
        if isinstance(message, list):
            for item in message:
                self.dispatch(item)
            return
        if not isinstance(message, dict):
            self.error(None, INVALID_REQUEST, "a request must be an object")
            return

        method = message.get("method")
        request_id = message.get("id")
        params = message.get("params") or {}
        if method is None:
            return  # a response to something we sent; we never send requests
        if request_id is None:
            self.handle_notification(method, params)
            return

        if method == "initialize":
            self.reply(request_id, self.initialize(params))
        elif method == "ping":
            self.reply(request_id, {})
        elif method == "tools/list":
            self.reply(request_id, {"tools": tools.DESCRIPTORS})
        elif method == "tools/call":
            self.reply(request_id, self.call_tool(params))
        elif method in ("resources/list", "resources/templates/list"):
            self.reply(request_id, {"resources": [], "resourceTemplates": []})
        elif method == "prompts/list":
            self.reply(request_id, {"prompts": []})
        elif method == "completion/complete":
            self.reply(request_id, {"completion": {"values": [], "total": 0,
                                                   "hasMore": False}})
        elif method == "logging/setLevel":
            self.reply(request_id, {})
        elif method == "shutdown":
            self.reply(request_id, {})
            self.running = False
        else:
            self.error(request_id, METHOD_NOT_FOUND, "unknown method: %s" % method)

    def handle_notification(self, method, params):
        if method in ("notifications/initialized", "initialized"):
            return
        if method in ("notifications/cancelled", "cancelled", "$/cancelRequest"):
            return
        if method == "exit":
            self.running = False
            return
        log("ignoring notification %s" % method)

    def initialize(self, params):
        requested = params.get("protocolVersion")
        if isinstance(requested, str) and requested in SUPPORTED_PROTOCOLS:
            self.protocol = requested
        else:
            self.protocol = DEFAULT_PROTOCOL
        return {
            "protocolVersion": self.protocol,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            "instructions": INSTRUCTIONS,
        }

    # -- tools ------------------------------------------------------------

    def call_tool(self, params):
        name = params.get("name")
        arguments = params.get("arguments")
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, dict):
            return self.tool_failure("'arguments' must be an object")
        handler = tools.HANDLERS.get(name)
        if handler is None:
            return self.tool_failure(
                "unknown tool %r; this server provides: %s"
                % (name, ", ".join(sorted(tools.HANDLERS))))
        try:
            content = handler(arguments)
        except (tools.ToolError, SpecError, BridgeError) as error:
            return self.tool_failure(str(error))
        except Exception as error:                          # pragma: no cover
            log("tool %s failed: %s" % (name, traceback.format_exc()))
            return self.tool_failure("%s: %s" % (type(error).__name__, error))
        return {"content": content, "isError": False}

    @staticmethod
    def tool_failure(message):
        return {"content": [{"type": "text", "text": message}], "isError": True}


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in ("--version", "-V"):
        print("%s %s" % (SERVER_NAME, SERVER_VERSION))
        return 0
    if argv and argv[0] in ("--help", "-h"):
        print(__doc__)
        print("Run without arguments to serve MCP over stdio.\n")
        print("  --where                 show where the Threat Modelling Tool was found")
        print("  --set-tool-dir <path>   remember where it lives, for good")
        print("  --version, --help")
        return 0
    if argv and argv[0] == "--set-tool-dir":
        if len(argv) < 2:
            print("usage: --set-tool-dir /path/to/the/folder/with/diagram-editor-*.jar",
                  file=sys.stderr)
            return 2
        try:
            saved = bridge.remember_tool_dir(argv[1])
        except BridgeError as error:
            print(str(error), file=sys.stderr)
            return 2
        print("Threat Modelling Tool: %s\nremembered in %s" % (saved, bridge.CONFIG_FILE))
        return 0
    if argv and argv[0] == "--where":
        try:
            found = bridge.find_tool_dir()
        except BridgeError as error:
            print(str(error), file=sys.stderr)
            return 2
        java = bridge.find_java()
        print("Threat Modelling Tool: %s" % found)
        print("Java:                  %s" % (java or "not found"))
        print("Java helper:           %s" % (
            bridge.BRIDGE_JAR if os.path.isfile(bridge.BRIDGE_JAR) else "not built yet"))
        remembered = bridge.remembered_tool_dir()
        print("Remembered path:       %s" % (remembered or "none (found by looking around)"))
        return 0
    try:
        sys.stdin.reconfigure(encoding="utf-8")
        sys.stdout.reconfigure(encoding="utf-8")
    except AttributeError:                                  # pragma: no cover - py<3.7
        pass
    Server().serve_forever()
    return 0


if __name__ == "__main__":                                  # pragma: no cover
    sys.exit(main())
