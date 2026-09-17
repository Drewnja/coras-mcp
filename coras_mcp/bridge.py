"""Talking to the Threat Modelling Tool itself (validate, render, open).

Everything here shells out to a small Java helper compiled against the
editor's own jars, so validation and rendering use the editor's real loader and
renderer rather than a second implementation that could drift from it.

Java is optional: writing and reading .dgx files works without it.
"""

import glob
import json
import os
import shutil
import subprocess
import sys
import threading

PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(PACKAGE_DIR)              # .../coras-mcp
BRIDGE_JAR = os.path.join(PROJECT_DIR, "java", "build", "coras-mcp-bridge.jar")
BUILD_SCRIPT = os.path.join(PROJECT_DIR, "java", "build.sh")

#: JAXB 2.0.3 (bundled with the 2007 editor) generates accessor classes at run
#: time, which the module system blocks from Java 9 onwards.  This property
#: makes it fall back to plain reflection -- without it the editor itself
#: cannot open or save a file on a modern JRE.
JAXB_FLAG = "-Dcom.sun.xml.bind.v2.bytecode.ClassTailor.noOptimize=true"


class BridgeError(RuntimeError):
    """Raised when the Java side is unavailable or fails."""


# --------------------------------------------------------------------------
# Locating things
# --------------------------------------------------------------------------

#: Remembers where the Threat Modelling Tool lives, for when the server is not
#: sitting next to it. Written by `python3 -m coras_mcp --set-tool-dir <path>`.
CONFIG_FILE = os.path.join(
    os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"),
    "coras-mcp", "tool-dir")


def _is_tool_dir(path):
    return bool(glob.glob(os.path.join(path, "diagram-editor-*.jar"))) and \
        os.path.isdir(os.path.join(path, "lib"))


def remembered_tool_dir():
    """The path saved with --set-tool-dir, if there is one and it still exists."""
    try:
        with open(CONFIG_FILE, encoding="utf-8") as handle:
            path = handle.read().strip()
    except (OSError, IOError):
        return None
    return path or None


def remember_tool_dir(path):
    """Save where the tool lives, so the server finds it from anywhere."""
    path = os.path.abspath(os.path.expanduser(str(path)))
    if not _is_tool_dir(path):
        raise BridgeError(
            "%s does not look like the Threat Modelling Tool: expected a "
            "diagram-editor-*.jar and a lib/ directory in it" % path)
    directory = os.path.dirname(CONFIG_FILE)
    if not os.path.isdir(directory):
        os.makedirs(directory)
    with open(CONFIG_FILE, "w", encoding="utf-8") as handle:
        handle.write(path + "\n")
    return path


def find_tool_dir(explicit=None):
    """The directory holding diagram-editor-*.jar and lib/.

    Looked for, in order: the argument, CORAS_TOOL_DIR, the path saved with
    --set-tool-dir, the tool/ directory shipped inside this package, and then
    every directory from here upwards -- which is what finds it when the server
    is dropped inside an existing copy of the tool.
    """
    candidates = []
    if explicit:
        candidates.append(explicit)
    if os.environ.get("CORAS_TOOL_DIR"):
        candidates.append(os.environ["CORAS_TOOL_DIR"])
    saved = remembered_tool_dir()
    if saved:
        candidates.append(saved)
    # The copy shipped with this package, when there is one.
    candidates.append(os.path.join(PROJECT_DIR, "tool"))
    candidates.append(PROJECT_DIR)
    walk = os.path.dirname(PROJECT_DIR)
    for _ in range(4):
        candidates.append(walk)
        parent = os.path.dirname(walk)
        if parent == walk:
            break
        walk = parent

    tried = []
    for candidate in candidates:
        candidate = os.path.abspath(os.path.expanduser(candidate))
        if candidate in tried:
            continue
        tried.append(candidate)
        if _is_tool_dir(candidate):
            return candidate
    raise BridgeError(
        "cannot find the Threat Modelling Tool (a diagram-editor-*.jar with a lib/ "
        "directory next to it). Looked in: %s. Point at it with\n"
        "    python3 -m coras_mcp --set-tool-dir /path/to/the/folder\n"
        "or set CORAS_TOOL_DIR. Creating and reading .dgx files works without it; "
        "only validating, rendering and opening the editor need it."
        % ", ".join(tried))


def classpath(tool_dir):
    parts = [BRIDGE_JAR]
    parts.extend(sorted(glob.glob(os.path.join(tool_dir, "diagram-editor-*.jar"))))
    parts.extend(sorted(glob.glob(os.path.join(tool_dir, "lib", "*.jar"))))
    return os.pathsep.join(parts)


def find_java(binary="java"):
    from_env = os.environ.get("CORAS_JAVA")
    if from_env:
        path = from_env
        if os.path.isdir(path):
            path = os.path.join(path, "bin", binary)
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        candidate = os.path.join(java_home, "bin", binary)
        if os.path.isfile(candidate):
            return candidate
    found = shutil.which(binary)
    if found:
        return found
    if sys.platform == "darwin" and os.path.exists("/usr/libexec/java_home"):
        try:
            home = subprocess.check_output(["/usr/libexec/java_home"],
                                           stderr=subprocess.DEVNULL).decode().strip()
            candidate = os.path.join(home, "bin", binary)
            if os.path.isfile(candidate):
                return candidate
        except (subprocess.CalledProcessError, OSError):
            pass
    return None


def java_available():
    return find_java() is not None


_DISPLAY = {}


def display_available(tool_dir=None):
    """Can the editor's AWT code actually run here?

    The editor builds a java.awt.dnd.DropTarget while constructing a diagram,
    which needs a real display even when nothing is shown on screen. On a
    headless Linux box that fails, so validating, rendering and opening all
    need a display (or Xvfb).
    """
    if "value" in _DISPLAY:
        return _DISPLAY["value"]
    try:
        _DISPLAY["value"] = bool(info(tool_dir).get("display"))
    except (BridgeError, OSError):
        _DISPLAY["value"] = False
    return _DISPLAY["value"]


HEADLESS_HINT = (
    "the CORAS editor needs a display: it builds an AWT drag-and-drop target "
    "while loading a diagram, which fails without one. On a headless Linux "
    "machine install Xvfb and run under it, for example `xvfb-run -a ...`. "
    "Writing and reading .dgx files does not need a display."
)


# --------------------------------------------------------------------------
# Building the helper jar
# --------------------------------------------------------------------------

def ensure_bridge_jar(tool_dir=None, rebuild=False):
    if os.path.isfile(BRIDGE_JAR) and not rebuild:
        return BRIDGE_JAR
    tool_dir = tool_dir or find_tool_dir()
    javac = find_java("javac")
    if javac is None:
        raise BridgeError(
            "the Java helper (%s) has not been built and no javac was found. "
            "Install a JDK, or run %s by hand." % (BRIDGE_JAR, BUILD_SCRIPT))
    source = os.path.join(PROJECT_DIR, "java", "src", "coras", "mcp", "Bridge.java")
    classes = os.path.join(PROJECT_DIR, "java", "build", "classes")
    if os.path.isdir(classes):
        shutil.rmtree(classes)
    os.makedirs(classes)
    command = [javac, "-nowarn", "-encoding", "UTF-8",
               "-cp", classpath(tool_dir), "-d", classes, source]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        raise BridgeError("could not compile the Java helper:\n%s"
                          % (result.stderr or result.stdout).strip())
    jar = find_java("jar")
    if jar is None:
        raise BridgeError("javac was found but jar was not; cannot package the Java helper")
    result = subprocess.run([jar, "cf", BRIDGE_JAR, "-C", classes, "."],
                            capture_output=True, text=True)
    shutil.rmtree(classes, ignore_errors=True)
    if result.returncode != 0:
        raise BridgeError("could not package the Java helper:\n%s"
                          % (result.stderr or result.stdout).strip())
    return BRIDGE_JAR


# --------------------------------------------------------------------------
# Running commands
# --------------------------------------------------------------------------

def _base_command(tool_dir, gui=False):
    java = find_java()
    if java is None:
        raise BridgeError(
            "no Java runtime found. Install one (for example: brew install --cask temurin), "
            "or set CORAS_JAVA to a JDK/JRE. Creating and reading .dgx files works "
            "without Java; only validating, rendering and opening the editor need it.")
    command = [java, JAXB_FLAG, "-Djava.awt.headless=false"]
    if gui:
        command.append("-Xdock:name=Threat Modelling Tool")
    else:
        # Keep off-screen rendering out of the Dock and away from the user's focus.
        command.append("-Dapple.awt.UIElement=true")
    command.extend(["-cp", classpath(tool_dir), "coras.mcp.Bridge"])
    return command


def run(args, tool_dir=None, timeout=120, gui=False):
    """Run a bridge command and return its parsed JSON result."""
    tool_dir = tool_dir or find_tool_dir()
    ensure_bridge_jar(tool_dir)
    command = _base_command(tool_dir, gui=gui) + list(args)
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise BridgeError("the Java helper did not finish within %ss" % timeout)
    except OSError as error:
        raise BridgeError("could not start Java: %s" % error)
    payload = _first_json(result.stdout)
    if payload is None:
        detail = (result.stderr or result.stdout or "").strip()
        raise BridgeError("the Java helper produced no result%s"
                          % (":\n" + _explain(detail)[-2000:] if detail else ""))
    if not payload.get("ok", False):
        raise BridgeError(_explain(payload.get("error")
                                   or "the Java helper reported a failure"))
    return payload


def _explain(message):
    """Turn the JVM's X11 complaint into something actionable."""
    text = message or ""
    if "X11" in text or "HeadlessException" in text or "DISPLAY" in text:
        return text + "\n" + HEADLESS_HINT
    return text


def run_detached(args, tool_dir=None, timeout=45):
    """Start the editor GUI and leave it running; wait only for its first reply."""
    tool_dir = tool_dir or find_tool_dir()
    ensure_bridge_jar(tool_dir)
    command = _base_command(tool_dir, gui=True) + list(args)
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True,
                                   start_new_session=True)
    except OSError as error:
        raise BridgeError("could not start Java: %s" % error)

    captured = {}

    def reader():
        try:
            captured["line"] = process.stdout.readline()
        except Exception:                      # pragma: no cover - stream closed
            captured["line"] = ""

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()
    thread.join(timeout)
    line = captured.get("line") or ""
    payload = _first_json(line)
    if payload is None:
        if process.poll() is not None:
            stderr = ""
            try:
                stderr = process.stderr.read() or ""
            except Exception:                  # pragma: no cover
                pass
            raise BridgeError("the editor exited straight away%s"
                              % (":\n" + _explain(stderr.strip())[-2000:]
                                 if stderr.strip() else ""))
        return {"ok": True, "note": "the editor is starting"}
    if not payload.get("ok", False):
        raise BridgeError(payload.get("error") or "the editor reported a failure")
    payload["pid"] = process.pid
    return payload


def _first_json(text):
    for line in (text or "").splitlines():
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                return json.loads(line)
            except ValueError:
                continue
    return None


# --------------------------------------------------------------------------
# Convenience wrappers
# --------------------------------------------------------------------------

def validate(path, tool_dir=None):
    return run(["validate", os.path.abspath(path)], tool_dir=tool_dir)


def render(path, out, diagram=None, fmt="png", scale=2.0, tool_dir=None):
    args = ["render", os.path.abspath(path), "--out", os.path.abspath(out),
            "--format", fmt, "--scale", str(scale)]
    if diagram is not None:
        args.extend(["--diagram", str(diagram)])
    return run(args, tool_dir=tool_dir)


def open_editor(path=None, tool_dir=None):
    args = ["open"]
    if path:
        args.append(os.path.abspath(path))
    return run_detached(args, tool_dir=tool_dir)


def info(tool_dir=None):
    return run(["info"], tool_dir=tool_dir, timeout=60)
