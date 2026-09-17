#!/usr/bin/env bash
# Builds coras-mcp-bridge.jar against the Threat Modelling Tool's own jars.
#
#   ./build.sh [path-to-tool-directory]
#
# The tool directory is the one holding diagram-editor-2.0-SNAPSHOT.jar and lib/.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
app_dir="${1:-${CORAS_TOOL_DIR:-$(cd "$here/.." && pwd)/tool}}"

editor_jar=""
for candidate in "$app_dir"/diagram-editor-*.jar; do
  [ -f "$candidate" ] && editor_jar="$candidate" && break
done
if [ -z "$editor_jar" ]; then
  echo "error: no diagram-editor-*.jar in $app_dir" >&2
  exit 1
fi
if [ ! -d "$app_dir/lib" ]; then
  echo "error: no lib/ directory in $app_dir" >&2
  exit 1
fi

cp="$editor_jar"
for jar in "$app_dir"/lib/*.jar; do
  cp="$cp:$jar"
done

out="$here/build"
rm -rf "$out"
mkdir -p "$out/classes"

javac_opts=(-nowarn -encoding UTF-8 -cp "$cp" -d "$out/classes")
# Target Java 8 so the bridge runs on every JRE that can run the tool itself.
if javac --release 8 -version >/dev/null 2>&1; then
  javac_opts=(--release 8 "${javac_opts[@]}")
fi

javac "${javac_opts[@]}" "$here/src/coras/mcp/Bridge.java"
jar cf "$out/coras-mcp-bridge.jar" -C "$out/classes" .
rm -rf "$out/classes"

echo "built $out/coras-mcp-bridge.jar"
