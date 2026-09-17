#!/usr/bin/env node
'use strict';

/*
 * npx entry point.
 *
 * The server itself is plain Python with no dependencies, so all this does is
 * find a usable interpreter and hand stdio straight over to it. MCP speaks
 * JSON-RPC over stdin/stdout, so the child must inherit both untouched.
 */

const { spawn, spawnSync } = require('child_process');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const PROBE = 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)';

/** Candidate interpreters, best first. Each is [command, leadingArgs]. */
function candidates() {
  const list = [];
  if (process.env.CORAS_PYTHON) {
    list.push([process.env.CORAS_PYTHON, []]);
  }
  if (process.platform === 'win32') {
    list.push(['py', ['-3']], ['python', []], ['python3', []]);
  } else {
    list.push(['python3', []], ['python', []]);
  }
  return list;
}

function usable(command, leading) {
  try {
    const result = spawnSync(command, leading.concat(['-c', PROBE]), {
      stdio: 'ignore',
      windowsHide: true,
    });
    return result.status === 0;
  } catch (error) {
    return false;
  }
}

function onPath(command) {
  try {
    const probe = process.platform === 'win32' ? 'where' : 'which';
    return spawnSync(probe, [command], { stdio: 'ignore', windowsHide: true }).status === 0;
  } catch (error) {
    return false;
  }
}

function chooseRunner() {
  for (const [command, leading] of candidates()) {
    if (usable(command, leading)) {
      return { command, args: leading.concat(['-m', 'coras_mcp']) };
    }
  }
  // No Python at all, but uv can fetch one on the spot.
  if (onPath('uv')) {
    return {
      command: 'uv',
      args: ['run', '--no-project', '--python', '3.12', 'python', '-m', 'coras_mcp'],
    };
  }
  return null;
}

function fail(message) {
  process.stderr.write('coras-mcp: ' + message + '\n');
  process.exit(1);
}

const runner = chooseRunner();
if (!runner) {
  fail(
    'no Python 3.8+ found.\n' +
      '  macOS:   xcode-select --install   (or: brew install python)\n' +
      '  Linux:   apt install python3      (or your package manager)\n' +
      '  Windows: https://python.org/downloads (tick "Add python.exe to PATH")\n' +
      '  Anywhere: install uv (https://docs.astral.sh/uv/) and this will use it.\n' +
      'Or set CORAS_PYTHON to an interpreter.'
  );
}

const child = spawn(runner.command, runner.args.concat(process.argv.slice(2)), {
  cwd: ROOT,
  stdio: 'inherit',
  windowsHide: true,
  env: Object.assign({}, process.env, {
    PYTHONPATH: ROOT + (process.env.PYTHONPATH ? path.delimiter + process.env.PYTHONPATH : ''),
    PYTHONUNBUFFERED: '1',
    PYTHONIOENCODING: 'utf-8',
  }),
});

child.on('error', (error) => fail('could not start ' + runner.command + ': ' + error.message));
child.on('exit', (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }
  process.exit(code === null ? 1 : code);
});

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => {
    if (!child.killed) child.kill(signal);
  });
}
