#!/usr/bin/env bash
# MYTHOS status line — reads Claude Code statusLine JSON on stdin, prints one status line.
# Shared by both accounts (referenced by absolute path from each settings.json).
python3 -c '
import json, sys, os
try:
    d = json.load(sys.stdin)
except Exception:
    d = {}
m = d.get("model") or {}
model = m.get("display_name") or m.get("id") or "?"
ws = d.get("workspace") or {}
cwd = ws.get("current_dir") or d.get("cwd") or os.getcwd()
base = os.path.basename(cwd.rstrip("/")) or cwd
print("⚙️ MYTHOS · " + str(model) + " · " + base +
      " · GROUND→PROBE→ANALYZE→PERSIST→VALIDATE · probes>theory")
'
