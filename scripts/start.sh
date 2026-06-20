#!/usr/bin/env bash
set -ex -o pipefail

if [[ -z "${START_COMMAND}" ]]; then
    # pm2-runtime keeps the process in the foreground (container-friendly) and
    # is the single, consistent process manager for Vulndesk (see package.json
    # stop/restart). The app is TypeScript, run through tsx as the interpreter.
    # Override with START_COMMAND for custom setups.
    pm2-runtime start app.ts --name vulndesk --interpreter ./node_modules/.bin/tsx
else
    /bin/bash -c "${START_COMMAND}"
fi
