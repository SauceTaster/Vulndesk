#!/usr/bin/env bash
set -ex -o pipefail

if [[ -z "${START_COMMAND}" ]]; then
    # pm2-runtime keeps the process in the foreground (container-friendly) and
    # is the single, consistent process manager for Vulndesk (see package.json
    # stop/restart). Override with START_COMMAND for custom setups.
    pm2-runtime start app.js --name vulndesk
else
    /bin/bash -c "${START_COMMAND}"
fi
