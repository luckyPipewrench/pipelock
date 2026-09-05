# Using Pipelock with Pi

Pi reads its global `httpProxy` setting from `~/.pi/agent/settings.json` and sets `HTTP_PROXY` and `HTTPS_PROXY`. Pipelock uses a dedicated named listener, so traffic through that listener receives the `pi` agent profile without relying on a header or a shared default identity. See Pi's [proxy setting documentation](https://github.com/earendil-works/pi/blob/v0.85.1/packages/coding-agent/docs/settings.md).

This setup covers requests that honor the proxy setting. Tools and subprocesses that ignore proxy environment variables need separate network containment.

## Configure the Pipelock listener

Named agent listeners require Pipelock Pro. Add a listener for Pi to the Pipelock configuration before running the installer:

```yaml
forward_proxy:
  enabled: true

agents:
  pi:
    listeners:
      - "127.0.0.1:18889"
```

Start or restart Pipelock with that configuration. Listener changes require a restart because Pipelock binds those sockets at startup.

`pipelock pi install` compares the settings with this configuration file. It can't prove that Pipelock has an active Pro license or that the listener bound successfully. Confirm the Pi listener in Pipelock's startup output before starting Pi.

## Install

Preview the settings change first. The proxy URL must match the listener in the named profile.

```bash
pipelock pi install --config "$PWD/pipelock.yaml" --profile pi \
  --proxy http://127.0.0.1:18889 --dry-run

pipelock pi install --config "$PWD/pipelock.yaml" --profile pi \
  --proxy http://127.0.0.1:18889
```

Restart Pi after the install. The command updates only the global `httpProxy` member and retains Pi's other settings. It uses `PI_CODING_AGENT_DIR` when set, so an overridden Pi configuration directory receives the change.

## Remove

The installer records the prior `httpProxy` value beside Pi's settings. Remove restores that value while preserving other changes made after installation:

```bash
pipelock pi remove --dry-run
pipelock pi remove
```

Re-running install recovers a prepared install only when Pi's proxy still matches the recorded target or prior value. The command refuses to overwrite a changed proxy value or an interrupted removal. Inspect the settings and state file before resolving another interrupted condition by hand.
