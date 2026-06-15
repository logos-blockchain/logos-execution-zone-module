# Running This Execution-Zone Module Against logoscore

`logos-execution-zone` is a Logos `core` module that wraps the
[Logos execution-zone wallet library](https://github.com/logos-blockchain/lssa)
(`wallet_ffi`) to provide wallet lifecycle, account management, balance and
block queries, transfers, pinata claiming, and account-id encoding. This
doc-test exercises **this** execution-zone-module commit end-to-end through the
headless `logoscore` runtime:

1. Build the `logoscore` CLI and the `lgpm` local package manager from their
   published flakes. `logoscore` is the headless frontend for `logos-liblogos`,
   so building it brings in the whole module-runtime stack (`logos_host`,
   `liblogos_core`, the IPC layer).
2. Build **this** execution-zone module as an installable `.lgx` package
   straight from its own flake's `#lgx` output, **pinned to the commit under
   test** — so the module you run is built from exactly what is checked out
   here, not the latest published release.
3. Install the `.lgx` into a `./modules` directory with `lgpm`.
4. Start `logoscore` in daemon mode (`-D`), load `logos_execution_zone`,
   introspect it with `module-info`, and call its wallet-free methods —
   verifying the module actually runs and round-trips real values through
   `wallet_ffi`.

The methods exercised here — `name`/`version` and the base58 account-id codec
(`account_id_to_base58` / `account_id_from_base58`) — are the module's
deterministic, **offline** surface: they need neither an open wallet nor a live
sequencer, so a green run is reproducible in CI. The stateful operations
(creating accounts, transfers, sync, pinata claims) require a running
sequencer and network, and are covered by the module's unit tests (mocked
`wallet_ffi`) and integration tests (real `wallet_ffi`) instead.

Because the module is built from the commit under test and then loaded and
called through a real `logoscore` daemon, a green run is real evidence that
this change keeps the execution-zone module loadable and callable.

**What you'll build:** This `logos_execution_zone` module, packaged as `.lgx`, installed with `lgpm`, and called through a `logoscore` daemon.

**What you'll learn:**

- How to build the `logoscore` runtime and the `lgpm` package manager from their flakes
- How a module's flake exposes a ready-to-install `.lgx` via its `#lgx` output
- How to install an `.lgx` into a modules directory with `lgpm`
- How to start the `logoscore` daemon, load a module, introspect it, and call its methods
- How to shut the daemon down and confirm it has exited

## Prerequisites

- **Nix** with flakes enabled. Install from [nixos.org](https://nixos.org/download.html), then enable flakes:

```bash
mkdir -p ~/.config/nix
echo 'experimental-features = nix-command flakes' >> ~/.config/nix/nix.conf
```

Verify: `nix flake --help >/dev/null 2>&1 && echo "Flakes enabled"`

- **A Linux or macOS machine.**

---

## Step 1: Build logoscore

Build the `logoscore` CLI from its published flake. The result is symlinked to
`./logos/`. `logoscore` is the headless frontend for `logos-liblogos`, so this
one build brings in the whole module-runtime stack the daemon needs.

### 1.1 Build the CLI

```bash
nix build 'github:logos-co/logos-logoscore-cli' --out-link ./logos
```

The build produces `logos/bin/logoscore` plus bundled runtime libraries
and a `logos/modules/` directory containing the built-in
`capability_module` (required for the auth handshake when loading
modules).

---

## Step 2: Build the lgpm package manager

`lgpm` installs `.lgx` packages into a modules directory and scans what is
installed. Build it from the `logos-package-manager` flake and link it as
`./lgpm`.

### 2.1 Build lgpm

```bash
nix build 'github:logos-co/logos-package-manager#cli' -o lgpm
```

The executable is at `./lgpm/bin/lgpm`.

---

## Step 3: Build and install this execution-zone module

Build **this** execution-zone module's `.lgx` straight from its flake's
`#lgx` output and install it into a local `./modules` directory with `lgpm`.
Every module built with
[`logos-module-builder`](https://github.com/logos-co/logos-module-builder)
exposes a ready-to-install `#lgx`.

> The `` in the URL is what pins the build to a specific commit: the
> doc-test runner expands it to a concrete ref. Locally that is this
> checkout's `HEAD` (see `run.sh`); in CI it is the commit being tested. With
> no pin it falls back to the latest `master`.

### 3.1 Build the module's .lgx

Build the `#lgx` output and link it as `./lez-lgx`. (This compiles the
module and the `wallet_ffi` library it depends on through Nix, so the
first build is slow.)

```bash
# From inside the clone this is simply: nix build '.#lgx'
nix build 'github:logos-co/logos-execution-zone-module#lgx' -o lez-lgx
```

The `.lgx` package is now under `./lez-lgx/`:

```bash
ls lez-lgx/*.lgx
```

### 3.2 Seed the modules directory with the bundled capability module

`logos_execution_zone` is loaded through the host's capability layer, so
the modules directory also needs the `capability_module` that ships with
`logoscore`. Copy it across first.

```bash
mkdir -p modules
cp -RL ./logos/modules/. ./modules/

```

### 3.3 Install the .lgx with lgpm

Install the freshly-built package into `./modules`. `logos_execution_zone`
is a `core` module, so it goes to `--modules-dir`. The package is unsigned
(a local dev build), so we pass `--allow-unsigned`.

```bash
./lgpm/bin/lgpm --modules-dir ./modules --allow-unsigned install --file lez-lgx/*.lgx
```

### 3.4 Confirm the install

Scan the directory and confirm the module landed:

```bash
./lgpm/bin/lgpm --modules-dir ./modules list
```

---

## Step 4: Run the daemon and call the module

Start `logoscore` in daemon mode pointed at `./modules`, then use the client
subcommands to load `logos_execution_zone`, introspect it, and call several
of its methods. Daemon output is captured in `logs.txt`.

### 4.1 Start the daemon

Start logoscore in daemon mode in the background, capturing output to
`logs.txt`:

```bash
logoscore -D -m ./modules > logs.txt &
```

The `-D` flag starts the daemon. The client subcommands below connect to
this running process via the config written under `~/.logoscore/`.

```bash
sleep 3
```

### 4.2 Inspect the startup log

Review the daemon's startup output:

```bash
cat logs.txt
```

### 4.3 Check daemon status

Verify the daemon is running:

```bash
logoscore status
```

### 4.4 List discovered modules

`logos_execution_zone` should be visible in the scan directory:

```bash
logoscore list-modules
```

### 4.5 Load the module

Load `logos_execution_zone` into the running daemon:

```bash
logoscore load-module logos_execution_zone
```

### 4.6 Confirm the module is loaded

Re-run `status`; the module that was `not_loaded` before now reports
`loaded`:

```bash
logoscore status
```

### 4.7 Introspect the module with module-info

`module-info` lists the methods the module exposes — the same methods you
can `call`:

```bash
logoscore module-info logos_execution_zone
```

### 4.8 Read the module name

`name` returns the module's own identifier — the simplest possible
round-trip through the loaded plugin over liblogos' IPC:

```bash
logoscore call logos_execution_zone name
```

### 4.9 Read the module version

`version` returns the module's semantic version (`1.0.0`), matching
`metadata.json`:

```bash
logoscore call logos_execution_zone version
```

### 4.10 Encode an account id to base58

`account_id_to_base58` takes a 32-byte account id as 64 hex characters
and returns its base58 form. This is a pure encoding helper in
`wallet_ffi` — no open wallet and no network required, so it runs
entirely offline:

```bash
logoscore call logos_execution_zone account_id_to_base58 aaaaaaaa...aaaa  # 64 hex chars
```

### 4.11 Round-trip it back to hex

`account_id_from_base58` is the inverse: feed it the base58 string we just
produced and it returns the original 64-hex account id. Encoding then
decoding the same id and recovering the input is a deterministic,
end-to-end proof that the codec — and the IPC path to this module — work:

```bash
# Encode, then decode the result back — the round-trip returns the input.
B58=$(logoscore call logos_execution_zone account_id_to_base58 aaaa...aaaa)
logoscore call logos_execution_zone account_id_from_base58 "$B58"
```

### 4.12 Reject malformed base58

Decoding obvious garbage fails cleanly: `account_id_from_base58` returns
an empty result rather than crashing the module or the daemon:

```bash
logoscore call logos_execution_zone account_id_from_base58 '!!!not-base58!!!'
```

### 4.13 Stop the daemon

Shut the daemon down cleanly:

```bash
logoscore stop
```

The daemon removes its state file and exits.

```bash
sleep 2
```

### 4.14 Confirm the daemon has stopped

With no daemon running, the client reports `not_running` and exits
non-zero, so we add `|| true` to let the doc-test assert on the output:

```bash
logoscore status
```
