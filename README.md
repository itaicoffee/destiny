# destiny

`destiny` is a local, cross-platform Rust CLI for deterministic, site-specific
passwords. Its modern v3 format is memory-hard; the exact One Shall Pass v2 and
v1 formats remain available for existing logins. There is no server, account,
sync, analytics, telemetry, or runtime network code.

The only secret is your master password. `destiny` never writes it to disk and
never accepts it as a command-line argument or environment variable. Your email,
host aliases, and non-secret per-host parameters can live in a local TOML file.

## Quick start

Build and install with a stable Rust toolchain:

```sh
cargo install --locked --path .
```

Save your email once:

```sh
destiny config email you@example.com
```

Then generate a password. The prompt does not echo; the result goes to the
native system clipboard and clears after 45 seconds if it has not been replaced:

```console
$ destiny github.com
Master password:
Password copied to the system clipboard for github.com; it will clear in 45s if unchanged.
```

Nothing secret is printed. Use `--print` only for scripts or when displaying the
password is an acceptable tradeoff:

```sh
destiny github.com --print
some-secret-provider | destiny github.com --password-stdin --print
```

`--password-stdin` requires redirected input, reads exactly one line, and refuses
an interactive terminal. Avoid environment variables for secrets. Both normal
interactive forms use the hidden prompt:

```sh
destiny you@example.com github.com
destiny github.com                    # after saving the email
```

Change clipboard lifetime per invocation, or explicitly disable timed clearing:

```sh
destiny github.com --clear-after 20
destiny github.com --clear-after 0
```

The background clipboard service receives the password only over an anonymous
pipe. It uses native OS APIs, asks supported clipboard managers not to retain
history/cloud copies, compares before clearing, and exits without disturbing
anything copied after the generated password.

## Host profiles

V3 defaults to a 16-character password. Save only exceptions:

```sh
destiny config host github.com --symbols 2 --generation 1
destiny github.com
```

Use a memorable alias without changing the actual host input:

```sh
destiny config host work --value login.example.com --symbols 1
destiny work
```

Rotate only that host by incrementing its generation:

```sh
destiny config host work --generation 2
```

Manage the non-secret configuration:

```sh
destiny config list
destiny config path
destiny config defaults --length 16 --symbols 1
destiny config remove-host work
destiny config clear-email
```

Command-line parameters override a host profile, which overrides global
defaults. `--params` (also `--show-params`) prints resolved, non-secret values to
stderr while still generating the password.

## Versions and parameters

V3 is the default:

- Argon2id v1.3 with 64 MiB of memory, three passes, and four lanes.
- Generation 1, length 16, and zero symbols.
- Length 12 through 16; symbols 0 through 3.
- Symbol insertion always preserves at least one uppercase letter, lowercase
  letter, and digit.

The KDF settings are fixed as part of v3 so a future dependency update cannot
silently rotate passwords. A future tuning change must become v4. The complete
byte-level format and test vectors are in [`docs/v3-format.md`](docs/v3-format.md).

Use the legacy selector for passwords already enrolled with One Shall Pass:

```sh
destiny github.com --legacy v2
destiny github.com --legacy v1
```

You can also use `--algorithm v3|v2|v1`, including in saved profiles. Legacy
defaults remain exact: v2 uses 8 bits and v1 uses 7 bits, both use generation 1,
length 12, and zero symbols.

```text
--generation / -g N
--length / -l N          v3: 12..16; legacy: 8..16
--symbols / -s N         0..3
--legacy v2|v1
--algorithm v3|v2|v1
--bits 1..16             legacy only
```

V2 and v1 deliberately retain all upstream behavior, including their historical
whitespace normalization and symbol substitution. Their independent reference
vectors are regression-tested byte-for-byte.

## V3 identity normalization

V3 removes common recovery footguns while keeping the rules small and frozen:

- Email, host, and master password use Unicode NFC normalization.
- Email and host are lowercased; international domain names become IDNA ASCII.
- A host's single trailing dot and one leading `www.` are ignored.
- URLs, paths, query strings, fragments, user info, ports, whitespace, invalid
  labels, and ambiguous email shapes are rejected instead of producing a
  surprising second password.
- Other subdomains remain distinct on purpose.

The direct `unicode-normalization` and `idna` versions are exactly pinned in the
manifest. A future table upgrade that changes any accepted input must use a new
algorithm version.

## Config location and migration

`destiny config path` prints the platform-specific path:

- macOS: `~/Library/Application Support/destiny/config.toml`
- Linux: `${XDG_CONFIG_HOME:-~/.config}/destiny/config.toml`
- Windows: `%APPDATA%\destiny\config\config.toml` (as resolved by the platform)

Set `DESTINY_CONFIG` to use an explicit path for non-secret profile sync. The
former `ORACLE_CONFIG` override and `oracle` default config location remain
supported so existing profiles continue to work after the rename. On Unix,
Destiny rejects symlinks, wrong ownership, hard-linked config files, and
group/world-readable locations. It enforces directory mode `0700`, file mode
`0600`, atomic replacement, and filesystem synchronization when it writes.
Windows uses the user's platform config directory and account ACLs; config
symlinks are still rejected.

Version-1 config files are migrated in memory. Their old implicit algorithm is
recorded as v2 on the next config write, so upgrading cannot silently rotate
previously enrolled passwords. New configs default to v3.

Example version-2 config:

```toml
version = 2
email = "you@example.com"

[defaults]
algorithm = "v3"
length = 16

[hosts.work]
host = "login.example.com"

[hosts.work.parameters]
generation = 2
symbols = 1

[hosts.old-site.parameters]
algorithm = "v2"
security_bits = 8
```

The schema has no password field, rejects unknown fields, and rejects aliases
that differ only by case or Unicode representation. Never add a master password
to this file.

## Security model

V3 substantially raises the cost of offline guessing, but deterministic password
generation still has an unavoidable tradeoff: a leaked generated password lets
an attacker test master-password guesses offline. Use a unique, high-entropy
master passphrase. Changing it changes every generated password.

Additional defenses:

- Master-password input is hidden or explicitly piped, never argv/config/env.
- Secret buffers and cryptographic state use zeroization where their types allow.
- Unix core dumps are disabled before reading secrets; Linux also marks the process
  non-dumpable to reduce tracing and `/proc` memory exposure.
- Clipboard history/cloud exclusion is requested on macOS, Windows, X11, and
  supported Wayland desktops, followed by compare-before-clear.
- Clipboard integration uses native APIs rather than executable lookup through
  `PATH`.
- The application source forbids unsafe Rust and has no runtime network stack.

A compromised desktop can still keylog input or read the clipboard during its
short lifetime. OS, firmware, swap, hibernation, privileged debugging, and
clipboard-manager policy remain outside a CLI's complete control. For most
people, a maintained password manager with random per-site secrets remains the
safer default; Destiny is for deliberate offline deterministic recovery.

## Development and supply chain

```sh
cargo fmt --check --all
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
cargo audit --deny warnings
```

Direct dependencies are exactly pinned and `Cargo.lock` is committed. CI uses
immutable full-commit action pins, locked Cargo commands, a three-OS test matrix,
and a weekly RustSec audit.

## License and attribution

MIT. The legacy derivation algorithms are ported from
[maxtaco/oneshallpass](https://github.com/maxtaco/oneshallpass), also MIT; see
[`LICENSE`](LICENSE).
