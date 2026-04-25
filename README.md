# lieuMt

`lieuMt.` is a small C++26 backend for serving a CS:GO client mirror, generating `version.toon` and `checksum.toon`, and publishing cached xxHash-addressed `.7z` replacement packages for the `launchMt` updater for the fragMount 2016 CS:GO project.

Target runtime is Debian 12 / Linux. 
Debian 12 because some silly vPS providers out there still use 12 and I'm soon going to migrate, want to be sure. (Will work fine with 13.)
Windows support has been removed on purpose and lieuMt. will not compile on Windows.

## Build

```bash
sudo apt-get install -y build-essential cmake ninja-build p7zip-full
cmake -S lieuMt -B lieuMt/build -G Ninja
cmake --build lieuMt/build
```

## Run

```bash
./lieuMt/build/lieuMt --root /srv/csgo --cache /srv/csgo/cache --host 0.0.0.0 --port 1919
```

Default flags:

- `--root ./client-root`
- `--cache ./cache`
- `--host 0.0.0.0`
- `--port 1919`
- `--version v1.0.0`

`lieuMt.` requires `7z` on `PATH`. On Debian 12 that usually means `p7zip-full`.

## What It Does

- Scans the configured game root and generates `version.toon` and `checksum.toon`
- Excludes `/cache/`, the generated `.toon` files, and heavy stable trees from the checksum pass
- Default skipped trees: `/csgo/expressions/`, `/csgo/maps/workshop/`, `/csgo/materials/`, `/csgo/models/`, `/csgo/sounds/`, and `/platform/`
- Uses `xxh3_64` for game validation instead of SHA256; the launcher still accepts older SHA256 manifests during transition
- Publishes package paths in `checksum.toon` and creates missing `.7z` archives on first request
- Caches tracked file packages in `/cache/files/<sha256>.7z`
- Can mark whole subtrees for authoritative replacement archives under `/cache/marks/`
- Serves packages from RAM when the compressed archive is `<= 128MB`
- Regenerates metadata daily at local `12:00`
- Lets you trigger manual regen from the console

## Security Notes

- `lieuMt.` only supports `GET`.
- Request headers are capped to a small fixed size.
- Only `HTTP/1.0` and `HTTP/1.1` are accepted.
- Per-IP rate limits and per-IP concurrent connection limits are enforced.
- Package requests are validated against strict SHA256-shaped names. // bundled .7z's do not get named.
- Cache paths and path traversal attempts are rejected.
- Responses send hardening headers such as `X-Content-Type-Options: nosniff` and `Content-Security-Policy: default-src 'none'`.

## HTTP

- `GET /health`
- `GET /version.toon`
- `GET /checksum.toon`
- `GET /packages/<sha256>.7z`
- `GET /marks/<archive>.7z`
- static `GET /path/in/root` for regular files under the configured root

There is no upload endpoint.
Upload or replace files over SSH, SCP, rsync, or SFTP, then run `regen`.

## Console

- `status`: shows bind address, version, file counts, checksum state, and active sends
- `regen`: rebuilds `version.toon` and `checksum.toon` without changing the version label
- `regen -version "v1.1.6"`: rebuilds the `.toon` files and also sets a specific version label
- `mark /bin/ --force-delete-excess`: treat a subtree as authoritative and rebuild a grouped archive for it
- `mark /csgo/bin/ -version "v1.1.6" --force-delete-excess`: same, while also stamping the marked subtree with an operator-facing version label
- `cache`: shows RAM cache stats
- `cache clear`: clears the RAM cache
- `help`: prints the command list
- `quit`: stops the server

## Usage Example

```bash
screen -S lieumt
./lieuMt/build/lieuMt --root /srv/csgo --cache /srv/csgo/cache --host 0.0.0.0 --port 1919

# in the lieuMt console
regen -version "v1.2.0"
mark /bin/ -version "v1.2.0" --force-delete-excess
```

Detach from `screen` with `Ctrl+A` then `D`.

## Deployment Notes

- `lieuMt.` is only the file/update backend
- launcher patching or launcher self-update can live in a separate service
- unmarked files stay in replace-only mode: if a file does not exist locally, it is skipped rather than created
- marked subtrees are different: the launcher downloads the grouped subtree archive, replaces that directory wholesale, and deletes excess files by virtue of replacing the entire tree
- package archives are lazy: `regen` hashes files and updates manifests, while `.7z` files are created only when a launcher requests them

## Name

The name `lieuMt.` derives from the french phrase I really like, `au lieu de`, meaning `instead of`, which fits the current updater model: only replace stuff that already exists. No adding of anything new (for the time being).
