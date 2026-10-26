# Original CLI — interactive Docker launcher

Requires Docker Engine and Docker Compose. From this directory:

```sh
docker compose run --rm --build malwhunter
```

`docker compose up` displays container output but does not forward terminal input.
Use the command above for a prompt in the same terminal; no start.sh is required.

The image builds automatically. After startup, enter a package and exact version
at the `Scan target >` prompt:

```text
Scan target > left-pad@1.3.0
... scan output ...
Scan target > chalk@4.1.2
... scan output ...
Scan target > q
```

The launcher stays open for additional scans. Type `q`, `quit`, or `exit` to stop.
If Docker permissions have not refreshed in your current terminal:

```sh
sg docker -c 'docker compose run --rm --build malwhunter'
```

`docker compose run` attaches terminal input. Use the following two-step
workflow if you prefer starting a persistent container with `up`:

```sh
docker compose up -d --build
docker compose attach malwhunter
```

After attaching, press Enter once if the prompt is not visible (attach does not
replay previous output). Only one interactive session should be attached to that
persistent container.
Type `q` to stop it; `docker compose down` removes the stopped service container.

## Project scan

Mount the project before starting, then enter `/project` at the prompt:

```sh
PROJECT_DIR=/absolute/path/to/project docker compose run --rm --build malwhunter
```

Use a package-lock.json with exact versions. The mounted folder is read-only.
Paths outside the mounted project are not available in the container.

## Direct commands still work

```sh
docker compose run --rm malwhunter inspect left-pad@1.3.0 --no-ai --no-detonate
docker compose run --rm malwhunter --help
PROJECT_DIR=/absolute/path/to/project docker compose run --rm -T malwhunter scan /project --no-ai --no-detonate --format json > report.json
```

The interactive launcher runs static Recon with AI and detonation off. No Docker
socket or AI credentials are mounted. The original scanner implementation and
verdict logic are unchanged; only Docker packaging and its launcher were added.
