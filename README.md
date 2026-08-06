# fyleinfo

`fyleinfo` is a self-contained Python command-line and optional Tkinter program
for analyzing text files, source code, configuration files, logs, and standard
input.

It reports:

- file size, SHA-256, encoding, newline style, and permissions
- words, unique words, lexical diversity, and frequent words
- lines, paragraphs, estimated sentences, and line-length review
- whitespace, indentation, duplicate lines, and bracket-count signals
- URLs, email addresses, IPv4 addresses, identifiers, and review markers
- text or JSON output
- optional report saving and an optional graphical interface

## Requirements

- Python 3.10 or newer
- No third-party Python runtime packages
- Optional GUI: Tkinter from the operating system package manager

`requirements.txt` is intentionally empty because the runtime imports only the
Python standard library.

## Quick start

Run directly from the repository:

```bash
python3 fyleinfo.py --help
python3 fyleinfo.py examples/sample_text.txt
python3 fyleinfo.py --format json examples/sample_code.py
```

Install for the current user without modifying system directories:

```bash
chmod +x install.sh
./install.sh
fyleinfo --version
```

The installer copies files under `~/.local/`. It does not use `sudo` and does
not install operating system packages.

## Optional operating system dependencies

Linux Mint, Ubuntu, Debian:

```bash
sudo apt update
sudo apt install python3 python3-tk git
```

Fedora and current DNF-based systems:

```bash
sudo dnf install python3 python3-tkinter git
```

Older YUM-based systems:

```bash
sudo yum install python3 python3-tkinter git
```

Arch Linux and derivatives:

```bash
sudo pacman -Syu python tk git
```

The GUI package is optional. Terminal analysis works without it.

## Common usage

```bash
fyleinfo notes.txt
fyleinfo --top 25 --ignore-common notes.txt
fyleinfo --find Python --find TODO source.py
fyleinfo --format json --output report.json source.py
printf '%s\n' 'alpha beta beta' | fyleinfo -
fyleinfo --gui notes.txt
```

## Safe output behavior

`--save` does not replace an existing report unless `--overwrite` is supplied.
The default input ceiling is 50 MiB. Use `--max-bytes 0` only when you have
confirmed that enough memory is available.

## Installation alternatives

### Direct user installation

```bash
./install.sh
```

### pipx from the local clone

```bash
pipx install .
```

### Editable development installation

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install --editable '.[dev]'
```

## Tests

Standard-library test run:

```bash
python3 -m unittest discover -s tests -v
```

Optional development checks:

```bash
python3 -m pip install --requirement requirements-dev.txt
ruff check .
python3 -m pytest
python3 -m build
```

## Repository structure

```text
fyleinfo/
├── .github/
│   ├── ISSUE_TEMPLATE/
│   ├── pull_request_template.md
│   └── workflows/tests.yml
├── completions/fyleinfo.bash
├── docs/fyleinfo_github_guide.html
├── examples/
├── learning/fyleinfo_commented.py
├── man/fyleinfo.1
├── scripts/
├── tests/test_fyleinfo.py
├── fyleinfo.py
├── install.sh
├── uninstall.sh
├── pyproject.toml
├── README.md
├── CHANGELOG.md
├── CONTRIBUTING.md
├── SECURITY.md
├── LICENSE
├── Makefile
└── requirements*.txt
```

## Development workflow

```bash
git switch -c feature/descriptive-name
# Edit and test.
git status
git diff
git add --all
git diff --staged
git commit -m 'Add descriptive change'
git push -u origin feature/descriptive-name
```

Update `CHANGELOG.md` for user-visible behavior changes. Keep production logic
in `fyleinfo.py`. Regenerate or manually synchronize the educational copy when
production behavior changes.

## License

MIT. See `LICENSE`.
