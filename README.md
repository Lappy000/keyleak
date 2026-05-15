# 🔑 keyleak

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Services](https://img.shields.io/badge/services-12%2B-orange.svg)](#supported-services)

**API key leak validator** — detect and verify leaked credentials across 12+ services from the command line.

`keyleak` takes API keys (from stdin, files, or direct input), automatically identifies the service they belong to, and validates whether they're still active by making safe, read-only API calls.

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/Lappy000/keyleak.git
cd keyleak

# Install in development mode
pip install -e .

# Or install dependencies directly
pip install -r requirements.txt
```

## 📖 Usage

### Pipe keys from stdin

```bash
# Single key
echo 'sk-abc123xyz456...' | keyleak

# Multiple keys (one per line)
cat leaked_keys.txt | keyleak

# From clipboard (macOS)
pbpaste | keyleak
```

### Scan files for keys

```bash
# Scan a single file
keyleak scan secrets.txt

# Scan multiple files
keyleak scan .env config.yml dump.txt

# Scan with glob patterns
keyleak scan *.env
```

### Check a single key directly

```bash
# Auto-detect service type
keyleak check 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'

# Force a specific service
keyleak check --service stripe 'sk_live_xxxxxx'
```

### Batch mode

```bash
# Process keys one per line from stdin
cat keys.txt | keyleak batch

# With JSON output
cat keys.txt | keyleak --json batch > results.json
```

### Output formats

```bash
# Rich table (default)
keyleak scan dump.txt

# JSON output
keyleak --json scan dump.txt

# Compact one-line format
keyleak --compact scan dump.txt

# Verbose with progress
keyleak -v scan dump.txt
```

### Filter by service

```bash
# Only check GitHub and AWS keys
keyleak -s github -s aws scan dump.txt
```

### List supported services

```bash
keyleak services
```

## 📋 Supported Services

| Service | Key Prefix | Validation Method | Endpoint |
|---------|-----------|-------------------|----------|
| **AWS** | `AKIA...` | STS GetCallerIdentity | `sts.amazonaws.com` |
| **OpenAI** | `sk-...` | List models | `GET /v1/models` |
| **Anthropic** | `sk-ant-...` | Send minimal message | `POST /v1/messages` |
| **GitHub** | `ghp_` / `gho_` / `github_pat_` | Get user | `GET /user` |
| **Stripe** | `sk_live_` / `sk_test_` | List charges | `GET /v1/charges?limit=1` |
| **Slack** | `xoxb-` / `xoxp-` | Auth test | `POST auth.test` |
| **SendGrid** | `SG.xxx.xxx` | Get profile | `GET /v3/user/profile` |
| **Twilio** | `SK...` (34 chars) | List accounts | `GET /2010-04-01/Accounts` |
| **Telegram** | `<digits>:<hash>` | Get bot info | `GET /bot<token>/getMe` |
| **DigitalOcean** | `dop_v1_...` | Get account | `GET /v2/account` |
| **Mailgun** | `key-...` | List domains | `GET /v3/domains` |
| **Hugging Face** | `hf_...` | Who am I | `GET /api/whoami-v2` |

## 🔧 Adding New Validators

1. Create a new file in `keyleak/validators/`:

```python
# keyleak/validators/myservice_key.py
"""MyService key validator."""

import time
import httpx
from keyleak.validators import KeyStatus, ValidationResult

def validate(key: str) -> ValidationResult:
    """Validate a MyService API key."""
    start_time = time.time()

    # Make a safe API call
    headers = {"Authorization": f"Bearer {key}"}
    try:
        with httpx.Client(timeout=15.0) as client:
            response = client.get("https://api.myservice.com/verify", headers=headers)

        elapsed = (time.time() - start_time) * 1000

        if response.status_code == 200:
            return ValidationResult(
                key_value=key,
                service="myservice",
                status=KeyStatus.VALID,
                message="Key is valid!",
                http_status=200,
                response_time_ms=round(elapsed, 2),
            )
        # ... handle other status codes
    except Exception as exc:
        elapsed = (time.time() - start_time) * 1000
        return ValidationResult(
            key_value=key,
            service="myservice",
            status=KeyStatus.ERROR,
            message=f"Error: {exc}",
            response_time_ms=round(elapsed, 2),
        )
```

2. Add a pattern to `keyleak/detector.py`:

```python
KeyPattern(
    service="myservice",
    pattern=re.compile(r"ms_[A-Za-z0-9]{32}"),
    description="MyService API Key",
    validator_module="keyleak.validators.myservice_key",
    prefix_hint="ms_",
    min_length=35,
    max_length=35,
),
```

3. Register in `keyleak/validators/__init__.py`:

```python
_VALIDATOR_MODULES = {
    ...
    "myservice": "keyleak.validators.myservice_key",
}
```

## ⚠️ Disclaimer

This tool is designed for **security professionals** and **authorized** leak validation only. Do not use it to exploit leaked credentials. If you find valid keys, report them responsibly to the key owner.

## 🏗️ Project Structure

```
keyleak/
├── keyleak/
│   ├── __init__.py          # Package metadata
│   ├── cli.py               # Click-based CLI with subcommands
│   ├── detector.py          # Regex-based key type detection
│   ├── output.py            # Rich table + JSON formatters
│   └── validators/
│       ├── __init__.py      # Base classes + dynamic loader
│       ├── aws.py           # AWS STS validation
│       ├── openai_key.py    # OpenAI /v1/models
│       ├── anthropic_key.py # Anthropic /v1/messages
│       ├── github_key.py    # GitHub /user
│       ├── stripe_key.py    # Stripe /v1/charges
│       ├── slack_key.py     # Slack auth.test
│       ├── sendgrid_key.py  # SendGrid /v3/user/profile
│       ├── twilio_key.py    # Twilio /2010-04-01/Accounts
│       ├── telegram_key.py  # Telegram /getMe
│       ├── digitalocean_key.py # DO /v2/account
│       ├── mailgun_key.py   # Mailgun /v3/domains
│       └── huggingface_key.py # HF /api/whoami-v2
├── README.md
├── pyproject.toml
├── requirements.txt
├── .gitignore
└── LICENSE
```

## 📄 License

MIT — see [LICENSE](LICENSE) for details.
