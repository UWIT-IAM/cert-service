# Daily cron jobs

The scripts in these folder run daily on a basic ubuntu machine with python installed.

The machine will install the dependencies in requirements.txt before running the scripts.

## Testing locally

To test these locally, create a virtual environment and activate it:

```
# Create a virtualenv
python3 -m venv .venv

# Activate it
# See https://docs.python.org/3/library/venv.html for windows instructions
source .venv/bin/activate

# Install the dependencies
pip install -r requirements.txt

# Run the script
python <script.py>
```

## Before submitting

```
Run pylint
```

## Adding a new DNS zone

To add support for a new zone, start at `./validators/__init__.py` and follow the instructions.
