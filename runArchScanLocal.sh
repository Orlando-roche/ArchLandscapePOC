# 0) In your repo root
#cd /path/to/your/repo

# 1) Make sure you have Python 3 (Homebrew example)
#brew install python@3.11   # skip if you already have python3

# 2) Create and activate a virtual env
#python3 -m venv .venv
#source .venv/bin/activate

# 3) Upgrade pip in the venv and install requirements (note the -r!)
#python -m pip install --upgrade pip
#python -m pip install -r requirements.txt

# 4) Run the scanner (it will create the diagrams folder if needed)
python archscan.py --repo . --out outputs/web-afm.json --diagram outputs/web-landscape.mmd

# 5) Validate (include your allowlist if you’re using it)
python validate_afm.py --afm outputs/web-afm.json --schema afm_schema.json --allowlist config/allowed_issuers.txt

