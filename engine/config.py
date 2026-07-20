import os
from pathlib import Path
from dotenv import load_dotenv
BASE_DIR = Path(__file__).parent
PROJECT_ROOT = BASE_DIR.parent
load_dotenv(PROJECT_ROOT / ".env")

WORDLIST_DIR = BASE_DIR / "filters" / "wordlists"

#Can be changed to any other path if needed, but make sure the files exist in that path
USERNAMES_PATH = WORDLIST_DIR / "usernames.txt"
PASSWORDS_PATH = WORDLIST_DIR / "PasswordTop1000.txt"

DATABASE_URL = os.getenv("DATABASE_URL")