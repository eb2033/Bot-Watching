from pathlib import Path
import sys


ENGINE_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = ENGINE_ROOT.parent
ENGINE_ROOT_STR = str(ENGINE_ROOT)
PROJECT_ROOT_STR = str(PROJECT_ROOT)

if PROJECT_ROOT_STR not in sys.path:
	sys.path.insert(0, PROJECT_ROOT_STR)

if ENGINE_ROOT_STR not in sys.path:
	sys.path.insert(0, ENGINE_ROOT_STR)
