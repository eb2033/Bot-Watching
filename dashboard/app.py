from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PROJECT_ROOT_STR = str(PROJECT_ROOT)

if PROJECT_ROOT_STR not in sys.path:
	sys.path.insert(0, PROJECT_ROOT_STR)

from flask import Flask

from dashboard import config
from dashboard.routes.api import api_bp
from dashboard.routes.dashboard import dashboard_bp


def create_app() -> Flask:
	app = Flask(__name__)
	app.config["SECRET_KEY"] = config.SECRET_KEY

	app.register_blueprint(dashboard_bp)
	app.register_blueprint(api_bp, url_prefix="/api")

	return app


if __name__ == "__main__":
	create_app().run(host="0.0.0.0", port=5000, debug=config.DEBUG)
