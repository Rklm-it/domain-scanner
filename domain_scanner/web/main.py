"""ASGI entry point.

    uvicorn domain_scanner.web.main:app --host 0.0.0.0 --port 8000

Configuration comes from the environment (see .env.example); creating the app
here rather than in app.py keeps importing the module side-effect free.
"""

from .app import create_app

app = create_app()
