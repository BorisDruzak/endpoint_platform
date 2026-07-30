"""Production ASGI import target."""

from endpoint_server.config import Settings
from endpoint_server.main import create_app


app = create_app(Settings.from_environment())
