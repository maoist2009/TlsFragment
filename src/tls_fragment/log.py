import logging
from tls_fragment.config import config

logging.basicConfig(
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("tls_fragmenter")
logger.setLevel(config["loglevel"])
