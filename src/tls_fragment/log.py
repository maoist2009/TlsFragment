import logging
from .config import config

if config.get("logfile"):
    logging.basicConfig(
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        filemode="w",
        filename=config["logfile"]
    )
else:
    logging.basicConfig(
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

logger = logging.getLogger("tls_fragmenter")
logger.setLevel(config["loglevel"])
