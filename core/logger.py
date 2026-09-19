import logging
import os
from logging.handlers import RotatingFileHandler

# Directory for logs – can be overridden via RECON_LOG_DIR env var
LOG_DIR = os.getenv('RECON_LOG_DIR', os.path.join(os.getcwd(), 'logs'))
os.makedirs(LOG_DIR, exist_ok=True)

LOG_FILE = os.path.join(LOG_DIR, 'recon_framework.log')

def get_logger(name: str = 'recon'):
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(name)s - %(message)s')
    # Rotate log after 5 MB, keep 5 backups
    handler = RotatingFileHandler(LOG_FILE, maxBytes=5*1024*1024, backupCount=5)
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    # Also output to console at INFO level
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console.setFormatter(formatter)
    logger.addHandler(console)
    return logger
