import logging
from colorlog import ColoredFormatter

formatter = ColoredFormatter(
    "%(log_color)s%(asctime)s [%(levelname)s]%(reset)s %(message)s",
    log_colors={
        "DEBUG": "blue",
        "INFO": "green",
        "WARNING": "yellow",
        "ERROR": "red",
        "CRITICAL": "bold_red",
    },
)

main_handler = logging.StreamHandler()
main_handler.setFormatter(formatter)

file_handler = logging.FileHandler("script.log")
file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))

logger = logging.getLogger(__name__)
logger.addHandler(main_handler)
logger.addHandler(file_handler)
logger.setLevel(logging.INFO)

def get_logger():
    return logger