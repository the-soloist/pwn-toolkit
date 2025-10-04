import logging
import logging.handlers
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

# Create logs directory
logs_dir = Path("logs")
logs_dir.mkdir(parents=True, exist_ok=True)

# Define custom log level
SUCCESS = 25
logging.addLevelName(SUCCESS, "SUCCESS")


def success(self, message, *args, **kwargs):
    if self.isEnabledFor(SUCCESS):
        self._log(SUCCESS, message, args, **kwargs)


logging.Logger.success = success

# Create loggers
root_logger = logging.getLogger()
root_logger.setLevel(logging.DEBUG)

main_logger = logging.getLogger("main")
main_logger.setLevel(logging.DEBUG)

# Create formatter
file_formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
console_formatter = logging.Formatter("- %(name)s - %(message)s")

# Create handlers
custom_theme = Theme(
    {
        "logging.level.success": "bold green",
        "logging.level.info": "bold blue",
        "logging.level.warning": "bold yellow",
        "logging.level.error": "bold red",
        "logging.level.critical": "bold white on red",
    }
)

# Create handlers
console_handler = RichHandler(
    rich_tracebacks=True,
    console=Console(theme=custom_theme),  # Apply the custom theme
)
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(console_formatter)

file_handler = logging.handlers.RotatingFileHandler(logs_dir / "app.log", "a", 10 * 1024 * 1024, 10)
file_handler.setLevel(logging.NOTSET)
file_handler.setFormatter(file_formatter)

# Add handlers to loggers
root_logger.addHandler(console_handler)
root_logger.addHandler(file_handler)

main_logger.addHandler(file_handler)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


if __name__ == "__main__":
    log = get_logger("test")

    log.debug("debug message")
    log.info("info message")
    log.success("success message")
    log.warning("warning message")
    log.error("error message")
    log.critical("critical message")

    try:
        print(1 / 0)
    except Exception:
        log.exception("unable print!")
