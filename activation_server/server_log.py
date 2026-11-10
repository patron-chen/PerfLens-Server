"""Write timestamped service logs and keep each size-based archive."""
from datetime import datetime
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path


LOG_DIR = Path("log")
LOG_NAME = "activation-server.log"
MAX_LOG_BYTES = 50 * 1024 * 1024


class LocalTimeFormatter(logging.Formatter):
    def formatTime(self, record, datefmt=None):
        return datetime.fromtimestamp(record.created).astimezone().isoformat(timespec="milliseconds")


class ArchiveLogHandler(RotatingFileHandler):
    def shouldRollover(self, record):
        size = self.stream.tell()
        if not size:
            return False
        # Count the bytes FileHandler writes, including Windows line endings.
        message = (self.format(record) + self.terminator).replace("\n", os.linesep)
        return size + len(message.encode(self.encoding, self.errors)) > self.maxBytes

    def doRollover(self):
        log_path = Path(self.baseFilename)
        stamp = datetime.now().astimezone().strftime("%Y%m%d-%H%M%S-%f%z")
        archive = log_path.with_name(f"{log_path.stem}-{stamp}{log_path.suffix}")
        index = 1
        while archive.exists():
            archive = log_path.with_name(f"{log_path.stem}-{stamp}-{index}{log_path.suffix}")
            index += 1

        self.stream.close()
        try:
            log_path.rename(archive)
        except PermissionError:
            # Windows log readers may temporarily prevent renaming. Keep the record and retry on the next write.
            pass
        finally:
            self.stream = self._open()


def file_log_handler(log_dir, fmt="%(asctime)s %(levelname)s %(message)s"):
    log_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    handler = ArchiveLogHandler(log_dir / LOG_NAME, maxBytes=MAX_LOG_BYTES, encoding="utf-8",
                                errors="backslashreplace")
    handler.setFormatter(LocalTimeFormatter(fmt))
    return handler
