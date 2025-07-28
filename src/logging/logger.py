# src/logging/logger.py

import logging
import structlog

def setup_logging(verbose: bool = False, log_format: str = 'plain'):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format='%(asctime)s [%(levelname)s] [%(module)s:%(funcName)s] %(message)s')
    if log_format == 'json':
        structlog.configure(
            processors=[
                structlog.processors.add_log_level,
                structlog.processors.StackInfoRenderer(),
                structlog.dev.set_exc_info,
                structlog.processors.TimeStamper(),
                structlog.processors.JSONRenderer()
            ],
            logger_factory=structlog.stdlib.LoggerFactory(),
        )
    # Return structlog.get_logger() if json, else logging.getLogger