import logging
import sys

def setup_logger(name: str = "agent_logger", log_file: str = "agent_traces.log", level: int = logging.DEBUG) -> logging.Logger:
    """Configures and returns a logger with both file and console handlers."""
    logger = logging.getLogger(name)
    
    # Avoid adding multiple handlers if logger is already configured
    if logger.hasHandlers():
        return logger
        
    logger.setLevel(level)

    # Formatter for clear traces
    formatter = logging.Formatter(
        '%(asctime)s | %(levelname)-8s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # File Handler
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setFormatter(formatter)
    
    # Console Handler (Standard Output)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger

# Global instance for easy importing
agent_logger = setup_logger()
