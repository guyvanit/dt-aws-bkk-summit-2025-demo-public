import logging
import os
import sys
import streamlit as st


# === Context Handling ===

def append_keys(**kwargs):
    st.session_state.setdefault("log_context", {})
    st.session_state["log_context"].update(kwargs)


def append_tags(*values):
    st.session_state.setdefault("log_tags", [])
    st.session_state["log_tags"].extend(str(v) for v in values)


def remove_keys(*keys):
    st.session_state.setdefault("log_context", {})
    for k in keys:
        st.session_state["log_context"].pop(k, None)


def remove_tags(*values):
    st.session_state.setdefault("log_tags", [])
    st.session_state["log_tags"] = [
        tag for tag in st.session_state["log_tags"] if tag not in values
    ]


def clear_keys():
    st.session_state["log_context"] = {}


def clear_tags():
    st.session_state["log_tags"] = []


def clear_all():
    clear_keys()
    clear_tags()


# === Custom Logging Filter ===

class SessionStateContextFilter(logging.Filter):
    def filter(self, record):
        ctx = st.session_state.get("log_context", {})
        tags = st.session_state.get("log_tags", [])

        ctx_str = " ".join(f"[{k.upper()}: {v}]" for k, v in ctx.items())
        tag_str = " ".join(f"[{t}]" for t in tags)
        record.dynamic_context = f"{ctx_str} {tag_str}".strip()
        
        # If dynamic_context is empty, set it to a space to avoid formatting issues
        if not record.dynamic_context:
            record.dynamic_context = " "

        return True


# === Logger Init ===

def get_logger(log_to_stdout=None, log_level=None):
    """
    Get or create a logger with the specified configuration.
    
    Args:
        log_to_stdout: If True, logs to stdout. If False, logs to file.
                      If None, checks environment variable LOG_TO_STDOUT.
        log_level: Logging level (DEBUG, INFO, etc.). If None, checks environment variable LOG_LEVEL.
    
    Returns:
        A configured logger instance.
    """
    if "logger" not in st.session_state:
        # Determine logging destination from params or env vars
        if log_to_stdout is None:
            log_to_stdout = os.environ.get("LOG_TO_STDOUT", "false").lower() in ("true", "1", "yes")
        
        # Determine log level from params or env vars
        if log_level is None:
            log_level_name = os.environ.get("LOG_LEVEL", "INFO").upper()
            log_level = getattr(logging, log_level_name, logging.INFO)
        
        logger = logging.getLogger("streamlit_app")
        logger.setLevel(log_level)
        
        if not logger.hasHandlers():
            # Create formatter
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(dynamic_context)s %(message)s",
                "%Y-%m-%d %H:%M:%S"
            )
            
            # Add filter for context BEFORE creating handlers
            # to ensure dynamic_context is available
            logger.addFilter(SessionStateContextFilter())
            
            if log_to_stdout:
                # Add stdout handler
                handler = logging.StreamHandler(sys.stdout)
                handler.setFormatter(formatter)
                logger.addHandler(handler)
                logger.info("Logging to stdout")
            else:
                # Add file handler
                os.makedirs("logs", exist_ok=True)
                handler = logging.FileHandler("logs/app.log")
                handler.setFormatter(formatter)
                logger.addHandler(handler)
                logger.info("Logging to file: logs/app.log")

        # Attach methods to logger
        logger.append_keys = append_keys
        logger.append_tags = append_tags
        logger.remove_keys = remove_keys
        logger.remove_tags = remove_tags
        logger.clear_keys = clear_keys
        logger.clear_tags = clear_tags
        logger.clear_all = clear_all
        
        # Store logger destination setting for reference
        logger.log_to_stdout = log_to_stdout
        
        st.session_state.logger = logger

    return st.session_state.logger
