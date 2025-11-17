"""Shared constants and terminal color helpers."""

class Colors:
    """Optimized color codes for terminal output."""

    H = "\033[95m"
    B = "\033[94m"
    C = "\033[96m"
    G = "\033[92m"
    Y = "\033[93m"
    R = "\033[91m"
    BOLD = "\033[1m"
    U = "\033[4m"
    END = "\033[0m"
    DIM = "\033[2m"
    BG_R = "\033[41m"
    BG_G = "\033[42m"


__all__ = ["Colors"]
