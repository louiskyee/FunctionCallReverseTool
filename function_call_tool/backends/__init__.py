"""Backend registry for FunctionCallReverseTool."""

from function_call_tool.backends.ghidra import GhidraBackend
from function_call_tool.backends.radare2 import Radare2Backend

BACKEND_REGISTRY = {
    'ghidra': GhidraBackend,
    'radare2': Radare2Backend,
}


def get_backend(name: str):
    """Get a backend class by name.

    Args:
        name: Backend name (e.g., 'ghidra', 'radare2').

    Returns:
        Backend class.

    Raises:
        ValueError: If backend name is not registered.
    """
    if name not in BACKEND_REGISTRY:
        available = ', '.join(BACKEND_REGISTRY.keys())
        raise ValueError(
            f"Unknown backend '{name}'. Available: {available}"
        )
    return BACKEND_REGISTRY[name]
