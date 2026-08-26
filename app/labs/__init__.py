"""Lab registry — maps lab IDs to their handlers and metadata."""
from typing import Dict, Any, Callable, List

# Each lab is a dict with metadata + a handler function
LAB_REGISTRY: Dict[str, Dict[str, Any]] = {}


def register_lab(lab_id: str, name: str, category: str, difficulty: str,
                 description: str, handler: Callable):
    LAB_REGISTRY[lab_id] = {
        "id": lab_id,
        "name": name,
        "category": category,
        "difficulty": difficulty,
        "description": description,
        "handler": handler,
    }


def get_lab(lab_id: str) -> Dict[str, Any]:
    return LAB_REGISTRY.get(lab_id)


def list_labs() -> List[Dict[str, Any]]:
    return [
        {k: v for k, v in lab.items() if k != "handler"}
        for lab in LAB_REGISTRY.values()
    ]


# Import lab modules to trigger registration
def init_labs():
    import app.labs.sql_injection  # noqa: F401
    import app.labs.xss  # noqa: F401
