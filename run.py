"""SentientAI — Application Entrypoint"""
import os

import uvicorn

if __name__ == "__main__":
    # Host/port are configurable (SENTIENTAI_HOST / SENTIENTAI_PORT) so the
    # dev launcher works on any machine; defaults keep the local behaviour.
    host = os.getenv("SENTIENTAI_HOST", "127.0.0.1")
    port = int(os.getenv("SENTIENTAI_PORT", "8000"))
    uvicorn.run(
        "app.main:app",
        host=host,
        port=port,
        reload=True,
        reload_dirs=["app"],
        reload_excludes=["data/*", "*.db", "*.log"],
    )
