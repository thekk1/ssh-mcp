import logging
import os

import uvicorn

from .app import PORT, build_app


def main() -> None:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
    uvicorn.run(build_app(), host="0.0.0.0", port=PORT)


if __name__ == "__main__":
    main()
