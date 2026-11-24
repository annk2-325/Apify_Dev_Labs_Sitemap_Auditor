"""Allow `python -m src` execution used by `apify run` inside `apify_actor/`."""

from __future__ import annotations

import asyncio

from .main import main

if __name__ == "__main__":
    asyncio.run(main())
