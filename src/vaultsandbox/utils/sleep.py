"""Sleep utility for VaultSandbox SDK."""

import asyncio


async def sleep(ms: int) -> None:
    """Sleep for the specified number of milliseconds.

    Args:
        ms: Number of milliseconds to sleep.
    """
    await asyncio.sleep(ms / 1000)
