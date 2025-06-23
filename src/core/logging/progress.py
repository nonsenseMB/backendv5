"""Progress tracking utilities for long-running operations.

This module provides context managers and decorators for showing
progress during long operations using Rich progress bars.
"""

from collections.abc import AsyncGenerator, Callable, Coroutine, Generator
from contextlib import asynccontextmanager, contextmanager
from functools import wraps
from typing import Any, ParamSpec, TypeVar

from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)

from src.core.logging.console import console

P = ParamSpec("P")
T = TypeVar("T")


@contextmanager
def track_progress(
    description: str, total: int | None = None, transient: bool = True
) -> Generator[Any, None, None]:
    """Context manager for tracking progress of operations.

    Args:
    ----
        description: Description of the operation
        total: Total number of steps (None for indeterminate)
        transient: Whether to remove progress bar when done

    Yields:
    ------
        Progress task that can be updated

    Example:
    -------
        with track_progress("Processing files", total=100) as task:
            for i in range(100):
                # Do work
                task.update(1)

    """
    if total is None:
        # Indeterminate progress (spinner)
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
            transient=transient,
        )
    else:
        # Determinate progress (bar)
        progress = Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=console,
            transient=transient,
        )

    with progress:
        task_id = progress.add_task(description, total=total)
        task = progress.tasks[task_id]

        # Add update method to task
        def update(advance: int = 1, **kwargs: Any) -> None:
            progress.update(task_id, advance=advance, **kwargs)

        task.update = update  # type: ignore[attr-defined]
        yield task


@asynccontextmanager
async def async_track_progress(
    description: str, total: int | None = None, transient: bool = True
) -> AsyncGenerator[Any, None]:
    """Async context manager for tracking progress of async operations.

    Args:
    ----
        description: Description of the operation
        total: Total number of steps (None for indeterminate)
        transient: Whether to remove progress bar when done

    Yields:
    ------
        Progress task that can be updated

    Example:
    -------
        async with async_track_progress("Fetching data", total=10) as task:
            for i in range(10):
                await fetch_item(i)
                task.update(1)

    """
    if total is None:
        # Indeterminate progress (spinner)
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
            transient=transient,
        )
    else:
        # Determinate progress (bar)
        progress = Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=console,
            transient=transient,
        )

    progress.start()
    try:
        task_id = progress.add_task(description, total=total)
        task = progress.tasks[task_id]

        # Add update method to task
        def update(advance: int = 1, **kwargs: Any) -> None:
            progress.update(task_id, advance=advance, **kwargs)

        task.update = update  # type: ignore[attr-defined]
        yield task
    finally:
        progress.stop()


def with_progress(
    description: str, total: int | None = None
) -> Callable[[Callable[P, T]], Callable[P, T]]:
    """Show progress for a function.

    Args:
    ----
        description: Description of the operation
        total: Total number of steps (None for indeterminate)

    Returns:
    -------
        Decorator function

    Example:
    -------
        @with_progress("Processing items", total=100)
        def process_items(items):
            for item in items:
                # Process item
                yield  # Update progress

    """

    def decorator(func: Callable[P, T]) -> Callable[P, T]:
        @wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            with track_progress(description, total=total) as task:
                # If function is a generator, update on each yield
                result = func(*args, **kwargs)
                if hasattr(result, "__iter__") and not isinstance(result, str | bytes):

                    def generator() -> Generator[Any, None, None]:
                        for item in result:
                            task.update(1)
                            yield item

                    return generator()  # type: ignore[return-value]
                return result

        return wrapper

    return decorator


def async_with_progress(
    description: str, total: int | None = None
) -> Callable[[Callable[P, T]], Callable[P, T]]:
    """Async decorator to show progress for an async function.

    Args:
    ----
        description: Description of the operation
        total: Total number of steps (None for indeterminate)

    Returns:
    -------
        Decorator function

    Example:
    -------
        @async_with_progress("Fetching data", total=10)
        async def fetch_all_data():
            for i in range(10):
                await fetch_item(i)
                yield  # Update progress

    """

    def decorator(func: Callable[P, T]) -> Callable[P, T]:
        @wraps(func)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            async with async_track_progress(description, total=total) as task:
                # If function is an async generator, update on each yield
                result = func(*args, **kwargs)
                if hasattr(result, "__aiter__"):

                    async def generator() -> AsyncGenerator[Any, None]:
                        async for item in result:
                            task.update(1)
                            yield item

                    return generator()  # type: ignore[return-value]
                return await result  # type: ignore[no-any-return,misc]

        return wrapper  # type: ignore[return-value]

    return decorator


# Convenience functions for common operations
def show_spinner(message: str) -> Progress:
    """Show a simple spinner with a message.

    Args:
    ----
        message: Message to display

    Returns:
    -------
        Progress instance (call .stop() when done)

    Example:
    -------
        spinner = show_spinner("Loading...")
        try:
            # Do work
        finally:
            spinner.stop()

    """
    progress = Progress(
        SpinnerColumn(),
        TextColumn(message),
        console=console,
        transient=True,
    )
    progress.start()
    return progress


async def run_with_spinner(
    coro: Coroutine[Any, Any, T], message: str = "Processing..."
) -> T:
    """Run an async coroutine with a spinner.

    Args:
    ----
        coro: Coroutine to run
        message: Message to display

    Returns:
    -------
        Result of the coroutine

    Example:
    -------
        result = await run_with_spinner(
            fetch_data(),
            "Fetching data..."
        )

    """
    progress = show_spinner(message)
    try:
        return await coro
    finally:
        progress.stop()
