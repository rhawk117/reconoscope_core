import contextlib
import warnings
from collections.abc import Generator


class ReconoscopeWarning(RuntimeWarning): ...


class SecurityWarning(ReconoscopeWarning): ...




def emit_warning(
    message: str,
    *,
    category: type[Warning] = ReconoscopeWarning,
    stacklevel: int = 3
) -> None:
    warnings.warn(
        message,
        category=category,
        stacklevel=stacklevel
    )


@contextlib.contextmanager
def on_error_emit_warning(
    message: str,
    *,
    catch: type[Exception] | tuple[type[Exception], ...],
    category: type[Warning] = ReconoscopeWarning,
    stacklevel: int = 3,
    reraise: bool = False,
) -> Generator[None]:
    try:
        yield
    except catch as exception:
        emit_warning(
            f'{message} (reason={exception!r})',
            category=category,
            stacklevel=stacklevel,
        )
        if reraise:
            raise
