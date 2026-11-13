from contextvars import ContextVar

_current_actor: ContextVar[str | None] = ContextVar("threatlens_current_actor", default=None)


def set_current_actor(actor: str):
    return _current_actor.set(actor)


def reset_current_actor(token: object) -> None:
    _current_actor.reset(token)  # type: ignore[arg-type]


def current_actor() -> str | None:
    return _current_actor.get()
