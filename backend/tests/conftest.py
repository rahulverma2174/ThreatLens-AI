from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from starlette.middleware.base import BaseHTTPMiddleware
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, initialize_schema
from app.dependencies import get_db
from app.main import app


@pytest.fixture
def client() -> Generator[TestClient, None, None]:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    initialize_schema(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def override_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    previous_factory = app.state.session_factory
    previous_test_mode = app.state.test_mode
    previous_auth_mode = app.state.auth_mode
    previous_demo_auth = app.state.demo_auth
    previous_middleware = app.user_middleware
    previous_stack = app.middleware_stack
    app.state.session_factory = session_factory
    app.state.test_mode = True
    # Starlette's BaseHTTPMiddleware request task stalls under this environment's
    # Python 3.14/httpx combination. The test client is in-process; production
    # localhost enforcement is exercised separately at the real-server boundary.
    app.user_middleware = [middleware for middleware in previous_middleware if middleware.cls is not BaseHTTPMiddleware]
    app.middleware_stack = None
    app.dependency_overrides[get_db] = override_db
    try:
        # Avoid application lifespan side effects (including binding the local syslog
        # receiver); this fixture already initializes its isolated in-memory schema.
        yield TestClient(app, base_url="https://testserver")
    finally:
        app.dependency_overrides.clear()
        app.state.session_factory = previous_factory
        app.state.test_mode = previous_test_mode
        app.state.auth_mode = previous_auth_mode
        app.state.demo_auth = previous_demo_auth
        app.user_middleware = previous_middleware
        app.middleware_stack = previous_stack
        Base.metadata.drop_all(bind=engine)
        engine.dispose()
