from collections.abc import AsyncGenerator
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlmodel import SQLModel, select
from sqlmodel.ext.asyncio.session import AsyncSession
from app.config import settings
from app.models.user import User
from app.models.audit import AuditLog  # noqa: F401
from app.services.security import hash_password

settings.ensure_directories()

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    connect_args={"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {},
)

async_session_maker = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_maker() as session:
        yield session


async def init_db() -> None:
    settings.ensure_directories()
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

    # Bootstrap admin user if not present
    async with async_session_maker() as session:
        result = await session.exec(select(User).where(User.username == settings.ADMIN_USERNAME))
        admin_user = result.first()
        if not admin_user:
            admin_user = User(
                username=settings.ADMIN_USERNAME,
                hashed_password=hash_password(settings.ADMIN_PASSWORD),
                is_admin=True,
            )
            session.add(admin_user)
            await session.commit()
