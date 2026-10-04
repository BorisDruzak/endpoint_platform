"""Two-route transaction containment; a disconnect never proves remote rollback."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from fastapi import HTTPException, Request
from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession, create_async_engine

from endpoint_server.auth.admin_sessions import AdminPrincipal, load_update_admin_in_transaction

logger = logging.getLogger(__name__)
NOT_APPLIED = "update_cancellation_attempt_not_applied"
UNKNOWN = "update_cancellation_outcome_unknown"


class OperationRetired(Exception):
    """Local acceptance deadline or explicit boundary count was exhausted."""


@dataclass
class OperationBudget:
    deadline: float
    retired: bool = False
    boundaries: int = 0
    commit_started: bool = False
    phase: str = "checkout"

    def retire(self) -> None:
        self.retired = True

    def check(self, *, sql: bool = False) -> None:
        if self.retired or asyncio.get_running_loop().time() >= self.deadline:
            self.retire()
            raise OperationRetired()
        if sql:
            self.boundaries += 1
            if self.boundaries > 64:
                self.retire()
                raise OperationRetired()

    def before_commit(self) -> None:
        self.check()
        if self.commit_started or self.deadline - asyncio.get_running_loop().time() < 3:
            self.retire()
            raise OperationRetired()
        self.phase = "commit"
        self.commit_started = True


class BudgetSession(AsyncSession):
    """Check every explicit SQL/flush entry, including the reused auth loader."""

    def __init__(self, *args, budget: OperationBudget, **kwargs):
        super().__init__(*args, **kwargs)
        self.budget = budget

    async def execute(self, *args, **kwargs):
        self.budget.check(sql=True)
        return await super().execute(*args, **kwargs)

    async def scalar(self, *args, **kwargs):
        self.budget.check(sql=True)
        return await super().scalar(*args, **kwargs)

    async def scalars(self, *args, **kwargs):
        self.budget.check(sql=True)
        return await super().scalars(*args, **kwargs)

    async def flush(self, *args, **kwargs):
        self.budget.check(sql=True)
        return await super().flush(*args, **kwargs)


@dataclass(eq=False)
class _Owner:
    budget: OperationBudget
    result: asyncio.Future
    entry: float
    acquired: asyncio.Event = field(default_factory=asyncio.Event)
    cleanup_started: asyncio.Event = field(default_factory=asyncio.Event)
    cleanup_deadline: float | None = None
    task: asyncio.Task | None = None
    connection: AsyncConnection | None = None
    raw: Any = None
    driver: Any = None
    leased: bool = False
    rollback_acknowledged: bool = False
    disposal: set[asyncio.Task] = field(default_factory=set)


class UpdateAdminTransactionProvider:
    """An independent two-connection pool, with slots held through late cleanup."""

    def __init__(self, database_url: str):
        if database_url.startswith("postgresql://"):
            database_url = database_url.replace("postgresql://", "postgresql+asyncpg://", 1)
        self.engine = create_async_engine(
            database_url, pool_size=2, max_overflow=0, pool_timeout=1,
            pool_pre_ping=True, connect_args={
                "timeout": 2, "command_timeout": 3,
                "server_settings": {"lock_timeout": "1000ms", "statement_timeout": "3000ms",
                    "idle_in_transaction_session_timeout": "3000ms"},
            },
        )
        self._owners: set[_Owner] = set()
        self._leases: dict[int, _Owner] = {}
        self._closed = False
        self._shutdown_tasks: set[asyncio.Task] = set()

        @event.listens_for(self.engine.sync_engine, "checkin")
        def checkin(dbapi_connection, connection_record):
            # Clear the lease before another checkout can reuse this physical driver.
            owner = self._leases.pop(id(connection_record), None)
            if owner is not None:
                owner.leased = False
                self._release_when_settled(owner)

        @event.listens_for(self.engine.sync_engine, "invalidate")
        def invalidate(dbapi_connection, connection_record, exception):
            owner = self._leases.pop(id(connection_record), None)
            if owner is not None:
                owner.leased = False
                self._release_when_settled(owner)

        @event.listens_for(self.engine.sync_engine, "checkout")
        def checkout(dbapi_connection, connection_record, connection_proxy):
            # get_raw_connection exposes the same record; no driver handle survives checkin.
            connection_record.info["update_admin_record"] = connection_record

    def _release_when_settled(self, owner: _Owner) -> None:
        if owner.task is not None and owner.task.done() and all(t.done() for t in owner.disposal):
            if not owner.leased:
                self._owners.discard(owner)
            # Retrieve exceptions without emitting SQL/parameters or orphan-task warnings.
            for task in (owner.task, *owner.disposal):
                if not task.cancelled():
                    task.exception()

    def _force_disconnect(self, owner: _Owner) -> None:
        connection = owner.connection
        if (owner.disposal or not owner.leased or connection is None or connection.closed
                or owner.raw is None or owner.raw.driver_connection is not owner.driver):
            return
        owner.driver.terminate()  # immediate local abort; not evidence of rollback/commit absence
        disposal = asyncio.create_task(connection.invalidate())
        owner.disposal.add(disposal)
        disposal.add_done_callback(lambda _: self._release_when_settled(owner))

    def _begin_cleanup(self, owner: _Owner) -> None:
        if owner.cleanup_deadline is None:
            owner.cleanup_deadline = min(owner.entry + 14, asyncio.get_running_loop().time() + 2)
            owner.cleanup_started.set()

    async def _operate(self, owner: _Owner, request: Request, readonly: bool,
            operation: Callable[[AsyncSession, OperationBudget, AdminPrincipal], Awaitable[Any]]) -> None:
        session = None
        value = None
        error: BaseException | None = None
        committed = False
        try:
            # This await is separately supervised by run(), including pre-ping/connect.
            connection = await self.engine.connect()
            owner.connection = connection
            owner.raw = await connection.get_raw_connection()
            owner.driver = owner.raw.driver_connection
            record = owner.raw.info["update_admin_record"]
            self._leases[id(record)] = owner
            owner.leased = True
            owner.budget.check()  # a late acquired connection may only be discarded
            owner.acquired.set()
            session = BudgetSession(bind=connection, budget=owner.budget,
                expire_on_commit=False, autoflush=False)
            owner.budget.phase = "limits"
            if readonly:
                await session.execute(text("SET TRANSACTION READ ONLY"))
            for command in ("SET LOCAL lock_timeout='1000ms'",
                    "SET LOCAL statement_timeout='3000ms'",
                    "SET LOCAL idle_in_transaction_session_timeout='3000ms'"):
                await session.execute(text(command))
            owner.budget.phase = "authentication"
            principal = await load_update_admin_in_transaction(request, session)
            owner.budget.phase = "domain"
            value = await operation(session, owner.budget, principal)
            if readonly:
                owner.budget.check()
                self._begin_cleanup(owner)
                await session.rollback()
                owner.rollback_acknowledged = True
            else:
                owner.budget.before_commit()  # no await between marking and COMMIT dispatch
                await session.commit()
                committed = True
            owner.budget.check()  # a late acknowledgement cannot extend the acceptance deadline
            if readonly and asyncio.get_running_loop().time() >= owner.cleanup_deadline:
                raise OperationRetired()
            owner.result.set_result((value, None))
        except BaseException as caught:
            error = caught
            owner.budget.retire()
            self._begin_cleanup(owner)  # failure starts the single cleanup budget before rollback
            if session is not None and not committed:
                try:
                    await session.rollback()  # this owner alone performs session cleanup
                    owner.rollback_acknowledged = True
                except BaseException:
                    pass
            if not owner.result.done():
                if isinstance(error, HTTPException) and owner.rollback_acknowledged and not owner.budget.commit_started:
                    owner.result.set_result((None, error))
                else:
                    unknown = (owner.budget.commit_started or not owner.rollback_acknowledged
                        or isinstance(error, (asyncio.CancelledError, OperationRetired, ConnectionError))
                        or getattr(error, "connection_invalidated", False))
                    code = UNKNOWN if unknown else NOT_APPLIED
                    # Checkout failed before any SQL: this attempt cannot have mutated state.
                    if session is None and not isinstance(error, (asyncio.CancelledError, OperationRetired)):
                        code = NOT_APPLIED
                    owner.result.set_result((None, HTTPException(503, code)))
            state = getattr(getattr(error, "orig", error), "sqlstate", None)
            logger.warning("update_cancellation_failure", extra={"phase": owner.budget.phase,
                "error_class": type(error).__name__, "sqlstate": state if state in ("55P03", "57014") else None,
                "elapsed": asyncio.get_running_loop().time() - owner.entry})
        finally:
            self._begin_cleanup(owner)
            if session is not None:
                try:
                    await session.close()
                except BaseException:
                    self._force_disconnect(owner)
            if owner.connection is not None:
                try:
                    if owner.budget.retired and not owner.rollback_acknowledged:
                        await owner.connection.invalidate()
                    await owner.connection.close()
                except BaseException:
                    self._force_disconnect(owner)

    async def run(self, request: Request, *, readonly: bool,
            operation: Callable[[AsyncSession, OperationBudget, AdminPrincipal], Awaitable[Any]]) -> Any:
        if self._closed or len(self._owners) >= 2:
            raise HTTPException(503, NOT_APPLIED)
        loop = asyncio.get_running_loop()
        entry = loop.time()
        owner = _Owner(OperationBudget(entry + 12), loop.create_future(), entry)
        self._owners.add(owner)  # synchronous admission; no waiting queue
        owner.task = asyncio.create_task(self._operate(owner, request, readonly, operation))
        owner.task.add_done_callback(lambda _: self._release_when_settled(owner))
        acquisition = asyncio.create_task(owner.acquired.wait())
        cleanup_notice = asyncio.create_task(owner.cleanup_started.wait())

        async def disconnected():
            while True:
                message = await request.receive()
                if message["type"] == "http.disconnect":
                    return

        disconnect = asyncio.create_task(disconnected())
        value = None
        response_error = None
        unsettled = False
        try:
            # Checkout ownership is visible only after connect/raw lease; never auth SQL after retirement.
            done, _ = await asyncio.wait({acquisition, owner.result, disconnect},
                timeout=max(0, min(entry + 3, owner.budget.deadline) - loop.time()),
                return_when=asyncio.FIRST_COMPLETED)
            if disconnect in done or not done:
                owner.budget.retire()
                owner.task.cancel()
                raise HTTPException(503, UNKNOWN if disconnect in done else NOT_APPLIED)
            remaining = owner.budget.deadline - loop.time()
            done, _ = await asyncio.wait({owner.result, disconnect, cleanup_notice}, timeout=max(0, remaining),
                return_when=asyncio.FIRST_COMPLETED)
            if cleanup_notice in done and not owner.result.done() and disconnect not in done:
                done, _ = await asyncio.wait({owner.result, disconnect},
                    timeout=max(0, owner.cleanup_deadline - loop.time()), return_when=asyncio.FIRST_COMPLETED)
            if disconnect in done or not done:
                owner.budget.retire()
                owner.task.cancel()
                raise HTTPException(503, UNKNOWN)
            value, error = owner.result.result()
            if error is not None:
                raise error
        except HTTPException as error:
            response_error = error
        except asyncio.CancelledError:
            owner.budget.retire()
            owner.task.cancel()
            raise
        finally:
            acquisition.cancel()
            cleanup_notice.cancel()
            disconnect.cancel()
            cleanup_end = owner.cleanup_deadline or min(entry + 14, loop.time() + 2)
            if not owner.task.done():
                await asyncio.wait({owner.task}, timeout=max(0, cleanup_end - loop.time()))
            if not owner.task.done():
                unsettled = True
                owner.budget.retire()
                owner.task.cancel()
                self._force_disconnect(owner)
            self._release_when_settled(owner)
        if unsettled and (response_error is not None or readonly):
            raise HTTPException(503, UNKNOWN)
        if response_error is not None:
            raise response_error
        return value

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        owners = tuple(self._owners)
        for owner in owners:
            owner.budget.retire()
            owner.task.cancel()
        pending = {o.task for o in owners if not o.task.done()}
        end = asyncio.get_running_loop().time() + 2
        if pending:
            await asyncio.wait(pending, timeout=2)
        for owner in owners:
            if not owner.task.done():
                self._force_disconnect(owner)
        disposal = asyncio.create_task(self.engine.dispose())
        self._shutdown_tasks.add(disposal)
        def disposed(task):
            self._shutdown_tasks.discard(task)
            if not task.cancelled():
                task.exception()
        disposal.add_done_callback(disposed)
        # Pool disposal also uses the one shared shutdown budget.
        await asyncio.wait({disposal}, timeout=max(0, end - asyncio.get_running_loop().time()))
