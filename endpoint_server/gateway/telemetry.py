"""Domain-only optional report transaction boundary; transport errors escape."""
from collections.abc import Callable
import logging

from endpoint_contracts.gateway_ws import TelemetryResultEnvelopeV1
from endpoint_contracts.telemetry_results import TELEMETRY_RESULTS_FEATURE, TelemetryResultV1

logger = logging.getLogger(__name__)


async def ingest_optional_report(
    connection,
    envelope,
    session_provider,
    ingest: Callable,
    rejected: type[Exception],
) -> None:
    disposition, reason = "accepted", "persisted"
    try:
        async with session_provider() as session:
            await ingest(session, connection.device_id, envelope.payload)
            await session.commit()
    except rejected:
        # Closing the dedicated session rolls back the entire projection.
        # No exception text or report content crosses into logs / wire results.
        disposition, reason = "rejected", "domain_rejected"
        logger.info("optional_telemetry_rejected", extra={"report_kind": envelope.kind, "reason_code": reason})
    if TELEMETRY_RESULTS_FEATURE in connection.protocol_features:
        await connection.send(TelemetryResultEnvelopeV1(
            schema_version="gateway_ws_envelope_v1", kind="telemetry_result", sequence=envelope.sequence,
            payload=TelemetryResultV1(schema_version="telemetry_result_v1", report_kind=envelope.kind,
                report_id=envelope.payload.observation_id, report_sequence=envelope.sequence,
                disposition=disposition, reason_code=reason),
        ))
