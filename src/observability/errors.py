"""Domain errors for immutable audit ingestion."""


class IdempotencyConflict(ValueError):
    """An idempotency key or event ID was reused for different audit content."""
