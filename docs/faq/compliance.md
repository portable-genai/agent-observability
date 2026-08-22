# Compliance FAQ

## Does this repository certify regulatory compliance?

No. It supplies technical control evidence. The institution owns legal interpretation,
operating effectiveness, retention approval and its regulator-specific crosswalk.

## Which evidence belongs in Hrz5?

Durable, already-redacted execution and decision records belong here. Hrz4 owns model
promotion evidence, while Hrz7 owns the human review decision and its segregation-of-duties
workflow.

## Is local SQLite regulator-grade WORM?

No. It is a bounded append-only-by-API demo buffer and is not tamper-evident. The managed
profile's locked Cloud Logging bucket carries the current WORM guarantee.
