# Logging

This document describes how nannyagent emits logs, how to choose log levels, and what should or should not be surfaced to the CLI.

## Goals

The logging layer is designed to:

- keep normal agent output concise
- preserve enough detail for debugging when debug logging is enabled
- avoid printing raw AI or API payloads to the CLI on malformed input
- avoid spamming the console with one-off authentication failures that often recover automatically
- keep daemon mode suitable for syslog-only environments

## Levels

nannyagent uses four log levels:

- `DEBUG`: verbose internal diagnostics, request flow, raw payloads when needed for troubleshooting
- `INFO`: important lifecycle events and successful operator-visible actions
- `WARN`: transient failures or degraded behavior that may self-recover
- `ERROR`: persistent failures or operator action required

The logger reads `LOG_LEVEL` from the environment. Supported values are:

- `DEBUG`
- `INFO`
- `WARN` or `WARNING`
- `ERROR`

If `LOG_LEVEL` is not set, the default is `INFO`.

## Console vs Syslog

In normal interactive mode, logs are written to the console and syslog when syslog is available.

In daemon mode, nannyagent can switch to syslog-only output. This prevents duplicate console noise while still preserving structured severity prefixes in the logger.

## Repeated Failure Escalation

Not every failure should be printed loudly the first time it occurs.

For repeated failures, the logging package exposes a helper policy that surfaces a message:

- on the first visible threshold, currently attempt `3`
- again every `10` attempts after that

This is used for noisy authentication failure paths so the agent does not print token-expiry or refresh-token banners on the first transient problem. Until the threshold is reached, those events stay at `DEBUG`.

Use this pattern when:

- the failure is expected to self-recover
- retry is already in progress
- the operator cannot take a better action on the first occurrence

Do not use this pattern when:

- the process is about to exit
- user action is required immediately
- a security-sensitive operation failed and must be surfaced right away

## Payload Logging

Raw AI or API payloads should not be printed at `ERROR` or `WARN` level unless the payload itself is short, intentional, and safe to expose.

Preferred pattern:

- emit a generic `WARN` or `ERROR` message to the CLI
- keep the raw payload in `DEBUG` logs only

This keeps malformed JSON, markdown-wrapped blobs, or unexpected model output from polluting the console while preserving detail for diagnosis.

## Package Guidance

Use these conventions when adding new logs:

- `DEBUG` for retry attempts, raw payloads, and internal branch decisions
- `INFO` for successful registration, investigation execution, and other significant state transitions
- `WARN` for retryable network or parsing issues
- `ERROR` only for persistent failure or required operator action

Avoid:

- large banners for retryable failures
- logging the same error on every retry
- dumping full request or response bodies at non-debug levels
- mixing user-facing guidance with low-level transport details in the same message

## Tests

The logging package includes tests for:

- level parsing from `LOG_LEVEL`
- severity gating
- message formatting
- global and instance syslog-only behavior
- repeated-failure visibility policy

When changing logging behavior, add or update tests in `internal/logging/logger_test.go` and the owning package tests for the call sites that use the logger.
