//! Runs curl and condenses long output for human consumption.
//!
//! For pipes / redirects (non-TTY) and JSON bodies the full response is passed
//! through unchanged — truncating mid-stream would break downstream parsers.
//! The condensed-form-with-tee-hint path is reserved for non-JSON bodies on
//! a real terminal where a human reads the output and the tee file gives the
//! LLM a way to recover the raw response.

use crate::core::tee::force_tee_hint;
use crate::core::tracking;
use crate::core::{
    stream::exec_capture,
    utils::{check_forbidden_curl_args, secure_curl_command},
};
use anyhow::{Context, Result};
use std::borrow::Cow;
use std::io::IsTerminal;

const MAX_RESPONSE_SIZE: usize = 500;

pub fn run(args: &[String], verbose: u8) -> Result<i32> {
    let timer = tracking::TimedExecution::start();

    if let Err(msg) = check_forbidden_curl_args(args) {
        eprintln!("{}", msg);
        return Ok(2);
    }

    // `secure_curl_command` strips CURL_HOME so a tainted parent env can't
    // inject curl flags via .curlrc on every invocation. See issue #38.
    let mut cmd = secure_curl_command();
    cmd.arg("-s"); // Silent mode (no progress bar)

    for arg in args {
        cmd.arg(arg);
    }

    if verbose > 0 {
        eprintln!("Running: curl -s {}", args.join(" "));
    }

    let result = exec_capture(&mut cmd).context("Failed to run curl")?;

    // Skip filtering on failure: curl can return HTML error bodies that would
    // be misleading to summarize, and we want the real exit code surfaced.
    if !result.success() {
        let msg = if result.stderr.trim().is_empty() {
            result.stdout.trim().to_string()
        } else {
            result.stderr.trim().to_string()
        };
        eprintln!("FAILED: curl {}", msg);
        return Ok(result.exit_code);
    }

    let exit_code = result.exit_code;
    let raw = result.stdout;
    let is_tty = std::io::stdout().is_terminal();
    let filtered = filter_curl_output(&raw, is_tty);

    println!("{}", filtered.content);
    if let Some(hint) = &filtered.tee_hint {
        println!("{}", hint);
    }

    timer.track(
        &format!("curl {}", args.join(" ")),
        &format!("contextcrawler curl {}", args.join(" ")),
        &raw,
        &filtered.content,
    );

    Ok(exit_code)
}

fn filter_curl_output(raw: &str, is_tty: bool) -> FilterResult<'_> {
    let trimmed = raw.trim();

    // Heuristic: looks like a top-level JSON document. Numbers / booleans / null
    // are always under MAX_RESPONSE_SIZE so they don't need detection here.
    let looks_like_json = (trimmed.starts_with('{') && trimmed.ends_with('}'))
        || (trimmed.starts_with('[') && trimmed.ends_with(']'))
        || (trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2);

    // JSON bodies: minify losslessly rather than pass through whole. Re-serialised
    // JSON is still valid JSON (preserve_order keeps key ordering stable), so a
    // downstream `curl ... | jq` keeps working — unlike mid-stream truncation,
    // which is why #1536 left JSON untouched. If the body isn't strictly
    // parseable, or is already minimal, fall through to plain passthrough.
    if looks_like_json {
        return match minify_json(trimmed) {
            Some(min) => FilterResult {
                content: Cow::Owned(min),
                tee_hint: None,
            },
            None => FilterResult {
                content: Cow::Borrowed(trimmed),
                tee_hint: None,
            },
        };
    }

    // Pass through unchanged when:
    // - stdout is not a terminal (pipes / redirects need the full body, #1282)
    // - body fits under the truncation threshold
    //
    // Critically, do NOT call `force_tee_hint` on this path — it has a side effect
    // (writes the raw body to a tee log file) and we don't need a recovery file
    // when the consumer already receives the full body.
    if !is_tty || trimmed.len() < MAX_RESPONSE_SIZE {
        return FilterResult {
            content: Cow::Borrowed(trimmed),
            tee_hint: None,
        };
    }

    // We're about to truncate for a human reader. Write a tee file so they (or
    // the LLM in their stead) can recover the full body from the printed hint.
    let Some(hint) = force_tee_hint(raw, "curl") else {
        // Tee disabled (RTK_TEE=0 or below MIN_TEE_SIZE): we have nowhere to
        // point a recovery hint to, so pass through rather than emit an
        // unrecoverable truncation marker.
        return FilterResult {
            content: Cow::Borrowed(trimmed),
            tee_hint: None,
        };
    };

    let mut end = MAX_RESPONSE_SIZE;
    // Don't cut in the middle of a UTF-8 character — .len() counts bytes.
    while !trimmed.is_char_boundary(end) {
        end -= 1;
    }
    FilterResult {
        content: Cow::Owned(format!(
            "{}... ({} bytes total)",
            &trimmed[..end],
            trimmed.len()
        )),
        tee_hint: Some(hint),
    }
}

struct FilterResult<'a> {
    content: Cow<'a, str>,
    tee_hint: Option<String>,
}

/// Losslessly minify a JSON body: parse and re-serialise without whitespace.
///
/// Returns `None` when the body isn't strictly-valid JSON (so the caller passes
/// it through untouched rather than risk corrupting it) or when minifying would
/// not shrink it (already-compact input — avoids a needless allocation and a
/// `Cow::Owned` clone of a multi-MB body).
fn minify_json(raw: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(raw).ok()?;
    let minified = serde_json::to_string(&value).ok()?;
    if minified.len() < raw.len() {
        Some(minified)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_curl_json_small_no_tee_hint() {
        let output = r#"{"r2Ready":true,"status":"ok"}"#;
        let result = filter_curl_output(output, true);
        assert_eq!(&*result.content, output);
        assert!(result.tee_hint.is_none());
    }

    #[test]
    fn test_filter_curl_non_json() {
        let output = "Hello, World!\nThis is plain text.";
        let result = filter_curl_output(output, true);
        assert_eq!(&*result.content, output);
    }

    #[test]
    fn test_filter_curl_long_output_truncated() {
        let long: String = "x".repeat(1000);
        let result = filter_curl_output(&long, true);
        assert!(result.content.starts_with('x'));
        assert!(result.content.contains("bytes total"));
        assert!(result.content.contains("1000"));
        assert!(result.content.len() < 600);
        assert!(result.tee_hint.is_some(), "TTY truncation must emit a hint");
    }

    #[test]
    fn test_filter_curl_multibyte_boundary() {
        let content = "a".repeat(499) + "é";
        let result = filter_curl_output(&content, true);
        assert!(result.content.contains("bytes total"));
        assert!(result.content.len() < 600);
    }

    #[test]
    fn test_filter_curl_exact_500_bytes() {
        let content = "a".repeat(500);
        let result = filter_curl_output(&content, true);
        assert!(result.content.contains("bytes total"));
    }

    // --- #1536: large JSON must remain parseable for downstream tools ---

    #[test]
    fn test_filter_curl_large_json_object_passthrough() {
        let payload = "x".repeat(600);
        let json = format!(r#"{{"data":"{}"}}"#, payload);
        let result = filter_curl_output(&json, true);
        assert!(!result.content.contains("bytes total"));
        assert!(result.content.starts_with('{'));
        assert!(result.content.ends_with('}'));
        assert!(result.tee_hint.is_none());
    }

    #[test]
    fn test_filter_curl_large_json_array_passthrough() {
        let body = (0..50)
            .map(|i| format!(r#"{{"id":{},"name":"item-{:04}"}}"#, i, i))
            .collect::<Vec<_>>()
            .join(",");
        let json = format!("[{}]", body);
        assert!(
            json.len() >= MAX_RESPONSE_SIZE,
            "fixture must exceed cap, got {}",
            json.len()
        );
        let result = filter_curl_output(&json, true);
        assert!(!result.content.contains("bytes total"));
        assert!(result.content.starts_with('['));
        assert!(result.content.ends_with(']'));
    }

    #[test]
    fn test_filter_curl_large_json_bare_string_passthrough() {
        // Bare top-level JSON string — e.g. an /api/token endpoint returning "<long-token>".
        let token = "z".repeat(800);
        let json = format!(r#""{}""#, token);
        let result = filter_curl_output(&json, true);
        assert!(!result.content.contains("bytes total"));
        assert!(result.content.starts_with('"'));
        assert!(result.content.ends_with('"'));
    }

    // --- #1282: pipes / redirects (non-TTY) must receive full body ---

    #[test]
    fn test_filter_curl_pipe_no_truncation_for_non_json() {
        let long: String = "x".repeat(1000);
        let result = filter_curl_output(&long, false);
        assert!(!result.content.contains("bytes total"));
        assert_eq!(result.content.len(), 1000);
        assert!(result.tee_hint.is_none());
    }

    #[test]
    fn test_filter_curl_pipe_no_truncation_for_json() {
        let payload = "y".repeat(600);
        let json = format!(r#"{{"data":"{}"}}"#, payload);
        let result = filter_curl_output(&json, false);
        assert!(!result.content.contains("bytes total"));
        assert!(result.content.ends_with('}'));
        assert!(result.tee_hint.is_none());
    }

    // --- Tier 1: lossless JSON minification ---

    #[test]
    fn test_filter_curl_pretty_json_is_minified() {
        // Pretty-printed JSON in → minified, still valid, smaller.
        let pretty = "{\n  \"a\": 1,\n  \"b\": [\n    1,\n    2,\n    3\n  ]\n}";
        let result = filter_curl_output(pretty, true);
        assert_eq!(&*result.content, r#"{"a":1,"b":[1,2,3]}"#);
        assert!(result.content.len() < pretty.len());
        assert!(result.tee_hint.is_none());
        // Output must round-trip as valid JSON (the whole point vs truncation).
        assert!(serde_json::from_str::<serde_json::Value>(&result.content).is_ok());
    }

    #[test]
    fn test_filter_curl_pretty_json_minified_on_pipe_too() {
        // Minification is lossless, so it applies on non-TTY (pipe to jq) as
        // well — jq receives valid, smaller JSON.
        let pretty = "[\n  {\n    \"id\": 1\n  }\n]";
        let result = filter_curl_output(pretty, false);
        assert_eq!(&*result.content, r#"[{"id":1}]"#);
        assert!(serde_json::from_str::<serde_json::Value>(&result.content).is_ok());
    }

    #[test]
    fn test_filter_curl_already_minified_json_passthrough_borrowed() {
        // Already-compact JSON: minify_json returns None → borrowed passthrough,
        // no needless allocation.
        let compact = r#"{"a":1,"b":[1,2,3]}"#;
        let result = filter_curl_output(compact, true);
        assert_eq!(&*result.content, compact);
        assert!(matches!(result.content, Cow::Borrowed(_)));
    }

    #[test]
    fn test_filter_curl_malformed_json_passthrough() {
        // Looks JSON-ish (starts { ends }) but isn't valid → must pass through
        // untouched rather than risk corrupting it.
        let bad = "{not: valid, json at all}";
        let result = filter_curl_output(bad, true);
        assert_eq!(&*result.content, bad);
        assert!(matches!(result.content, Cow::Borrowed(_)));
    }

    #[test]
    fn test_filter_curl_minified_json_preserves_key_order() {
        // serde_json `preserve_order` feature keeps keys in source order.
        let pretty = "{\n  \"zebra\": 1,\n  \"apple\": 2,\n  \"mango\": 3\n}";
        let result = filter_curl_output(pretty, true);
        assert_eq!(&*result.content, r#"{"zebra":1,"apple":2,"mango":3}"#);
    }

    // --- Cow optimization: passthrough must not allocate ---

    #[test]
    fn test_filter_curl_passthrough_is_borrowed() {
        // Passthrough paths return Cow::Borrowed to avoid copying multi-MB bodies.
        let pipe_payload = "x".repeat(2000);
        let pipe_result = filter_curl_output(&pipe_payload, false);
        assert!(matches!(pipe_result.content, Cow::Borrowed(_)));

        let json_payload = format!(r#"[{}]"#, "1,".repeat(300));
        let json_result = filter_curl_output(&json_payload, true);
        assert!(matches!(json_result.content, Cow::Borrowed(_)));
    }
}
