//! Safe inline rich-text parsing and semantic span encoding.
//!
//! The supported syntax is deliberately small: `**strong**`, `*emphasis*`,
//! and `` `code` ``. Unmatched or unsupported syntax, including HTML, remains
//! literal text. Renderers consume plain text plus UTF-8 byte ranges; this
//! module never emits or interprets HTML.

use std::{error::Error, fmt, sync::Arc};

use lattice_protocol::Value;

use super::MAX_SPACE_PAYLOAD_BYTES;

pub const MAX_RICH_TEXT_SPANS: usize = 1_024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum RichTextStyle {
    Strong = 0,
    Emphasis = 1,
    Code = 2,
}

/// Half-open UTF-8 byte range in rendered text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RichTextSpan {
    pub start: u32,
    pub end: u32,
    pub style: RichTextStyle,
}

/// Plain display text and non-overlapping semantic style spans.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RichText {
    text: Arc<str>,
    spans: Vec<RichTextSpan>,
}

impl RichText {
    /// Parse the supported inline syntax; all unsupported markup stays literal.
    ///
    /// # Errors
    ///
    /// Returns an error if the source exceeds the Space payload bound or
    /// produces more than the supported number of semantic spans.
    pub fn parse(source: &str) -> Result<Self, RichTextError> {
        if source.len() > MAX_SPACE_PAYLOAD_BYTES {
            return Err(RichTextError::InputTooLarge);
        }
        let mut text = String::with_capacity(source.len());
        let mut spans = Vec::new();
        let mut cursor = 0;
        while cursor < source.len() {
            let remaining = &source[cursor..];
            if let Some(rest) = remaining.strip_prefix('\\')
                && let Some(escaped) = rest.chars().next()
                && matches!(escaped, '\\' | '*' | '`')
            {
                text.push(escaped);
                cursor += 1 + escaped.len_utf8();
                continue;
            }
            if let Some((marker, style)) = opening_marker(remaining) {
                let body_start = cursor + marker.len();
                if let Some(close) = find_closing_marker(source, body_start, marker, style) {
                    let body = &source[body_start..close];
                    if valid_body(body, marker, style) {
                        if spans.len() == MAX_RICH_TEXT_SPANS {
                            return Err(RichTextError::TooManySpans);
                        }
                        let start =
                            u32::try_from(text.len()).map_err(|_| RichTextError::InputTooLarge)?;
                        text.push_str(body);
                        let end =
                            u32::try_from(text.len()).map_err(|_| RichTextError::InputTooLarge)?;
                        spans.push(RichTextSpan { start, end, style });
                    } else {
                        text.push_str(&source[cursor..close + marker.len()]);
                    }
                    cursor = close + marker.len();
                    continue;
                }
                append_escaped_literal(remaining, &mut text);
                break;
            }
            let character = remaining
                .chars()
                .next()
                .ok_or(RichTextError::InputTooLarge)?;
            text.push(character);
            cursor += character.len_utf8();
        }
        Ok(Self {
            text: Arc::from(text),
            spans,
        })
    }

    /// Parse source text and require its canonical semantic spans to match wire data.
    ///
    /// # Errors
    ///
    /// Returns an error for an oversized source, excessive spans, or a wire
    /// span list that differs from the canonical parse.
    pub fn parse_with_spans(source: &str, encoded: &Value) -> Result<Self, RichTextError> {
        let parsed = Self::parse(source)?;
        if parsed.spans_value() != *encoded {
            return Err(RichTextError::InvalidWireSpans);
        }
        Ok(parsed)
    }

    /// Plain text suitable for display without an HTML or markup interpreter.
    #[must_use]
    pub fn render_plain_text(&self) -> &str {
        &self.text
    }

    /// Semantic spans in ascending rendered-text byte order.
    #[must_use]
    pub fn spans(&self) -> &[RichTextSpan] {
        &self.spans
    }

    /// Canonical wire value for semantic spans.
    #[must_use]
    pub fn spans_value(&self) -> Value {
        Value::Array(
            self.spans
                .iter()
                .map(|span| {
                    Value::Array(vec![
                        Value::Unsigned(span.style as u64),
                        Value::Unsigned(u64::from(span.start)),
                        Value::Unsigned(u64::from(span.end)),
                    ])
                })
                .collect(),
        )
    }

    /// Account for all independently retained derived content.
    #[must_use]
    pub fn retained_bytes(&self) -> usize {
        self.text.len().saturating_add(
            self.spans
                .len()
                .saturating_mul(std::mem::size_of::<RichTextSpan>()),
        )
    }
}

fn opening_marker(remaining: &str) -> Option<(&'static str, RichTextStyle)> {
    if remaining.starts_with("**") {
        Some(("**", RichTextStyle::Strong))
    } else if remaining.starts_with('*') {
        Some(("*", RichTextStyle::Emphasis))
    } else if remaining.starts_with('`') {
        Some(("`", RichTextStyle::Code))
    } else {
        None
    }
}

fn find_closing_marker(
    source: &str,
    start: usize,
    marker: &str,
    style: RichTextStyle,
) -> Option<usize> {
    let mut search_from = start;
    while let Some(relative) = source[search_from..].find(marker) {
        let close = search_from + relative;
        if style == RichTextStyle::Strong {
            let star_run = source.as_bytes()[close..]
                .iter()
                .take_while(|byte| **byte == b'*')
                .count();
            if star_run == 3 {
                search_from = close + marker.len();
                continue;
            }
        } else if style == RichTextStyle::Emphasis {
            let bytes = source.as_bytes();
            if (close > 0 && bytes[close - 1] == b'*')
                || (close + 1 < bytes.len() && bytes[close + 1] == b'*')
            {
                search_from = close + marker.len();
                continue;
            }
        }
        return Some(close);
    }
    None
}
fn append_escaped_literal(source: &str, output: &mut String) {
    let mut characters = source.chars().peekable();
    while let Some(character) = characters.next() {
        if character == '\\'
            && characters
                .peek()
                .is_some_and(|escaped| matches!(escaped, '\\' | '*' | '`'))
        {
            output.push(characters.next().expect("peeked escaped character"));
        } else {
            output.push(character);
        }
    }
}

fn valid_body(body: &str, marker: &str, style: RichTextStyle) -> bool {
    if body.is_empty() || body.contains('\n') || body.contains('\r') {
        return false;
    }
    if style != RichTextStyle::Code
        && (body.chars().next().is_some_and(char::is_whitespace)
            || body.chars().next_back().is_some_and(char::is_whitespace))
    {
        return false;
    }
    match style {
        RichTextStyle::Strong | RichTextStyle::Emphasis => !body.contains('*'),
        RichTextStyle::Code => !body.contains(marker),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RichTextError {
    InputTooLarge,
    TooManySpans,
    InvalidWireSpans,
}

impl fmt::Display for RichTextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InputTooLarge => "rich-text source exceeds the Space payload bound",
            Self::TooManySpans => "rich text exceeds the semantic span limit",
            Self::InvalidWireSpans => "rich-text semantic spans do not match their source",
        };
        formatter.write_str(message)
    }
}

impl Error for RichTextError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_only_supported_inline_styles_and_keeps_unsupported_markup_literal() {
        let parsed = RichText::parse("Hi **世界** *friend* `code` <script>alert(1)</script>")
            .expect("parse bounded inline text");
        assert_eq!(
            parsed.render_plain_text(),
            "Hi 世界 friend code <script>alert(1)</script>"
        );
        assert_eq!(
            parsed.spans(),
            &[
                RichTextSpan {
                    start: 3,
                    end: 9,
                    style: RichTextStyle::Strong,
                },
                RichTextSpan {
                    start: 10,
                    end: 16,
                    style: RichTextStyle::Emphasis,
                },
                RichTextSpan {
                    start: 17,
                    end: 21,
                    style: RichTextStyle::Code,
                },
            ]
        );
    }

    #[test]
    fn unmatched_nested_and_escaped_markers_are_safe_text() {
        let parsed = RichText::parse(r"**open *nested* \*literal\* <b>raw</b>")
            .expect("parse unsupported constructs as text");
        assert_eq!(
            parsed.render_plain_text(),
            "**open *nested* *literal* <b>raw</b>"
        );
        assert!(parsed.spans().is_empty());
    }

    #[test]
    fn semantic_wire_spans_must_match_reparsed_source() {
        let parsed = RichText::parse("**safe**").expect("parse strong span");
        assert_eq!(
            RichText::parse_with_spans("**safe**", &parsed.spans_value()).unwrap(),
            parsed
        );
        assert_eq!(
            RichText::parse_with_spans("**safe**", &Value::Array(Vec::new())),
            Err(RichTextError::InvalidWireSpans)
        );
    }

    #[test]
    fn input_and_span_budgets_fail_closed() {
        assert_eq!(
            RichText::parse(&"x".repeat(MAX_SPACE_PAYLOAD_BYTES + 1)),
            Err(RichTextError::InputTooLarge)
        );
        let many_spans = "**x**".repeat(MAX_RICH_TEXT_SPANS + 1);
        assert_eq!(
            RichText::parse(&many_spans),
            Err(RichTextError::TooManySpans)
        );
    }
}
