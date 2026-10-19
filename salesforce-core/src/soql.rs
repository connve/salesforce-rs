//! Helpers for building SOQL queries.
//!
//! The REST and Bulk APIs take SOQL as text and have no bind variables, so
//! values have to be written into the query as literals. These functions
//! write them so a value can't change the query.
//!
//! ```
//! use salesforce_core::chrono::{TimeZone, Utc};
//! use salesforce_core::soql;
//!
//! let query = format!(
//!     "SELECT Id FROM Contact WHERE LastName = {} AND Email LIKE {} \
//!      AND CreatedDate > {} AND Id IN {}",
//!     soql::quote("O'Brien"),
//!     soql::like_ends_with("@example.com"),
//!     soql::datetime(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()),
//!     soql::quote_list(["003xx0000000001", "003xx0000000002"]).unwrap(),
//! );
//! ```

use chrono::{DateTime, NaiveDate, Utc};

/// Quotes `value` as a SOQL string literal.
///
/// Escapes `\`, `'`, `"`, newline, carriage return, tab, backspace, and form
/// feed. In a `LIKE` expression, `%` and `_` in `value` still act as
/// wildcards; use [`like_contains`], [`like_starts_with`], or
/// [`like_ends_with`] to match them literally.
///
/// ```
/// use salesforce_core::soql;
///
/// let query = format!(
///     "SELECT Id FROM Contact WHERE LastName = {}",
///     soql::quote("O'Brien"),
/// );
/// assert_eq!(query, r"SELECT Id FROM Contact WHERE LastName = 'O\'Brien'");
/// ```
pub fn quote(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('\'');
    push_escaped(&mut quoted, value, false);
    quoted.push('\'');
    quoted
}

/// A `LIKE` pattern matching values that contain `value`.
///
/// ```
/// use salesforce_core::soql;
///
/// assert_eq!(soql::like_contains("50%"), r"'%50\%%'");
/// ```
pub fn like_contains(value: &str) -> String {
    like_pattern("%", value, "%")
}

/// A `LIKE` pattern matching values that start with `value`.
pub fn like_starts_with(value: &str) -> String {
    like_pattern("", value, "%")
}

/// A `LIKE` pattern matching values that end with `value`.
pub fn like_ends_with(value: &str) -> String {
    like_pattern("%", value, "")
}

/// Formats `values` as a list for `IN` or `NOT IN`, e.g. `('a', 'b')`.
///
/// Returns `None` when `values` is empty, since SOQL has no empty list.
///
/// ```
/// use salesforce_core::soql;
///
/// assert_eq!(soql::quote_list(["a", "b"]).as_deref(), Some("('a', 'b')"));
/// assert_eq!(soql::quote_list(Vec::<String>::new()), None);
/// ```
pub fn quote_list<I>(values: I) -> Option<String>
where
    I: IntoIterator,
    I::Item: AsRef<str>,
{
    let mut list = String::from("(");
    for (index, value) in values.into_iter().enumerate() {
        if index > 0 {
            list.push_str(", ");
        }
        list.push_str(&quote(value.as_ref()));
    }
    if list.len() == 1 {
        return None;
    }
    list.push(')');
    Some(list)
}

/// Formats `date` as a SOQL date literal, e.g. `2026-10-19`.
pub fn date(date: NaiveDate) -> String {
    date.format("%Y-%m-%d").to_string()
}

/// Formats `datetime` as a SOQL dateTime literal, e.g.
/// `2026-10-19T12:00:00Z`. Fractional seconds are dropped.
pub fn datetime(datetime: DateTime<Utc>) -> String {
    datetime.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn like_pattern(prefix: &str, value: &str, suffix: &str) -> String {
    let mut pattern = String::with_capacity(value.len() + 4);
    pattern.push('\'');
    pattern.push_str(prefix);
    push_escaped(&mut pattern, value, true);
    pattern.push_str(suffix);
    pattern.push('\'');
    pattern
}

/// The `\%` and `\_` escapes are only valid in `LIKE`, so they are written only
/// when `like` is set.
fn push_escaped(out: &mut String, value: &str, like: bool) {
    for c in value.chars() {
        match c {
            '\\' => out.push_str(r"\\"),
            '\'' => out.push_str(r"\'"),
            '"' => out.push_str(r#"\""#),
            '\n' => out.push_str(r"\n"),
            '\r' => out.push_str(r"\r"),
            '\t' => out.push_str(r"\t"),
            // Salesforce lists `\b` as "bell"; like Java, it reads it as
            // backspace (U+0008).
            '\u{8}' => out.push_str(r"\b"),
            '\u{c}' => out.push_str(r"\f"),
            '%' if like => out.push_str(r"\%"),
            '_' if like => out.push_str(r"\_"),
            c => out.push(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    /// One character of a parsed literal: matched as itself, or a `LIKE`
    /// wildcard.
    #[derive(Debug, Clone, PartialEq)]
    enum Piece {
        Lit(char),
        Wild(char),
    }

    /// Parses a SOQL string literal by the documented escape rules. Returns
    /// `None` for an unterminated literal, an unknown escape, or text after
    /// the closing quote.
    fn parse(literal: &str, like: bool) -> Option<Vec<Piece>> {
        let mut chars = literal.chars();
        if chars.next()? != '\'' {
            return None;
        }
        let mut pieces = Vec::new();
        while let Some(c) = chars.next() {
            match c {
                '\'' => return chars.next().is_none().then_some(pieces),
                '\\' => {
                    let unescaped = match chars.next()? {
                        'n' | 'N' => '\n',
                        'r' | 'R' => '\r',
                        't' | 'T' => '\t',
                        'b' | 'B' => '\u{8}',
                        'f' | 'F' => '\u{c}',
                        c @ ('"' | '\'' | '\\') => c,
                        c @ ('%' | '_') if like => c,
                        _ => return None,
                    };
                    pieces.push(Piece::Lit(unescaped));
                }
                c @ ('%' | '_') if like => pieces.push(Piece::Wild(c)),
                c => pieces.push(Piece::Lit(c)),
            }
        }
        None
    }

    fn literal(value: &str) -> Vec<Piece> {
        value.chars().map(Piece::Lit).collect()
    }

    /// Every ASCII character alone and together, plus injection attempts and
    /// non-ASCII text.
    fn samples() -> Vec<String> {
        let mut samples: Vec<String> = (0u8..=0x7f).map(|b| char::from(b).to_string()).collect();
        samples.push((0u8..=0x7f).map(char::from).collect());
        samples.extend(
            [
                "",
                r"x' OR Name != '",
                r"x\' OR Id != '",
                r"\\'",
                "50%_off",
                "Zażółć 😀",
            ]
            .map(String::from),
        );
        samples
    }

    #[test]
    fn test_quote_roundtrips() {
        for value in samples() {
            assert_eq!(
                parse(&quote(&value), false),
                Some(literal(&value)),
                "value {value:?}"
            );
        }
    }

    #[test]
    fn test_like_patterns_roundtrip() {
        let wild = Piece::Wild('%');
        for value in samples() {
            let lit = literal(&value);
            let contains = [vec![wild.clone()], lit.clone(), vec![wild.clone()]].concat();
            let starts_with = [lit.clone(), vec![wild.clone()]].concat();
            let ends_with = [vec![wild.clone()], lit].concat();
            assert_eq!(parse(&like_contains(&value), true), Some(contains));
            assert_eq!(parse(&like_starts_with(&value), true), Some(starts_with));
            assert_eq!(parse(&like_ends_with(&value), true), Some(ends_with));
        }
    }

    #[test]
    fn test_quote_escapes_each_sequence() {
        let cases = [
            ("\n", r"'\n'"),
            ("\r", r"'\r'"),
            ("\t", r"'\t'"),
            ("\u{8}", r"'\b'"),
            ("\u{c}", r"'\f'"),
            ("\"", r#"'\"'"#),
            ("'", r"'\''"),
            ("\\", r"'\\'"),
        ];
        for (value, expected) in cases {
            assert_eq!(quote(value), expected, "value {value:?}");
        }
    }

    #[test]
    fn test_quote_keeps_like_wildcards() {
        assert_eq!(quote("50%_off"), "'50%_off'");
    }

    #[test]
    fn test_like_escapes_wildcards() {
        assert_eq!(like_starts_with("50%_off"), r"'50\%\_off%'");
    }

    #[test]
    fn test_quote_list() {
        assert_eq!(
            quote_list(vec!["a".to_string(), "b'".to_string()]).as_deref(),
            Some(r"('a', 'b\'')")
        );
        assert_eq!(quote_list(["only"]).as_deref(), Some("('only')"));
        assert_eq!(quote_list(Vec::<&str>::new()), None);
    }

    #[test]
    fn test_date() {
        let value = NaiveDate::from_ymd_opt(2026, 1, 9).expect("valid date");
        assert_eq!(date(value), "2026-01-09");
    }

    #[test]
    fn test_datetime_drops_fractional_seconds() {
        let value = Utc
            .with_ymd_and_hms(2026, 10, 19, 7, 5, 3)
            .single()
            .expect("valid datetime")
            + chrono::Duration::milliseconds(250);
        assert_eq!(datetime(value), "2026-10-19T07:05:03Z");
    }
}
