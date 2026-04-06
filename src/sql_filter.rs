//! SQL expression parser for packet filters.
//!
//! Converts SQL WHERE-clause expressions into [`FilterExpr`] trees using
//! the `sqlparser` crate.  The `packet_number` identifier is treated as a
//! virtual column for pre-dissection packet-number filtering.
//!
//! # Examples
//!
//! ```text
//! tcp AND ipv4.src = '10.0.0.1'
//! tcp.dst_port > 1024
//! (tcp OR udp) AND NOT dns
//! packet_number BETWEEN 1 AND 100
//! ```

use sqlparser::ast::{BinaryOperator, Expr, UnaryOperator, Value};
use sqlparser::dialect::GenericDialect;
use sqlparser::parser::Parser;
use sqlparser::tokenizer::Token;

use crate::filter::{CompareOp, PacketNumberFilter, WhereClause, normalize_protocol_name};
use crate::filter_expr::FilterExpr;

/// Virtual column name for packet-number filtering.
const PACKET_NUMBER_COL: &str = "packet_number";

/// Parse a SQL expression string into a [`FilterExpr`].
///
/// The input should be the body of a WHERE clause (without the `WHERE`
/// keyword).  Supports `AND`, `OR`, `NOT`, parentheses, comparison operators
/// (`=`, `!=`/`<>`, `>`, `<`, `>=`, `<=`), `BETWEEN`, `IN`, and bare
/// identifiers as protocol existence checks.
pub fn parse(input: &str) -> Result<FilterExpr, String> {
    let dialect = GenericDialect {};
    let mut parser = Parser::new(&dialect)
        .try_with_sql(input)
        .map_err(|e| format!("SQL parse error: {e}"))?;
    let expr = parser
        .parse_expr()
        .map_err(|e| format!("SQL parse error: {e}"))?;

    // Ensure the entire input was consumed.
    if parser.peek_token().token != Token::EOF {
        return Err(format!(
            "unexpected trailing input after expression: {}",
            input
        ));
    }

    convert_expr(&expr)
}

/// Wrap an expression in `NOT` when `negated` is true.
fn maybe_negate(expr: FilterExpr, negated: bool) -> FilterExpr {
    if negated {
        FilterExpr::Not(Box::new(expr))
    } else {
        expr
    }
}

/// Recursively convert a `sqlparser` AST expression into a [`FilterExpr`].
fn convert_expr(expr: &Expr) -> Result<FilterExpr, String> {
    match expr {
        Expr::BinaryOp { left, op, right } => convert_binary_op(left, op, right),

        Expr::UnaryOp {
            op: UnaryOperator::Not,
            expr: inner,
        } => {
            let inner = convert_expr(inner)?;
            Ok(FilterExpr::Not(Box::new(inner)))
        }

        Expr::Nested(inner) => convert_expr(inner),

        Expr::Identifier(ident) => Ok(FilterExpr::Protocol(normalize_protocol_name(&ident.value))),

        // Compound identifier without comparison → protocol existence check.
        Expr::CompoundIdentifier(parts) if !parts.is_empty() => Ok(FilterExpr::Protocol(
            normalize_protocol_name(&parts[0].value),
        )),

        Expr::Between {
            expr: inner,
            negated,
            low,
            high,
        } => convert_between(inner, *negated, low, high),

        Expr::InList {
            expr: inner,
            list,
            negated,
        } => convert_in_list(inner, list, *negated),

        Expr::Value(val) => match &val.value {
            Value::Boolean(true) => Err("bare TRUE is not supported as a filter".into()),
            Value::Boolean(false) => Err("bare FALSE is not supported as a filter".into()),
            _ => Err(format!("unsupported SQL expression: {expr}")),
        },

        _ => Err(format!("unsupported SQL expression: {expr}")),
    }
}

/// Convert a binary operator expression.
fn convert_binary_op(left: &Expr, op: &BinaryOperator, right: &Expr) -> Result<FilterExpr, String> {
    match op {
        BinaryOperator::And => {
            let l = convert_expr(left)?;
            let r = convert_expr(right)?;
            Ok(FilterExpr::And(Box::new(l), Box::new(r)))
        }
        BinaryOperator::Or => {
            let l = convert_expr(left)?;
            let r = convert_expr(right)?;
            Ok(FilterExpr::Or(Box::new(l), Box::new(r)))
        }
        BinaryOperator::Eq
        | BinaryOperator::NotEq
        | BinaryOperator::Lt
        | BinaryOperator::LtEq
        | BinaryOperator::Gt
        | BinaryOperator::GtEq => convert_comparison(left, op, right),
        _ => Err(format!("unsupported operator: {op}")),
    }
}

/// Convert a comparison expression (e.g. `ipv4.src = '10.0.0.1'`).
fn convert_comparison(
    left: &Expr,
    op: &BinaryOperator,
    right: &Expr,
) -> Result<FilterExpr, String> {
    let compare_op = match op {
        BinaryOperator::Eq => CompareOp::Eq,
        BinaryOperator::NotEq => CompareOp::Ne,
        BinaryOperator::Lt => CompareOp::Lt,
        BinaryOperator::LtEq => CompareOp::Le,
        BinaryOperator::Gt => CompareOp::Gt,
        BinaryOperator::GtEq => CompareOp::Ge,
        _ => return Err(format!("unsupported comparison operator: {op}")),
    };

    let (name, field) = extract_field_ref(left)?;
    let value = extract_value(right)?;

    if name == PACKET_NUMBER_COL && field.is_none() {
        let n: u64 = value
            .parse()
            .map_err(|_| format!("packet_number requires an integer value, got '{value}'"))?;
        return convert_packet_number_comparison(compare_op, n);
    }

    let field = field.ok_or_else(|| {
        format!("comparison requires protocol.field format on left side, got '{name}'")
    })?;

    Ok(FilterExpr::Where(WhereClause::new(
        name, field, compare_op, value,
    )))
}

/// Convert a packet_number comparison into a [`FilterExpr::PacketNumber`].
fn convert_packet_number_comparison(op: CompareOp, n: u64) -> Result<FilterExpr, String> {
    let pnf = match op {
        CompareOp::Eq => PacketNumberFilter::from_ranges(vec![(n, n)]),
        CompareOp::Ge => PacketNumberFilter::from_ranges(vec![(n, u64::MAX)]),
        CompareOp::Gt => {
            if n == u64::MAX {
                return Err("packet_number > u64::MAX is always false".into());
            }
            PacketNumberFilter::from_ranges(vec![(n + 1, u64::MAX)])
        }
        CompareOp::Le => PacketNumberFilter::from_ranges(vec![(1, n)]),
        CompareOp::Lt => {
            if n <= 1 {
                return Err(
                    "packet_number < 1 is always false (packet numbers are 1-based)".into(),
                );
            }
            PacketNumberFilter::from_ranges(vec![(1, n - 1)])
        }
        CompareOp::Ne => {
            // NOT packet_number = N
            return Ok(FilterExpr::Not(Box::new(FilterExpr::PacketNumber(
                PacketNumberFilter::from_ranges(vec![(n, n)]),
            ))));
        }
    };
    Ok(FilterExpr::PacketNumber(pnf))
}

/// Extract a `(name, field)` pair from the left side of a comparison.
///
/// - `Identifier("packet_number")` → `("packet_number", None)`
/// - `CompoundIdentifier(["ipv4", "src"])` → `("ipv4", Some("src"))`
fn extract_field_ref(expr: &Expr) -> Result<(String, Option<String>), String> {
    match expr {
        Expr::Identifier(ident) => Ok((ident.value.clone(), None)),
        Expr::CompoundIdentifier(parts) if parts.len() == 2 => {
            Ok((parts[0].value.clone(), Some(parts[1].value.clone())))
        }
        Expr::CompoundIdentifier(parts) if parts.len() > 2 => {
            let protocol = parts[0].value.clone();
            let field = parts[1..]
                .iter()
                .map(|p| p.value.as_str())
                .collect::<Vec<_>>()
                .join(".");
            Ok((protocol, Some(field)))
        }
        _ => Err(format!(
            "expected field reference (protocol.field) on left side of comparison, got: {expr}"
        )),
    }
}

/// Extract a string value from the right side of a comparison.
fn extract_value(expr: &Expr) -> Result<String, String> {
    match expr {
        Expr::Value(val) => match &val.value {
            Value::SingleQuotedString(s) => Ok(s.clone()),
            Value::DoubleQuotedString(s) => Ok(s.clone()),
            Value::Number(s, _) => Ok(s.clone()),
            _ => Err(format!("unsupported value type: {}", val.value)),
        },
        Expr::UnaryOp {
            op: UnaryOperator::Minus,
            expr: inner,
        } => {
            // Handle negative numbers: -1 → "-1"
            let v = extract_value(inner)?;
            Ok(format!("-{v}"))
        }
        _ => Err(format!("expected a literal value, got: {expr}")),
    }
}

/// Convert a `BETWEEN` expression.
fn convert_between(
    inner: &Expr,
    negated: bool,
    low: &Expr,
    high: &Expr,
) -> Result<FilterExpr, String> {
    let (name, field) = extract_field_ref(inner)?;
    let low_val = extract_value(low)?;
    let high_val = extract_value(high)?;

    if name == PACKET_NUMBER_COL && field.is_none() {
        let lo: u64 = low_val
            .parse()
            .map_err(|_| format!("packet_number BETWEEN requires integers, got '{low_val}'"))?;
        let hi: u64 = high_val
            .parse()
            .map_err(|_| format!("packet_number BETWEEN requires integers, got '{high_val}'"))?;
        let expr = FilterExpr::PacketNumber(PacketNumberFilter::from_ranges(vec![(lo, hi)]));
        return Ok(maybe_negate(expr, negated));
    }

    let field = field.ok_or_else(|| {
        format!("BETWEEN requires protocol.field format on left side, got '{name}'")
    })?;
    let ge = FilterExpr::Where(WhereClause::new(
        name.clone(),
        field.clone(),
        CompareOp::Ge,
        low_val,
    ));
    let le = FilterExpr::Where(WhereClause::new(name, field, CompareOp::Le, high_val));
    let expr = FilterExpr::And(Box::new(ge), Box::new(le));
    Ok(maybe_negate(expr, negated))
}

/// Convert an `IN` list expression.
fn convert_in_list(inner: &Expr, list: &[Expr], negated: bool) -> Result<FilterExpr, String> {
    let (name, field) = extract_field_ref(inner)?;

    if name == PACKET_NUMBER_COL && field.is_none() {
        let mut ranges = Vec::with_capacity(list.len());
        for item in list {
            let val = extract_value(item)?;
            let n: u64 = val
                .parse()
                .map_err(|_| format!("packet_number IN requires integers, got '{val}'"))?;
            ranges.push((n, n));
        }
        let expr = FilterExpr::PacketNumber(PacketNumberFilter::from_ranges(ranges));
        return Ok(maybe_negate(expr, negated));
    }

    if list.is_empty() {
        return Err("IN list must not be empty".into());
    }
    let field = field
        .ok_or_else(|| format!("IN requires protocol.field format on left side, got '{name}'"))?;
    let mut exprs: Vec<FilterExpr> = Vec::with_capacity(list.len());
    for item in list {
        let val = extract_value(item)?;
        exprs.push(FilterExpr::Where(WhereClause::new(
            name.clone(),
            field.clone(),
            CompareOp::Eq,
            val,
        )));
    }
    let mut result = exprs.remove(0);
    for e in exprs {
        result = FilterExpr::Or(Box::new(result), Box::new(e));
    }
    Ok(maybe_negate(result, negated))
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet_dissector_core::field::FieldValue;
    use packet_dissector_core::packet::{DissectBuffer, Packet};
    use packet_dissector_test_alloc::test_desc;

    fn make_buf(
        name: &'static str,
        fields: &[(&'static str, FieldValue<'static>)],
    ) -> DissectBuffer<'static> {
        let mut buf = DissectBuffer::new();
        buf.begin_layer(name, None, &[], 0..0);
        for (fname, fval) in fields {
            buf.push_field(test_desc(fname, fname), fval.clone(), 0..0);
        }
        buf.end_layer();
        buf
    }

    fn make_tcp_ipv4_buf() -> DissectBuffer<'static> {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("IPv4", None, &[], 0..0);
        buf.push_field(
            test_desc("src", "Source"),
            FieldValue::Ipv4Addr([10, 0, 0, 1]),
            0..0,
        );
        buf.end_layer();
        buf.begin_layer("TCP", None, &[], 0..0);
        buf.push_field(
            test_desc("dst_port", "Destination Port"),
            FieldValue::U16(8080),
            0..0,
        );
        buf.end_layer();
        buf
    }

    static EMPTY_DATA: [u8; 0] = [];

    fn pkt_from<'a>(buf: &'a DissectBuffer<'static>) -> Packet<'a, 'static> {
        Packet::new(buf, &EMPTY_DATA)
    }

    // --- Basic comparisons ---

    #[test]
    fn eq_string() {
        let expr = parse("ipv4.src = '10.0.0.1'").unwrap();
        let buf = make_tcp_ipv4_buf();
        assert!(expr.matches(&pkt_from(&buf)));
    }

    #[test]
    fn eq_number() {
        let expr = parse("tcp.dst_port = 8080").unwrap();
        let buf = make_tcp_ipv4_buf();
        assert!(expr.matches(&pkt_from(&buf)));
    }

    #[test]
    fn gt_number() {
        let expr = parse("tcp.dst_port > 80").unwrap();
        let buf = make_tcp_ipv4_buf();
        assert!(expr.matches(&pkt_from(&buf)));
    }

    #[test]
    fn lt_number() {
        let expr = parse("tcp.dst_port < 9000").unwrap();
        let buf = make_tcp_ipv4_buf();
        assert!(expr.matches(&pkt_from(&buf)));
    }

    #[test]
    fn ne_number() {
        let expr = parse("tcp.dst_port != 80").unwrap();
        let buf = make_tcp_ipv4_buf();
        assert!(expr.matches(&pkt_from(&buf)));
    }

    #[test]
    fn ne_sqlstyle() {
        let expr = parse("tcp.dst_port <> 80").unwrap();
        let buf = make_tcp_ipv4_buf();
        assert!(expr.matches(&pkt_from(&buf)));
    }

    // --- Protocol existence ---

    #[test]
    fn protocol_exists() {
        let expr = parse("tcp").unwrap();
        let buf = make_tcp_ipv4_buf();
        assert!(expr.matches(&pkt_from(&buf)));
    }

    #[test]
    fn protocol_not_exists() {
        let expr = parse("dns").unwrap();
        let buf = make_tcp_ipv4_buf();
        assert!(!expr.matches(&pkt_from(&buf)));
    }

    // --- Boolean operators ---

    #[test]
    fn and_expr() {
        let expr = parse("tcp AND ipv4.src = '10.0.0.1'").unwrap();
        let buf = make_tcp_ipv4_buf();
        assert!(expr.matches(&pkt_from(&buf)));
    }

    #[test]
    fn or_expr() {
        let expr = parse("dns OR tcp").unwrap();
        let buf = make_tcp_ipv4_buf();
        assert!(expr.matches(&pkt_from(&buf)));
    }

    #[test]
    fn not_expr() {
        let expr = parse("NOT dns").unwrap();
        let buf = make_tcp_ipv4_buf();
        assert!(expr.matches(&pkt_from(&buf)));
    }

    // --- Parentheses ---

    #[test]
    fn parentheses() {
        let expr = parse("(tcp OR dns) AND ipv4.src = '10.0.0.1'").unwrap();
        let buf = make_tcp_ipv4_buf();
        assert!(expr.matches(&pkt_from(&buf)));
    }

    #[test]
    fn nested_parentheses() {
        let expr = parse("NOT (dns AND (tcp OR udp))").unwrap();
        let buf = make_tcp_ipv4_buf();
        assert!(expr.matches(&pkt_from(&buf)));
    }

    // --- packet_number virtual column ---

    #[test]
    fn packet_number_eq() {
        let expr = parse("packet_number = 5").unwrap();
        let buf = make_tcp_ipv4_buf();
        assert!(expr.matches_with_number(&pkt_from(&buf), 5));
        assert!(!expr.matches_with_number(&pkt_from(&buf), 4));
    }

    #[test]
    fn packet_number_between() {
        let expr = parse("packet_number BETWEEN 10 AND 20").unwrap();
        let buf = make_tcp_ipv4_buf();
        assert!(expr.matches_with_number(&pkt_from(&buf), 10));
        assert!(expr.matches_with_number(&pkt_from(&buf), 15));
        assert!(expr.matches_with_number(&pkt_from(&buf), 20));
        assert!(!expr.matches_with_number(&pkt_from(&buf), 9));
        assert!(!expr.matches_with_number(&pkt_from(&buf), 21));
    }

    #[test]
    fn packet_number_in() {
        let expr = parse("packet_number IN (1, 5, 10)").unwrap();
        let buf = make_tcp_ipv4_buf();
        assert!(expr.matches_with_number(&pkt_from(&buf), 1));
        assert!(expr.matches_with_number(&pkt_from(&buf), 5));
        assert!(expr.matches_with_number(&pkt_from(&buf), 10));
        assert!(!expr.matches_with_number(&pkt_from(&buf), 3));
    }

    #[test]
    fn packet_number_gt() {
        let expr = parse("packet_number > 100").unwrap();
        let buf = make_tcp_ipv4_buf();
        assert!(expr.matches_with_number(&pkt_from(&buf), 101));
        assert!(!expr.matches_with_number(&pkt_from(&buf), 100));
    }

    #[test]
    fn packet_number_combined_with_protocol() {
        let expr = parse("packet_number BETWEEN 1 AND 100 AND tcp").unwrap();
        let buf = make_tcp_ipv4_buf();
        assert!(expr.matches_with_number(&pkt_from(&buf), 50));
        assert!(!expr.matches_with_number(&pkt_from(&buf), 150));
    }

    #[test]
    fn packet_number_only_detection() {
        let pn = parse("packet_number BETWEEN 1 AND 100").unwrap();
        assert!(pn.is_packet_number_only());

        let mixed = parse("packet_number = 1 AND tcp").unwrap();
        assert!(!mixed.is_packet_number_only());
    }

    // --- BETWEEN for fields ---

    #[test]
    fn field_between() {
        let expr = parse("tcp.dst_port BETWEEN 8000 AND 9000").unwrap();
        let buf = make_tcp_ipv4_buf();
        assert!(expr.matches(&pkt_from(&buf)));
    }

    #[test]
    fn field_between_out_of_range() {
        let expr = parse("tcp.dst_port BETWEEN 1 AND 80").unwrap();
        let buf = make_tcp_ipv4_buf();
        assert!(!expr.matches(&pkt_from(&buf)));
    }

    // --- IN for fields ---

    #[test]
    fn field_in_list() {
        let expr = parse("tcp.dst_port IN (80, 443, 8080)").unwrap();
        let buf = make_tcp_ipv4_buf();
        assert!(expr.matches(&pkt_from(&buf)));
    }

    #[test]
    fn field_in_list_no_match() {
        let expr = parse("tcp.dst_port IN (80, 443)").unwrap();
        let buf = make_tcp_ipv4_buf();
        assert!(!expr.matches(&pkt_from(&buf)));
    }

    // --- Negative numbers ---

    #[test]
    fn negative_number() {
        let expr = parse("test.val > -1").unwrap();
        let buf = make_buf("Test", &[("val", FieldValue::I32(0))]);
        assert!(expr.matches(&pkt_from(&buf)));
    }

    // --- Error cases ---

    #[test]
    fn empty_input_errors() {
        // Empty input will be caught by sqlparser
        assert!(parse("").is_err());
    }

    #[test]
    fn invalid_syntax() {
        assert!(parse("AND AND").is_err());
    }

    #[test]
    fn trailing_input() {
        assert!(parse("tcp extra_stuff").is_err());
    }

    // --- Nested field ---

    #[test]
    fn nested_field() {
        let expr = parse("dns.questions.name = 'example.com'").unwrap();
        let mut buf = DissectBuffer::new();
        buf.begin_layer("DNS", None, &[], 0..0);
        let arr = buf.begin_container(
            test_desc("questions", "Questions"),
            FieldValue::Array(0..0),
            0..0,
        );
        let obj = buf.begin_container(test_desc("q", "Q"), FieldValue::Object(0..0), 0..0);
        buf.push_field(
            test_desc("name", "Name"),
            FieldValue::Str("example.com"),
            0..0,
        );
        buf.end_container(obj);
        buf.end_container(arr);
        buf.end_layer();
        assert!(expr.matches(&pkt_from(&buf)));
    }
}
