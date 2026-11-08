//! Requests and their results, per protocol, read from the protocol
//! statistics of [`StatsOutput`]: how many requests were sent, how they were
//! answered (result codes, errors, no answer) and how fast.

use serde::Deserialize as _;
use serde_json::Value;

use crate::stats::{ResponseTimeStats, StatsOutput};

/// One way requests of a protocol ended.
#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    /// What happened (`"200"`, `"NXDOMAIN"`, `"No response"`).
    pub label: String,
    /// Messages with this outcome.
    pub count: u64,
    /// Whether the outcome is a failure.
    pub error: bool,
    /// A display filter for the messages with this outcome, when one can
    /// be written.
    pub filter: Option<String>,
}

/// The requests of one protocol and how they ended.
#[derive(Debug, Clone, PartialEq)]
pub struct Responses {
    /// Protocol short name (`"SIP"`).
    pub protocol: &'static str,
    pub requests: u64,
    pub responses: u64,
    /// Most frequent first; "No response" last.
    pub outcomes: Vec<Outcome>,
    /// Time from each request to its response, when the protocol's
    /// statistics match them.
    pub response_time: Option<ResponseTimeStats>,
}

/// The protocols in `stats` that send requests, and how those ended.
pub fn responses(stats: &StatsOutput) -> Vec<Responses> {
    let mut out = Vec::new();
    let get = |name: &str| stats.protocol_stats.get(name);
    if let Some(dns) = get("dns") {
        out.push(summarize(
            "DNS",
            dns,
            ("total_queries", "total_responses", "rcode_distribution"),
            |name| name != "NOERROR",
            |name| Some(format!("dns.qr = 1 and dns.rcode_name = '{name}'")),
        ));
    }
    if let Some(sip) = get("sip") {
        out.push(summarize(
            "SIP",
            sip,
            (
                "total_requests",
                "total_responses",
                "status_code_distribution",
            ),
            |code| code.parse::<u16>().is_ok_and(|c| c >= 400),
            |code| numeric(code).map(|c| format!("sip.status_code = {c}")),
        ));
    }
    if let Some(http) = get("http") {
        out.push(summarize(
            "HTTP",
            http,
            (
                "total_requests",
                "total_responses",
                "status_code_distribution",
            ),
            |code| code.parse::<u16>().is_ok_and(|c| c >= 400),
            |code| numeric(code).map(|c| format!("http.status_code = {c}")),
        ));
    }
    if let Some(diameter) = get("diameter") {
        // RFC 6733, Section 7.1: 1xxx informational, 2xxx success, 3xxx
        // protocol errors, 4xxx transient and 5xxx permanent failures.
        out.push(summarize(
            "Diameter",
            diameter,
            (
                "total_requests",
                "total_answers",
                "result_code_distribution",
            ),
            |name| match name.parse::<u32>() {
                Ok(code) => code >= 3000,
                Err(_) => !name.contains("SUCCESS"),
            },
            // The code is one of the message's AVPs, which a filter
            // cannot tie to its value.
            |_| None,
        ));
    }
    out.retain(|r| r.requests > 0 || r.responses > 0);
    out
}

fn numeric(code: &str) -> Option<u32> {
    code.parse().ok()
}

fn summarize(
    protocol: &'static str,
    stats: &Value,
    (requests_key, responses_key, codes_key): (&str, &str, &str),
    is_error: impl Fn(&str) -> bool,
    filter: impl Fn(&str) -> Option<String>,
) -> Responses {
    let count = |key: &str| stats.get(key).and_then(Value::as_u64).unwrap_or(0);
    let requests = count(requests_key);
    let responses = count(responses_key);
    let mut outcomes: Vec<Outcome> = stats
        .get(codes_key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            let label = entry.get("name")?.as_str()?.to_string();
            let count = entry.get("count")?.as_u64()?;
            Some(Outcome {
                error: is_error(&label),
                filter: filter(&label),
                label,
                count,
            })
        })
        .collect();
    if requests > responses {
        outcomes.push(Outcome {
            label: "No response".to_string(),
            count: requests - responses,
            error: true,
            filter: None,
        });
    }
    let response_time = stats
        .get("response_time")
        .and_then(|v| ResponseTimeStats::deserialize(v).ok());
    Responses {
        protocol,
        requests,
        responses,
        outcomes,
        response_time,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde_json::json;

    use super::*;

    fn stats(protocol_stats: HashMap<String, Value>) -> StatsOutput {
        StatsOutput {
            record_type: "stats".to_string(),
            total_packets: 10,
            time_start: None,
            time_end: None,
            duration_secs: 1.0,
            protocols: HashMap::new(),
            protocol_stats,
            top_talkers: None,
            tcp_streams: None,
        }
    }

    #[test]
    fn requests_end_in_results_errors_or_no_response() {
        let s = stats(HashMap::from([
            (
                "dns".to_string(),
                json!({
                    "total_queries": 5, "total_responses": 3,
                    "rcode_distribution": [{"name": "NOERROR", "count": 2}, {"name": "NXDOMAIN", "count": 1}],
                    "response_time": {"min": 0.01, "max": 0.03, "mean": 0.02, "median": 0.02, "p95": 0.03, "p99": 0.03, "count": 3}
                }),
            ),
            (
                "sip".to_string(),
                json!({
                    "total_requests": 2, "total_responses": 2,
                    "status_code_distribution": [{"name": "200", "count": 1}, {"name": "486", "count": 1}]
                }),
            ),
            (
                "diameter".to_string(),
                json!({
                    "total_requests": 1, "total_answers": 1,
                    "result_code_distribution": [{"name": "DIAMETER_UNABLE_TO_COMPLY", "count": 1}]
                }),
            ),
            (
                "http".to_string(),
                json!({"total_requests": 0, "total_responses": 0}),
            ),
        ]));
        let r = responses(&s);
        let protocols: Vec<&str> = r.iter().map(|r| r.protocol).collect();
        // HTTP had no requests.
        assert_eq!(protocols, ["DNS", "SIP", "Diameter"]);

        let dns = &r[0];
        assert_eq!((dns.requests, dns.responses), (5, 3));
        let labels: Vec<(&str, u64, bool)> = dns
            .outcomes
            .iter()
            .map(|o| (o.label.as_str(), o.count, o.error))
            .collect();
        assert_eq!(
            labels,
            [
                ("NOERROR", 2, false),
                ("NXDOMAIN", 1, true),
                ("No response", 2, true)
            ]
        );
        assert_eq!(
            dns.outcomes[1].filter.as_deref(),
            Some("dns.qr = 1 and dns.rcode_name = 'NXDOMAIN'")
        );
        assert_eq!(dns.outcomes[2].filter, None);
        assert_eq!(dns.response_time.as_ref().map(|t| t.count), Some(3));

        let sip = &r[1];
        assert!(!sip.outcomes[0].error);
        assert!(sip.outcomes[1].error);
        assert_eq!(
            sip.outcomes[1].filter.as_deref(),
            Some("sip.status_code = 486")
        );
        assert_eq!(sip.response_time, None);

        let diameter = &r[2];
        assert!(diameter.outcomes[0].error);
        assert_eq!(diameter.outcomes[0].filter, None);
    }
}
