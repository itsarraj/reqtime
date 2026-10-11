use std::fmt::Write as _;
use std::time::Duration;

use crate::timing::HopTiming;

pub struct Phase {
    pub label: &'static str,
    pub start: Duration,
    pub end: Duration,
}

/// Breaks a hop's cumulative timestamps into named phases, each as a
/// `[start, end)` span within the total — the shape a waterfall bar
/// needs. TLS Handshake is only included for `https` hops (`None`
/// simply produces one fewer phase, not a zero-width one).
pub fn phases(hop: &HopTiming) -> Vec<Phase> {
    let mut result = vec![
        Phase {
            label: "DNS Lookup",
            start: Duration::ZERO,
            end: hop.dns_lookup,
        },
        Phase {
            label: "TCP Connect",
            start: hop.dns_lookup,
            end: hop.tcp_connect,
        },
    ];

    let pretransfer = match hop.tls_handshake {
        Some(tls_end) => {
            result.push(Phase {
                label: "TLS Handshake",
                start: hop.tcp_connect,
                end: tls_end,
            });
            tls_end
        }
        None => hop.tcp_connect,
    };

    result.push(Phase {
        label: "Server Processing",
        start: pretransfer,
        end: hop.time_to_first_byte,
    });
    result.push(Phase {
        label: "Content Transfer",
        start: hop.time_to_first_byte,
        end: hop.total,
    });

    result
}

fn duration_to_col(d: Duration, total: Duration, width: usize) -> usize {
    if total.is_zero() || width == 0 {
        return 0;
    }
    let frac = d.as_secs_f64() / total.as_secs_f64();
    ((frac * width as f64).round() as usize).min(width)
}

/// Renders one phase as a `width`-character bar: filled columns show
/// *when* the phase occurs within the overall timeline (not just how
/// long it took in isolation), which is what makes a waterfall a
/// waterfall rather than a plain bar chart — a phase is always given
/// at least one visible column even if its computed width would
/// otherwise round to zero, so a genuinely fast phase (a sub-millisecond
/// DNS cache hit, say) doesn't just silently disappear from the picture.
pub fn render_bar(phase: &Phase, total: Duration, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    let mut start_col = duration_to_col(phase.start, total, width);
    let mut end_col = duration_to_col(phase.end, total, width);
    if start_col >= width {
        start_col = width - 1;
    }
    if end_col <= start_col {
        end_col = start_col + 1;
    }
    end_col = end_col.min(width);

    let mut bar = vec!['░'; width];
    for slot in bar.iter_mut().take(end_col).skip(start_col) {
        *slot = '█';
    }
    bar.into_iter().collect()
}

pub fn format_duration(d: Duration) -> String {
    let ms = d.as_secs_f64() * 1000.0;
    if ms < 1.0 {
        format!("{:.2}ms", ms)
    } else if ms < 1000.0 {
        format!("{:.1}ms", ms)
    } else {
        format!("{:.2}s", d.as_secs_f64())
    }
}

pub fn render_waterfall(hop: &HopTiming, width: usize) -> String {
    let mut out = String::new();
    let segments = phases(hop);
    let label_width = segments.iter().map(|p| p.label.len()).max().unwrap_or(0);

    for phase in &segments {
        let bar = render_bar(phase, hop.total, width);
        let duration = phase.end.saturating_sub(phase.start);
        writeln!(
            out,
            "  {:label_width$}  [{bar}]  {}",
            phase.label,
            format_duration(duration)
        )
        .ok();
    }
    writeln!(
        out,
        "  {:label_width$}   {}",
        "Total",
        format_duration(hop.total)
    )
    .ok();
    out
}

pub fn render_summary(hop: &HopTiming) -> String {
    let mut out = String::new();
    writeln!(out, "{} {} ({})", hop.status, hop.reason, hop.url).ok();
    writeln!(out, "  connected to {}", hop.remote_addr).ok();
    writeln!(out, "  {} byte(s) body", hop.body_len).ok();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;

    fn sample_hop(with_tls: bool) -> HopTiming {
        HopTiming {
            url: Url::parse("https://example.com/").unwrap(),
            remote_addr: "127.0.0.1:443".parse().unwrap(),
            dns_lookup: Duration::from_millis(10),
            tcp_connect: Duration::from_millis(30),
            tls_handshake: if with_tls {
                Some(Duration::from_millis(60))
            } else {
                None
            },
            time_to_first_byte: Duration::from_millis(120),
            total: Duration::from_millis(130),
            status: 200,
            reason: "OK".to_string(),
            headers: vec![],
            body_len: 42,
        }
    }

    #[test]
    fn https_hop_has_all_five_phases() {
        let hop = sample_hop(true);
        let segs = phases(&hop);
        let labels: Vec<&str> = segs.iter().map(|p| p.label).collect();
        assert_eq!(
            labels,
            vec![
                "DNS Lookup",
                "TCP Connect",
                "TLS Handshake",
                "Server Processing",
                "Content Transfer"
            ]
        );
    }

    #[test]
    fn http_hop_omits_tls_handshake_phase() {
        let hop = sample_hop(false);
        let segs = phases(&hop);
        assert!(!segs.iter().any(|p| p.label == "TLS Handshake"));
        assert_eq!(segs.len(), 4);
    }

    #[test]
    fn phase_boundaries_chain_correctly() {
        let hop = sample_hop(true);
        let segs = phases(&hop);
        for pair in segs.windows(2) {
            assert_eq!(
                pair[0].end, pair[1].start,
                "phase '{}' end must equal phase '{}' start",
                pair[0].label, pair[1].label
            );
        }
        assert_eq!(segs.last().unwrap().end, hop.total);
    }

    #[test]
    fn a_phase_spanning_the_whole_timeline_fills_the_entire_bar() {
        let phase = Phase {
            label: "x",
            start: Duration::ZERO,
            end: Duration::from_millis(100),
        };
        let bar = render_bar(&phase, Duration::from_millis(100), 20);
        assert_eq!(bar, "█".repeat(20));
    }

    #[test]
    fn a_phase_covering_the_first_half_fills_only_the_left_half() {
        let phase = Phase {
            label: "x",
            start: Duration::ZERO,
            end: Duration::from_millis(50),
        };
        let bar = render_bar(&phase, Duration::from_millis(100), 20);
        assert_eq!(bar, format!("{}{}", "█".repeat(10), "░".repeat(10)));
    }

    #[test]
    fn a_zero_duration_phase_still_shows_at_least_one_column() {
        let phase = Phase {
            label: "x",
            start: Duration::from_millis(50),
            end: Duration::from_millis(50),
        };
        let bar = render_bar(&phase, Duration::from_millis(100), 20);
        assert!(
            bar.contains('█'),
            "a zero-width phase must still be visible: {bar}"
        );
    }

    #[test]
    fn format_duration_switches_units_sensibly() {
        assert_eq!(format_duration(Duration::from_micros(500)), "0.50ms");
        assert_eq!(format_duration(Duration::from_millis(45)), "45.0ms");
        assert_eq!(format_duration(Duration::from_millis(1500)), "1.50s");
    }

    #[test]
    fn render_waterfall_contains_every_phase_label_and_the_total() {
        let hop = sample_hop(true);
        let text = render_waterfall(&hop, 30);
        assert!(text.contains("DNS Lookup"));
        assert!(text.contains("TLS Handshake"));
        assert!(text.contains("Content Transfer"));
        assert!(text.contains("Total"));
        assert!(text.contains("130.0ms"));
    }

    #[test]
    fn render_waterfall_omits_tls_line_for_plain_http() {
        let hop = sample_hop(false);
        let text = render_waterfall(&hop, 30);
        assert!(!text.contains("TLS Handshake"));
    }
}
