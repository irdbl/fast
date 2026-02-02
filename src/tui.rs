use crate::display::{format_bytes, format_speed};
use crate::nat::{DebugLog, DetectionResult, NatTopology, NatType};
use crate::types::{ClientInfo, DataPoint, TestHistory, TestState};
use crossterm::{
    event::{self, Event, KeyCode},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Style, Stylize},
    symbols::Marker,
    text::{Line, Span},
    widgets::{Axis, Block, Borders, Chart, Dataset, Gauge, Paragraph},
    Frame, Terminal,
};
use std::io::stdout;
use std::time::Duration;

const TEST_DURATION_SECS: f64 = 10.0;

pub struct Tui {
    terminal: Terminal<ratatui::backend::CrosstermBackend<std::io::Stdout>>,
}

impl Tui {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        enable_raw_mode()?;
        stdout().execute(EnterAlternateScreen)?;
        let backend = ratatui::backend::CrosstermBackend::new(stdout());
        let terminal = Terminal::new(backend)?;
        Ok(Self { terminal })
    }

    pub fn restore(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        disable_raw_mode()?;
        stdout().execute(LeaveAlternateScreen)?;
        Ok(())
    }

    pub fn draw(
        &mut self,
        state: &TestState,
        history: &TestHistory,
        client: &ClientInfo,
        servers: &[String],
        phase: &str,
        nat_result: Option<&DetectionResult>,
        nat_log: &DebugLog,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let elapsed = state.elapsed().as_secs_f64();
        let progress = (elapsed / TEST_DURATION_SECS).min(1.0);

        let current_download = history.points.last().map(|p| p.download_speed).unwrap_or(0.0);
        let current_upload = history.points.last().map(|p| p.upload_speed).unwrap_or(0.0);
        let current_latency = history.points.last().map(|p| p.latency).unwrap_or(0.0);

        let nat_messages: Vec<String> = nat_log
            .lock()
            .map(|l| l.clone())
            .unwrap_or_default();

        self.terminal.draw(|frame| {
            let area = frame.area();

            // Main layout: header, charts, stats+nat, footer
            let chunks = Layout::vertical([
                Constraint::Length(3),  // Header + progress
                Constraint::Min(6),     // Charts
                Constraint::Length(12), // Stats + NAT (bigger)
                Constraint::Length(2),  // Footer
            ])
            .split(area);

            // Header with progress bar and connection info
            render_header(frame, chunks[0], phase, progress, client, servers);

            // Speed chart (full width)
            render_speed_chart(frame, chunks[1], history);

            // Stats and NAT area - two columns
            render_stats_and_nat(
                frame,
                chunks[2],
                current_download,
                current_upload,
                current_latency,
                state.get_download_bytes(),
                state.get_upload_bytes(),
                nat_result,
                &nat_messages,
            );

            // Footer
            render_footer(frame, chunks[3]);
        })?;

        Ok(())
    }

    pub fn should_quit(&self) -> Result<bool, Box<dyn std::error::Error>> {
        if event::poll(Duration::from_millis(0))? {
            if let Event::Key(key) = event::read()? {
                if key.code == KeyCode::Char('q') || key.code == KeyCode::Esc {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}

impl Drop for Tui {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

fn render_header(
    frame: &mut Frame,
    area: Rect,
    phase: &str,
    progress: f64,
    client: &ClientInfo,
    servers: &[String],
) {
    let chunks = Layout::vertical([Constraint::Length(1), Constraint::Length(2)]).split(area);

    // Top row: title on left, connection info on right
    let top_chunks = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[0]);

    let title = Line::from(vec![
        Span::styled("fast.com ", Style::default().fg(Color::Red).bold()),
        Span::styled("speed test", Style::default().fg(Color::White)),
        Span::raw("  "),
        Span::styled(phase, Style::default().fg(Color::Yellow)),
    ]);
    frame.render_widget(Paragraph::new(title), top_chunks[0]);

    // Connection info on right
    let isp = client.isp.as_deref().unwrap_or("Unknown");
    let server_str = servers.first().map(|s| s.as_str()).unwrap_or("");
    let connection_info = Line::from(vec![
        Span::styled(&client.ip, Style::default().fg(Color::Cyan)),
        Span::raw("  "),
        Span::styled(isp, Style::default().fg(Color::DarkGray)),
        Span::raw("  →  "),
        Span::styled(server_str, Style::default().fg(Color::DarkGray)),
    ]);
    frame.render_widget(
        Paragraph::new(connection_info).alignment(ratatui::layout::Alignment::Right),
        top_chunks[1],
    );

    let gauge = Gauge::default()
        .block(Block::default())
        .gauge_style(Style::default().fg(Color::Cyan))
        .ratio(progress)
        .label(format!("{:.1}s / {:.1}s", progress * TEST_DURATION_SECS, TEST_DURATION_SECS));
    frame.render_widget(gauge, chunks[1]);
}

/// Interpolate between points to create a denser dataset for smoother lines
fn interpolate_points(points: &[(f64, f64)], steps_between: usize) -> Vec<(f64, f64)> {
    if points.len() < 2 {
        return points.to_vec();
    }

    let mut result = Vec::with_capacity(points.len() * (steps_between + 1));

    for window in points.windows(2) {
        let (x1, y1) = window[0];
        let (x2, y2) = window[1];

        result.push((x1, y1));

        for i in 1..=steps_between {
            let t = i as f64 / (steps_between + 1) as f64;
            let x = x1 + t * (x2 - x1);
            let y = y1 + t * (y2 - y1);
            result.push((x, y));
        }
    }

    // Add the last point
    if let Some(&last) = points.last() {
        result.push(last);
    }

    result
}

fn render_speed_chart(frame: &mut Frame, area: Rect, history: &TestHistory) {
    let raw_download: Vec<(f64, f64)> = history
        .points
        .iter()
        .map(|p| (p.time, p.download_speed / 1_000_000.0)) // Convert to Mbps
        .collect();

    let raw_upload: Vec<(f64, f64)> = history
        .points
        .iter()
        .map(|p| (p.time, p.upload_speed / 1_000_000.0))
        .collect();

    // Interpolate for smoother lines (add 4 points between each sample)
    let download_data = interpolate_points(&raw_download, 4);
    let upload_data = interpolate_points(&raw_upload, 4);

    let max_speed = (history.max_download.max(history.max_upload) / 1_000_000.0 * 1.1).max(10.0);

    let datasets = vec![
        Dataset::default()
            .name("Download")
            .marker(Marker::Braille)
            .style(Style::default().fg(Color::Green))
            .data(&download_data),
        Dataset::default()
            .name("Upload")
            .marker(Marker::Braille)
            .style(Style::default().fg(Color::Blue))
            .data(&upload_data),
    ];

    let chart = Chart::new(datasets)
        .block(
            Block::default()
                .title(" Speed (Mbps) ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        )
        .x_axis(
            Axis::default()
                .style(Style::default().fg(Color::DarkGray))
                .bounds([0.0, TEST_DURATION_SECS])
                .labels(vec![
                    Line::from("0s"),
                    Line::from("5s"),
                    Line::from("10s"),
                ]),
        )
        .y_axis(
            Axis::default()
                .style(Style::default().fg(Color::DarkGray))
                .bounds([0.0, max_speed])
                .labels(vec![
                    Line::from("0"),
                    Line::from(format!("{:.0}", max_speed / 2.0)),
                    Line::from(format!("{:.0}", max_speed)),
                ]),
        );

    frame.render_widget(chart, area);
}

fn render_stats_and_nat(
    frame: &mut Frame,
    area: Rect,
    download_speed: f64,
    upload_speed: f64,
    latency: f64,
    download_bytes: u64,
    upload_bytes: u64,
    nat_result: Option<&DetectionResult>,
    nat_messages: &[String],
) {
    let chunks = Layout::horizontal([
        Constraint::Percentage(35),
        Constraint::Percentage(65), // NAT box gets more space
    ])
    .split(area);

    // Left: speeds
    let speed_text = vec![
        Line::from(vec![
            Span::styled("  Download  ", Style::default().fg(Color::Green)),
            Span::styled(
                format!("{:>12}", format_speed(download_speed)),
                Style::default().fg(Color::White).bold(),
            ),
        ]),
        Line::from(vec![
            Span::styled("            ", Style::default()),
            Span::styled(
                format!("{:>12}", format_bytes(download_bytes)),
                Style::default().fg(Color::DarkGray),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Upload    ", Style::default().fg(Color::Blue)),
            Span::styled(
                format!("{:>12}", format_speed(upload_speed)),
                Style::default().fg(Color::White).bold(),
            ),
        ]),
        Line::from(vec![
            Span::styled("            ", Style::default()),
            Span::styled(
                format!("{:>12}", format_bytes(upload_bytes)),
                Style::default().fg(Color::DarkGray),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Latency   ", Style::default().fg(Color::Yellow)),
            Span::styled(
                format!("{:>9.0} ms", latency),
                Style::default().fg(Color::White).bold(),
            ),
        ]),
    ];

    let speed_block = Paragraph::new(speed_text).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray))
            .title(" Current "),
    );
    frame.render_widget(speed_block, chunks[0]);

    // Right: NAT detection
    let topology_color = match nat_result.map(|r| &r.topology) {
        Some(NatTopology::Direct) => Color::Green,
        Some(NatTopology::SingleNat) => Color::Green,
        Some(NatTopology::DoubleNat) => Color::Yellow,
        Some(NatTopology::Cgnat) => Color::Red,
        Some(NatTopology::CgnatPlusNat) => Color::Red,
        _ => Color::DarkGray,
    };

    let nat_type_color = match nat_result.map(|r| &r.nat_type) {
        Some(NatType::OpenInternet) => Color::Green,
        Some(NatType::FullCone) => Color::Green,
        Some(NatType::RestrictedCone) => Color::Yellow,
        Some(NatType::PortRestrictedCone) => Color::Yellow,
        Some(NatType::Symmetric) => Color::Red,
        Some(NatType::Blocked) => Color::Red,
        _ => Color::DarkGray,
    };

    let topology_str = nat_result
        .map(|r| {
            let conf = format!(" ({:.0}%)", r.confidence * 100.0);
            format!("{}{}", r.topology, conf)
        })
        .unwrap_or_else(|| "Detecting...".to_string());

    let nat_type_str = nat_result
        .map(|r| r.nat_type.to_string())
        .unwrap_or_default();

    let external_info = nat_result
        .and_then(|r| {
            r.public_ip.as_ref().map(|ip| {
                format!("{}:{}", ip, r.external_port.unwrap_or(0))
            })
        })
        .unwrap_or_default();

    let mut nat_lines: Vec<Line> = vec![
        Line::from(vec![
            Span::styled("  Topology ", Style::default().fg(Color::DarkGray)),
            Span::styled(topology_str, Style::default().fg(topology_color).bold()),
        ]),
    ];

    if !nat_type_str.is_empty() {
        nat_lines.push(Line::from(vec![
            Span::styled("  NAT Type ", Style::default().fg(Color::DarkGray)),
            Span::styled(nat_type_str, Style::default().fg(nat_type_color)),
        ]));
    }

    if !external_info.is_empty() {
        nat_lines.push(Line::from(vec![
            Span::styled("  External ", Style::default().fg(Color::DarkGray)),
            Span::raw(external_info),
        ]));
    }

    // Network info (local IP, gateway, DNS)
    if let Some(result) = nat_result {
        let local = result.network.local_ip.as_deref().unwrap_or("--");
        let gw = result.network.default_gateway.as_deref().unwrap_or("--");
        nat_lines.push(Line::from(vec![
            Span::styled("  Local    ", Style::default().fg(Color::DarkGray)),
            Span::raw(format!("{} → {}", local, gw)),
        ]));
        if !result.network.dns_servers.is_empty() {
            let dns = result.network.dns_servers.join(", ");
            let dns_display = if dns.len() > 40 { format!("{}...", &dns[..40]) } else { dns };
            nat_lines.push(Line::from(vec![
                Span::styled("  DNS      ", Style::default().fg(Color::DarkGray)),
                Span::raw(dns_display),
            ]));
        }
    }

    // Add UPnP info
    if let Some(result) = nat_result {
        if result.upnp.available {
            let gateway = result.upnp.gateway_name.as_deref().unwrap_or("Gateway");
            let status = if result.upnp.can_add_mapping { "✓ mapping" } else { "no mapping" };
            nat_lines.push(Line::from(vec![
                Span::styled("  UPnP     ", Style::default().fg(Color::DarkGray)),
                Span::styled(gateway, Style::default().fg(Color::Green)),
                Span::styled(format!(" ({})", status), Style::default().fg(Color::DarkGray)),
            ]));
        }

        // NAT-PMP/PCP info
        if result.nat_pmp.nat_pmp_available {
            nat_lines.push(Line::from(vec![
                Span::styled("  NAT-PMP  ", Style::default().fg(Color::DarkGray)),
                Span::styled("available", Style::default().fg(Color::Green)),
            ]));
        } else if result.nat_pmp.pcp_available {
            nat_lines.push(Line::from(vec![
                Span::styled("  PCP      ", Style::default().fg(Color::DarkGray)),
                Span::styled("available", Style::default().fg(Color::Green)),
            ]));
        }

        // ICE candidates (compact view)
        if !result.ice_candidates.host.is_empty() || !result.ice_candidates.srflx.is_empty() {
            let host = result.ice_candidates.host.first()
                .map(|c| format!("{}:{}", c.address, c.port))
                .unwrap_or_else(|| "--".to_string());
            let srflx = result.ice_candidates.srflx.first()
                .map(|c| format!("{}:{}", c.address, c.port))
                .unwrap_or_else(|| "--".to_string());
            nat_lines.push(Line::from(vec![
                Span::styled("  ICE      ", Style::default().fg(Color::DarkGray)),
                Span::styled("host:", Style::default().fg(Color::DarkGray)),
                Span::raw(format!("{} ", host)),
                Span::styled("srflx:", Style::default().fg(Color::DarkGray)),
                Span::raw(srflx),
            ]));
        }

        // UDP connectivity (compact)
        let udp = &result.udp_connectivity;
        let port_status = |ok: bool| if ok { "✓" } else { "✗" };
        nat_lines.push(Line::from(vec![
            Span::styled("  UDP      ", Style::default().fg(Color::DarkGray)),
            Span::styled(format!("3478:{} ", port_status(udp.port_3478)),
                Style::default().fg(if udp.port_3478 { Color::Green } else { Color::Red })),
            Span::styled(format!("443:{} ", port_status(udp.port_443)),
                Style::default().fg(if udp.port_443 { Color::Green } else { Color::Red })),
            Span::styled(format!("19302:{}", port_status(udp.port_19302)),
                Style::default().fg(if udp.port_19302 { Color::Green } else { Color::Red })),
        ]));
    }

    // Add evidence if available
    if let Some(result) = nat_result {
        for evidence in result.evidence.iter().take(2) {
            let truncated = if evidence.len() > 55 {
                format!("{}...", &evidence[..55])
            } else {
                evidence.clone()
            };
            nat_lines.push(Line::from(vec![
                Span::styled(format!("  * {}", truncated), Style::default().fg(Color::Cyan)),
            ]));
        }
    }

    // Add debug messages (last 4)
    let start = nat_messages.len().saturating_sub(4);
    for msg in nat_messages.iter().skip(start) {
        let truncated = if msg.len() > 60 {
            format!("{}...", &msg[..60])
        } else {
            msg.clone()
        };
        nat_lines.push(Line::from(vec![
            Span::styled(format!("  {}", truncated), Style::default().fg(Color::DarkGray)),
        ]));
    }

    let nat_block = Paragraph::new(nat_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray))
            .title(" NAT Detection "),
    );
    frame.render_widget(nat_block, chunks[1]);
}

fn render_footer(frame: &mut Frame, area: Rect) {
    let footer = Line::from(vec![
        Span::styled("  q", Style::default().fg(Color::Yellow)),
        Span::raw(" quit  "),
        Span::styled("Download", Style::default().fg(Color::Green)),
        Span::raw(" + "),
        Span::styled("Upload", Style::default().fg(Color::Blue)),
        Span::raw(" + "),
        Span::styled("Latency", Style::default().fg(Color::Yellow)),
        Span::raw(" running concurrently"),
    ]);
    frame.render_widget(Paragraph::new(footer), area);
}

/// Calculate instantaneous speed from byte counts
pub fn calculate_speed(prev_bytes: u64, curr_bytes: u64, dt_secs: f64) -> f64 {
    if dt_secs > 0.0 && curr_bytes > prev_bytes {
        ((curr_bytes - prev_bytes) as f64 * 8.0) / dt_secs
    } else {
        0.0
    }
}

/// Sample current state into a data point
pub fn sample_state(
    state: &TestState,
    prev_download: u64,
    prev_upload: u64,
    dt_secs: f64,
) -> DataPoint {
    let curr_download = state.get_download_bytes();
    let curr_upload = state.get_upload_bytes();

    DataPoint {
        time: state.elapsed().as_secs_f64(),
        download_speed: calculate_speed(prev_download, curr_download, dt_secs),
        upload_speed: calculate_speed(prev_upload, curr_upload, dt_secs),
        latency: state.get_latest_latency().unwrap_or(0.0),
    }
}
