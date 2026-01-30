use crate::display::{format_bytes, format_speed};
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
    ) -> Result<(), Box<dyn std::error::Error>> {
        let elapsed = state.elapsed().as_secs_f64();
        let progress = (elapsed / TEST_DURATION_SECS).min(1.0);

        let current_download = history.points.last().map(|p| p.download_speed).unwrap_or(0.0);
        let current_upload = history.points.last().map(|p| p.upload_speed).unwrap_or(0.0);
        let current_latency = history.points.last().map(|p| p.latency).unwrap_or(0.0);

        self.terminal.draw(|frame| {
            let area = frame.area();

            // Main layout: header, charts, stats, footer
            let chunks = Layout::vertical([
                Constraint::Length(3), // Header + progress
                Constraint::Min(10),   // Charts
                Constraint::Length(7), // Stats
                Constraint::Length(2), // Footer
            ])
            .split(area);

            // Header with progress bar
            render_header(frame, chunks[0], phase, progress);

            // Speed chart (full width)
            render_speed_chart(frame, chunks[1], history);

            // Stats area
            render_stats(
                frame,
                chunks[2],
                current_download,
                current_upload,
                current_latency,
                state.get_download_bytes(),
                state.get_upload_bytes(),
                client,
                servers,
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

fn render_header(frame: &mut Frame, area: Rect, phase: &str, progress: f64) {
    let chunks = Layout::vertical([Constraint::Length(1), Constraint::Length(2)]).split(area);

    let title = Line::from(vec![
        Span::styled("fast.com ", Style::default().fg(Color::Red).bold()),
        Span::styled("speed test", Style::default().fg(Color::White)),
        Span::raw("  "),
        Span::styled(phase, Style::default().fg(Color::Yellow)),
    ]);
    frame.render_widget(Paragraph::new(title), chunks[0]);

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

fn render_stats(
    frame: &mut Frame,
    area: Rect,
    download_speed: f64,
    upload_speed: f64,
    latency: f64,
    download_bytes: u64,
    upload_bytes: u64,
    client: &ClientInfo,
    servers: &[String],
) {
    let chunks = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // Left: speeds
    let speed_text = vec![
        Line::from(vec![
            Span::styled("  Download  ", Style::default().fg(Color::Green)),
            Span::styled(
                format!("{:>12}", format_speed(download_speed)),
                Style::default().fg(Color::White).bold(),
            ),
            Span::styled(
                format!("  ({})", format_bytes(download_bytes)),
                Style::default().fg(Color::DarkGray),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Upload    ", Style::default().fg(Color::Blue)),
            Span::styled(
                format!("{:>12}", format_speed(upload_speed)),
                Style::default().fg(Color::White).bold(),
            ),
            Span::styled(
                format!("  ({})", format_bytes(upload_bytes)),
                Style::default().fg(Color::DarkGray),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Latency   ", Style::default().fg(Color::Yellow)),
            Span::styled(
                format!("{:>9.0} ms", latency),
                Style::default().fg(Color::White).bold(),
            ),
            Span::styled("  (loaded)", Style::default().fg(Color::DarkGray)),
        ]),
    ];

    let speed_block = Paragraph::new(speed_text).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray))
            .title(" Current "),
    );
    frame.render_widget(speed_block, chunks[0]);

    // Right: client info
    let isp = client.isp.as_deref().unwrap_or("Unknown");
    let server_str = servers.join(" | ");
    let info_text = vec![
        Line::from(vec![
            Span::styled("  Client  ", Style::default().fg(Color::DarkGray)),
            Span::raw(format!("{}, {}", client.location.city, client.location.country)),
        ]),
        Line::from(vec![
            Span::styled("          ", Style::default()),
            Span::styled(&client.ip, Style::default().fg(Color::Cyan)),
            Span::raw(format!("  {}", isp)),
        ]),
        Line::from(vec![
            Span::styled("  Server  ", Style::default().fg(Color::DarkGray)),
            Span::raw(if server_str.len() > 40 {
                format!("{}...", &server_str[..40])
            } else {
                server_str
            }),
        ]),
    ];

    let info_block = Paragraph::new(info_text).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray))
            .title(" Connection "),
    );
    frame.render_widget(info_block, chunks[1]);
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
