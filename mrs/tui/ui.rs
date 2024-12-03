use ratatui::{
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols,
    text::{self, Span},
    widgets::{
        canvas::{self, Canvas, Circle, Map, MapResolution, Rectangle},
        Axis, BarChart, Block, Borders, Cell, Chart, Dataset, Gauge, LineGauge, List, ListItem,
        Paragraph, Row, Sparkline, Table, Tabs, Wrap,
    },
    Frame,
};
use std::collections::HashMap;
use lazy_static::lazy_static;
use crate::app::App;

lazy_static! {
    static ref PROTO_STYLE_MAP: HashMap<String, Style> = {
        let mut map = HashMap::new();
        map.insert("UDP".into(), Style::default().fg(Color::Magenta));
        map.insert("TCP".into(), Style::default().fg(Color::LightCyan));
        map.insert("ARP".into(), Style::default().fg(Color::LightRed));
        map.insert("IPv4".into(), Style::default().fg(Color::LightGreen));
        map.insert("IPv6".into(), Style::default().fg(Color::LightMagenta));
        map
    };
}


pub fn draw(frame: &mut Frame, app: &mut App) {
    let chunks = Layout::vertical([Constraint::Length(3), Constraint::Min(0)]).split(frame.area());
    let tabs = app
        .tabs
        .titles
        .iter()
        .map(|t| text::Line::from(Span::styled(*t, Style::default().fg(Color::Green))))
        .collect::<Tabs>()
        .block(Block::bordered().title(app.title))
        .highlight_style(Style::default().fg(Color::Yellow))
        .select(app.tabs.index);
    frame.render_widget(tabs, chunks[0]);
    match app.tabs.index {
        0 => draw_first_tab(frame, app, chunks[1]),
        //1 => draw_second_tab(frame, app, chunks[1]),
        1 => draw_third_tab(frame, app, chunks[1]),
        _ => {}
    };
}

fn draw_overview(frame: &mut Frame, _app: &mut App, area: Rect) {
    let status_str = "Status: Healthy | ARP Attacks: 0 | Suspicious Packets: 3".to_string();
    let text = vec![
        text::Line::from(""),
        text::Line::from(status_str),
        text::Line::from(""),
    ];
    let block = Block::default().borders(Borders::ALL).title(Span::styled(
        "Status",
        Style::default()
            .fg(Color::Magenta)
            .add_modifier(Modifier::BOLD),
    ));
    let paragraph = Paragraph::new(text)
        .block(block)
        .wrap(Wrap { trim: true })
        .alignment(Alignment::Center);
    frame.render_widget(paragraph, area);
}

fn proto_style_matcher(proto: &str) -> Style {
    if let Some(style) = PROTO_STYLE_MAP.get(proto) {
        *style
    } else {
        Style::default().fg(Color::Blue)
    }
}


fn draw_logger(frame: &mut Frame, app: &mut App, area: Rect) {
    // Draw logs
    let info_style = Style::default().fg(Color::Blue);
    let warning_style = Style::default().fg(Color::Yellow);
    let error_style = Style::default().fg(Color::Magenta);
    let critical_style = Style::default().fg(Color::Red);


    let logs: Vec<ListItem> = app.captured_packets
        .iter()
        .map(|packet_display| {
            /*
            let s = match level {
                "ERROR" => error_style,
                "CRITICAL" => critical_style,
                "WARNING" => warning_style,
                _ => info_style,
            };
            */
            let s = info_style;
            let content = vec![text::Line::from(
                packet_display.iter().enumerate()
                .map(|(idx, val)| {if idx == 0 {Span::styled(format!("{}: ", val), proto_style_matcher(val))} else {Span::styled(format!("{} ", val), s)}}).collect::<Vec<_>>(),
            )];
            ListItem::new(content)
        })
        .collect();
    let logs = List::new(logs).block(
        Block::bordered().title(Span::styled(
            "Logs",
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        )),
    );
    frame.render_stateful_widget(logs, area, &mut app.logs.state);
}

fn draw_control_panel(frame: &mut Frame, app: &mut App, area: Rect) {
    // Draw tasks
    let tasks: Vec<ListItem> = app
        .tasks
        .items
        .iter()
        .map(|i| ListItem::new(vec![text::Line::from(Span::raw(*i))]))
        .collect();
    let tasks = List::new(tasks)
        .block(
            Block::bordered().title(Span::styled(
                "Controls",
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::BOLD),
            )),
        )
        .highlight_style(Style::default().add_modifier(Modifier::BOLD))
        .highlight_symbol("> ");
    frame.render_stateful_widget(tasks, area, &mut app.tasks.state);
}

fn draw_events(frame: &mut Frame, app: &mut App, area: Rect) {
    // Draw logs
    let info_style = Style::default().fg(Color::Blue);
    let _warning_style = Style::default().fg(Color::Yellow);
    let _error_style = Style::default().fg(Color::Magenta);
    let _critical_style = Style::default().fg(Color::Red);
    let logs: Vec<ListItem> = app
        .barchart
        .iter()
        .map(|&(evt, level)| {
            let s = info_style;
            let content = vec![text::Line::from(vec![
                Span::styled(format!("{level:<9}"), s),
                Span::raw(evt),
            ])];
            ListItem::new(content)
        })
        .collect();
    let logs = List::new(logs).block(Block::bordered().title("Events"));
    frame.render_stateful_widget(logs, area, &mut app.logs.state);
}

fn draw_live_monitor(frame: &mut Frame, app: &mut App, area: Rect) {
    let x_labels = vec![
        Span::styled(
            format!("{}", app.signals.window[0]),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!(
            "{}",
            (app.signals.window[0] + app.signals.window[1]) / 2.0
        )),
        Span::styled(
            format!("{}", app.signals.window[1]),
            Style::default().add_modifier(Modifier::BOLD),
        ),
    ];
    let datasets = vec![
        Dataset::default()
            .name("data2")
            .marker(symbols::Marker::Dot)
            .style(Style::default().fg(Color::Cyan))
            .data(&app.signals.sin1.points),
        Dataset::default()
            .name("data3")
            .marker(if app.enhanced_graphics {
                symbols::Marker::Braille
            } else {
                symbols::Marker::Dot
            })
            .style(Style::default().fg(Color::Yellow))
            .data(&app.signals.sin2.points),
    ];
    let chart = Chart::new(datasets)
        .block(
            Block::bordered().title(Span::styled(
                "Chart",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )),
        )
        .x_axis(
            Axis::default()
                .title("X Axis")
                .style(Style::default().fg(Color::Gray))
                .bounds(app.signals.window)
                .labels(x_labels),
        )
        .y_axis(
            Axis::default()
                .title("Y Axis")
                .style(Style::default().fg(Color::Gray))
                .bounds([-20.0, 20.0])
                .labels([
                    Span::styled("-20", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw("0"),
                    Span::styled("20", Style::default().add_modifier(Modifier::BOLD)),
                ]),
        );
    frame.render_widget(chart, area);
}

fn draw_global_charts(frame: &mut Frame, app: &mut App, area: Rect) {
    let constraints = vec![
        Constraint::Ratio(3, 6),
        //Constraint::Ratio(4, 6),
        Constraint::Ratio(3, 6),
    ];
    let chunks = Layout::horizontal(constraints).split(area);
    //draw_charts(frame, app, chunks[0]);
    draw_events(frame, app, chunks[0]);
    //draw_live_monitor(frame, app, chunks[1]);
    draw_control_panel(frame, app, chunks[1]);
}

fn draw_first_tab(frame: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::vertical([
        Constraint::Length(5),
        Constraint::Min(8),
        Constraint::Length(15),
    ])
    .split(area);
    draw_overview(frame, app, chunks[0]);
    draw_global_charts(frame, app, chunks[1]);
    //draw_charts(frame, app, chunks[1]);
    //draw_text(frame, chunks[2]);
    draw_logger(frame, app, chunks[2]);
}

fn draw_gauges(frame: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::vertical([
        Constraint::Length(2),
        Constraint::Length(3),
        Constraint::Length(2),
    ])
    .margin(1)
    .split(area);
    let block = Block::bordered().title("Graphs");
    frame.render_widget(block, area);

    let label = format!("{:.2}%", app.progress * 100.0);
    let gauge = Gauge::default()
        .block(Block::new().title("Gauge:"))
        .gauge_style(
            Style::default()
                .fg(Color::Magenta)
                .bg(Color::Black)
                .add_modifier(Modifier::ITALIC | Modifier::BOLD),
        )
        .use_unicode(app.enhanced_graphics)
        .label(label)
        .ratio(app.progress);
    frame.render_widget(gauge, chunks[0]);

    let sparkline = Sparkline::default()
        .block(Block::new().title("Sparkline:"))
        .style(Style::default().fg(Color::Green))
        .data(&app.sparkline.points)
        .bar_set(if app.enhanced_graphics {
            symbols::bar::NINE_LEVELS
        } else {
            symbols::bar::THREE_LEVELS
        });
    frame.render_widget(sparkline, chunks[1]);

    let line_gauge = LineGauge::default()
        .block(Block::new().title("LineGauge:"))
        .filled_style(Style::default().fg(Color::Magenta))
        .line_set(if app.enhanced_graphics {
            symbols::line::THICK
        } else {
            symbols::line::NORMAL
        })
        .ratio(app.progress);
    frame.render_widget(line_gauge, chunks[2]);
}

fn draw_barchart(frame: &mut Frame, app: &mut App, area: Rect) {
    let barchart = BarChart::default()
        .block(Block::bordered().title("Bar chart"))
        .data(&app.barchart)
        .bar_width(3)
        .bar_gap(2)
        .bar_set(if app.enhanced_graphics {
            symbols::bar::NINE_LEVELS
        } else {
            symbols::bar::THREE_LEVELS
        })
        .value_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Green)
                .add_modifier(Modifier::ITALIC),
        )
        .label_style(Style::default().fg(Color::Yellow))
        .bar_style(Style::default().fg(Color::Green));
    frame.render_widget(barchart, area);
}

fn draw_second_tab(frame: &mut Frame, app: &mut App, area: Rect) {
    let chunks =
        Layout::horizontal([Constraint::Percentage(30), Constraint::Percentage(70)]).split(area);
    let up_style = Style::default().fg(Color::Green);
    let failure_style = Style::default()
        .fg(Color::Red)
        .add_modifier(Modifier::RAPID_BLINK | Modifier::CROSSED_OUT);
    let rows = app.servers.iter().map(|s| {
        let style = if s.status == "Up" {
            up_style
        } else {
            failure_style
        };
        Row::new(vec![s.name, s.location, s.status]).style(style)
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(15),
            Constraint::Length(15),
            Constraint::Length(10),
        ],
    )
    .header(
        Row::new(vec!["Server", "Location", "Status"])
            .style(Style::default().fg(Color::Yellow))
            .bottom_margin(1),
    )
    .block(Block::bordered().title("Servers"));
    frame.render_widget(table, chunks[0]);

    let map = Canvas::default()
        .block(Block::bordered().title("World"))
        .paint(|ctx| {
            ctx.draw(&Map {
                color: Color::White,
                resolution: MapResolution::High,
            });
            ctx.layer();
            ctx.draw(&Rectangle {
                x: 0.0,
                y: 30.0,
                width: 10.0,
                height: 10.0,
                color: Color::Yellow,
            });
            ctx.draw(&Circle {
                x: app.servers[2].coords.1,
                y: app.servers[2].coords.0,
                radius: 10.0,
                color: Color::Green,
            });
            for (i, s1) in app.servers.iter().enumerate() {
                for s2 in &app.servers[i + 1..] {
                    ctx.draw(&canvas::Line {
                        x1: s1.coords.1,
                        y1: s1.coords.0,
                        y2: s2.coords.0,
                        x2: s2.coords.1,
                        color: Color::Yellow,
                    });
                }
            }
            for server in &app.servers {
                let color = if server.status == "Up" {
                    Color::Green
                } else {
                    Color::Red
                };
                ctx.print(
                    server.coords.1,
                    server.coords.0,
                    Span::styled("X", Style::default().fg(color)),
                );
            }
        })
        .marker(if app.enhanced_graphics {
            symbols::Marker::Braille
        } else {
            symbols::Marker::Dot
        })
        .x_bounds([-180.0, 180.0])
        .y_bounds([-90.0, 90.0]);
    frame.render_widget(map, chunks[1]);
}

fn draw_third_tab(frame: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::horizontal([Constraint::Ratio(1, 2), Constraint::Ratio(1, 2)]).split(area);

    let items: Vec<Row> = app
        .system
        .processes()
        .iter()
        .map(|(pid, process)| {
            let cells = vec![
                Cell::from(Span::raw(format!("{}: ", pid))),
                Cell::from(Span::raw(format!("{:?} ", process.name()))),
                Cell::from(Span::raw(format!("{:?}: ", process.disk_usage()))),
            ];
            Row::new(cells)
        })
        .collect();
    let table = Table::new(
        items,
        [
            Constraint::Ratio(1, 3),
            Constraint::Ratio(1, 3),
            Constraint::Ratio(1, 3),
        ],
    )
    .block(Block::bordered().title("Processes"));

    frame.render_widget(table, chunks[0]);

    // Network interfaces name, total data received and total data transmitted:
    let net_items: Vec<Row> = app
        .networks
        .iter()
        .map(|(interface_name, data)| {
            let cells = vec![
                Cell::from(Span::raw(interface_name.to_string())),
                Cell::from(Span::raw(format!(
                    "Total: {} B (down) / {} B (up)",
                    data.total_received(),
                    data.total_transmitted()
                ))),
                Cell::from(Span::raw(format!(
                    "Active: {} B (down) / {} B (up)",
                    data.received(),
                    data.transmitted()
                ))),
            ];
            Row::new(cells)
        })
        .collect();

    let table = Table::new(
        net_items,
        [
            Constraint::Ratio(1, 7),
            Constraint::Ratio(3, 7),
            Constraint::Ratio(3, 7),
        ],
    )
    .block(Block::bordered().title("Network"));
    frame.render_widget(table, chunks[1]);
}
