/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/
use std::sync::Arc;
use std::time::{Duration, Instant};

use hex::encode;
use penumbra::core::device::DeviceInfo;
use penumbra::core::seccfg::LockFlag;
use penumbra::{Device, find_mtk_port};
use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Style};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};
use strum::IntoEnumIterator;
use strum_macros::{AsRefStr, EnumIter};
use tokio::sync::Mutex;

use crate::app::{AppCtx, AppPage};
use crate::components::selectable_list::{
    ListItemEntry,
    ListItemEntryBuilder,
    SelectableList,
    SelectableListBuilder,
};
use crate::pages::Page;

#[derive(Clone, PartialEq, Default)]
enum DeviceStatus {
    #[default]
    WaitingForDevice,
    Initializing,
    DAReady,
    Error(String),
}

#[derive(EnumIter, AsRefStr, Debug, Clone, Copy)]
enum DeviceAction {
    #[strum(serialize = "Unlock Bootloader")]
    UnlockBootloader,
    #[strum(serialize = "Lock Bootloader")]
    LockBootloader,
    #[strum(serialize = "Back to Menu")]
    BackToMenu,
}

pub struct DevicePage {
    menu: SelectableList,
    actions: Vec<DeviceAction>,
    device: Option<Arc<Mutex<Device<'static>>>>,
    status: DeviceStatus,
    status_message: Option<(String, Style)>,
    last_poll: Instant,
    device_info: Option<DeviceInfo>,
}

impl DevicePage {
    pub fn new() -> Self {
        let actions: Vec<DeviceAction> = DeviceAction::iter().collect();
        let menu_items: Vec<ListItemEntry> = actions
            .iter()
            .map(|action| {
                let icon = match action {
                    DeviceAction::UnlockBootloader => '🔓',
                    DeviceAction::LockBootloader => '🔒',
                    DeviceAction::BackToMenu => '❌',
                };
                let label = action.as_ref().to_string();

                ListItemEntryBuilder::new(label).icon(icon).build().unwrap()
            })
            .collect();
        let menu: SelectableList = SelectableListBuilder::default()
            .items(menu_items)
            .highlight_symbol(">>".to_string())
            .build()
            .unwrap();

        Self {
            menu,
            actions,
            device: None,
            status: DeviceStatus::default(),
            status_message: None,
            last_poll: Instant::now(),
            device_info: None,
        }
    }

    async fn poll_device(&mut self, ctx: &mut AppCtx) -> Result<(), DeviceStatus> {
        if self.status == DeviceStatus::DAReady || matches!(self.status, DeviceStatus::Error(_)) {
            return Ok(());
        }
        if self.status == DeviceStatus::WaitingForDevice
            && self.last_poll.elapsed() > Duration::from_millis(500)
        {
            self.last_poll = Instant::now();
            let ports = find_mtk_port().await;
            if let Some(port) = ports {
                self.status = DeviceStatus::Initializing;

                let da_data: Vec<u8> = ctx
                    .loader()
                    .map(|loader| loader.file().da_raw_data.as_slice().to_vec())
                    .ok_or_else(|| DeviceStatus::Error("No DA loader in context".to_string()))?;

                let mut dev = Device::init(port, da_data)
                    .await
                    .map_err(|e| DeviceStatus::Error(format!("Device init failed: {e}")))?;

                dev.enter_da_mode()
                    .await
                    .map_err(|e| DeviceStatus::Error(format!("Failed DA mode: {e}")))?;

                if let Some(arc_mutex) = dev.dev_info.as_ref() {
                    let guard = arc_mutex.lock().await;
                    self.device_info = Some(DeviceInfo::clone(&guard));
                }
                self.device = Some(Arc::new(Mutex::new(dev)));
                self.status = DeviceStatus::DAReady;
            }
        }
        Ok(())
    }

    async fn set_device_lock_state(&mut self, flag: LockFlag) -> Result<Vec<u8>, String> {
        match &self.device {
            Some(dev_arc) => {
                let mut dev = dev_arc.lock().await;
                match dev.set_seccfg_lock_state(flag).await {
                    Some(response) => Ok(response),
                    None => Err("Failed to change lock state".to_string()),
                }
            }
            None => Err("No device connected".to_string()),
        }
    }
}

#[async_trait::async_trait]
impl Page for DevicePage {
    async fn handle_input(&mut self, ctx: &mut AppCtx, key: KeyEvent) {
        match key.code {
            KeyCode::Up => self.menu.previous(),
            KeyCode::Down => self.menu.next(),
            KeyCode::Enter => {
                let action = self.actions[self.menu.selected_index().unwrap_or(2)];
                match action {
                    DeviceAction::UnlockBootloader | DeviceAction::LockBootloader => {
                        let (label, flag) = match action {
                            DeviceAction::UnlockBootloader => ("Unlock", LockFlag::Unlock),
                            DeviceAction::LockBootloader => ("Lock", LockFlag::Lock),
                            _ => unreachable!(),
                        };

                        match self.set_device_lock_state(flag).await {
                            Ok(_) => {
                                self.status_message = Some((
                                    format!("{label} done."),
                                    Style::default().fg(Color::Green).bg(Color::Black),
                                ));
                            }
                            Err(e) => {
                                self.status = DeviceStatus::Error(format!("{label} failed: {e}"));
                            }
                        }
                    }
                    DeviceAction::BackToMenu => ctx.change_page(AppPage::Welcome),
                }
            }
            _ => {}
        }
    }

    fn render(&mut self, frame: &mut Frame<'_>, _ctx: &mut AppCtx) {
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(10), Constraint::Length(6), Constraint::Min(5)])
            .split(frame.area());

        let (status_line, style) = match &self.status {
            DeviceStatus::WaitingForDevice => (
                "Waiting for device...".to_string(),
                Style::default().fg(Color::Yellow).bg(Color::Black),
            ),
            DeviceStatus::Initializing => (
                "Initializing device...".to_string(),
                Style::default().fg(Color::Cyan).bg(Color::Black),
            ),
            DeviceStatus::DAReady => {
                ("DA mode active.".to_string(), Style::default().fg(Color::Green).bg(Color::Black))
            }
            DeviceStatus::Error(msg) => {
                (format!("Error: {msg}"), Style::default().fg(Color::Red).bg(Color::Black))
            }
        };

        let mut status_lines = vec![status_line];
        let paragraph_style = if let Some((msg, msg_style)) = &self.status_message {
            status_lines.push(msg.clone());
            msg_style.clone()
        } else {
            style
        };

        frame.render_widget(
            Paragraph::new(status_lines.join("\n"))
                .style(paragraph_style)
                .block(Block::default().borders(Borders::ALL)),
            layout[0],
        );

        let info_lines = match &self.device_info {
            Some(info) => vec![
                format!("SoC ID: {}", encode(&info.soc_id)),
                format!("MeID: {}", encode(&info.meid)),
            ],
            None => vec!["No device info available".to_string()],
        };

        frame.render_widget(
            Paragraph::new(info_lines.join("\n"))
                .block(Block::default().title("Device Info").borders(Borders::ALL))
                .style(Style::default().fg(Color::Cyan)),
            layout[1],
        );

        self.menu.render(layout[2], frame, "Actions");
    }

    async fn on_enter(&mut self, _ctx: &mut AppCtx) {
        self.menu.state.select(Some(0));
        self.status = DeviceStatus::WaitingForDevice;
        self.last_poll = Instant::now();
        self.device = None;
        self.device_info = None;
    }

    async fn on_exit(&mut self, _ctx: &mut AppCtx) {}

    async fn update(&mut self, ctx: &mut AppCtx) {
        if let Err(e) = self.poll_device(ctx).await {
            self.status = e;
        }
    }
}
