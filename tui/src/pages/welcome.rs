/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/
use std::fs;

use penumbra::da::DAFile;
use ratatui::crossterm::event::{Event, KeyCode, KeyEvent};
use ratatui::prelude::*;
use ratatui::widgets::*;
use ratatui_explorer::{FileExplorer, Theme};
use strum::IntoEnumIterator;
use strum_macros::{AsRefStr, EnumIter};

use super::LOGO;
use crate::app::{AppCtx, AppPage};
use crate::components::selectable_list::{
    ListItemEntry,
    ListItemEntryBuilder,
    SelectableList,
    SelectableListBuilder,
};
use crate::pages::Page;

#[derive(EnumIter, AsRefStr, Debug, Clone, Copy)]
enum MenuAction {
    #[strum(serialize = "Select DA")]
    SelectDa,
    #[strum(serialize = "Enter DA Mode")]
    EnterDaMode,
    Quit,
}

#[derive(Default)]
enum WelcomeState {
    #[default]
    Idle,
    Browsing(FileExplorer),
}

#[derive(Default)]
pub struct WelcomePage {
    state: WelcomeState,
    actions: Vec<MenuAction>,
    menu: SelectableList,
}

impl WelcomePage {
    pub fn new() -> Self {
        let actions: Vec<MenuAction> = MenuAction::iter().collect();
        let menu_items: Vec<ListItemEntry> = actions
            .iter()
            .map(|action| {
                let icon = match action {
                    MenuAction::SelectDa => '🔍',
                    MenuAction::EnterDaMode => '🚀',
                    MenuAction::Quit => '❌',
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

        Self { actions, menu, ..Default::default() }
    }
}

#[async_trait::async_trait]
impl Page for WelcomePage {
    fn render(&mut self, f: &mut Frame<'_>, ctx: &mut AppCtx) {
        let area = f.area();

        // Split vertical: logo | loader info | menu/file explorer
        let vertical_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(9), // Logo
                Constraint::Length(2), // Loader info
                Constraint::Min(0),    // Rest
            ])
            .split(area);

        // Logo
        let logo = Paragraph::new(LOGO).alignment(Alignment::Center);
        f.render_widget(logo, vertical_chunks[0]);

        // Loader info (show filename or None)
        let loader_text = ctx
            .loader()
            .map(|_| format!("Selected Loader: {}", ctx.loader_name()))
            .unwrap_or_else(|| "Selected Loader: None".to_string());

        let loader_paragraph = Paragraph::new(loader_text)
            .style(Style::default().fg(Color::Yellow))
            .alignment(Alignment::Center);
        f.render_widget(loader_paragraph, vertical_chunks[1]);

        // Split horizontal: menu | explorer
        let horizontal_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(60), Constraint::Min(0)])
            .split(vertical_chunks[2]);

        // Menu
        self.menu.render(horizontal_chunks[0], f, "Menu");

        // File explorer
        if let WelcomeState::Browsing(explorer) = &mut self.state {
            f.render_widget(&explorer.widget(), horizontal_chunks[1]);
        }
    }

    async fn handle_input(&mut self, ctx: &mut AppCtx, key: KeyEvent) {
        match &mut self.state {
            WelcomeState::Browsing(explorer) => {
                if let Err(err) = explorer.handle(&Event::Key(key)) {
                    unimplemented!("Error handling unimplemented: {:?}", err);
                };

                if key.code == KeyCode::Enter {
                    if !explorer.files().is_empty() {
                        let selected_file = &explorer.files()[explorer.selected_idx()];
                        let path = &selected_file.path();

                        if path.extension().map_or(false, |ext| ext == "bin") {
                            match fs::read(path) {
                                Ok(raw_data) => match DAFile::parse_da(&raw_data) {
                                    Ok(da_file) => {
                                        ctx.set_loader(path.to_path_buf(), da_file);
                                        self.state = WelcomeState::Idle;
                                    }
                                    Err(err) => {
                                        unimplemented!("Error handling unimplemented: {:?}", err);
                                    }
                                },
                                Err(err) => {
                                    unimplemented!("Error handling unimplemented: {:?}", err);
                                }
                            }
                        }
                    }
                }

                if key.code == KeyCode::Esc {
                    self.state = WelcomeState::Idle;
                }
            }

            WelcomeState::Idle => match key.code {
                KeyCode::Up => self.menu.previous(),
                KeyCode::Down => self.menu.next(),
                KeyCode::Enter => {
                    let action = self.actions[self.menu.selected_index().unwrap_or(2)];
                    match action {
                        MenuAction::SelectDa => {
                            let theme = Theme::default().add_default_title();
                            match FileExplorer::with_theme(theme) {
                                Ok(explorer) => {
                                    self.state = WelcomeState::Browsing(explorer);
                                }
                                Err(err) => {
                                    eprintln!("Failed to launch file explorer: {err}");
                                }
                            }
                        }
                        MenuAction::EnterDaMode => ctx.change_page(AppPage::DevicePage),
                        MenuAction::Quit => ctx.quit(),
                    }
                }
                _ => {}
            },
        }
    }
}
