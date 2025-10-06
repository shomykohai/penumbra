/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/
use crate::app::{AppCtx, AppPage};
use crate::pages::Page;
use penumbra::da::DAFile;
use ratatui::crossterm::event::{Event, KeyCode, KeyEvent};
use ratatui::{prelude::*, widgets::*};
use ratatui_explorer::{FileExplorer, Theme};
use strum::IntoEnumIterator;
use strum_macros::{AsRefStr, EnumIter};
use std::{fs};

use super::LOGO;

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
    selected_idx: usize,
}

impl WelcomePage {
    pub fn new() -> Self {
        let actions: Vec<MenuAction> = MenuAction::iter().collect();

        Self {
            actions,
            ..Default::default()
        }
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
        let loader_text = ctx.loader()
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
        let block = Block::default().title("Menu").borders(Borders::ALL);
        let items: Vec<ListItem> = self.actions
            .iter()
            .map(|action| ListItem::new(action.as_ref()))
            .collect();
        let mut list_state = ListState::default();
        list_state.select(Some(self.selected_idx));
        let menu_list = List::new(items)
            .block(block)
            .highlight_style(Style::default().bg(Color::Gray).fg(Color::Black))
            .highlight_symbol(">> ");
        f.render_stateful_widget(menu_list, horizontal_chunks[0], &mut list_state);

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
                KeyCode::Up => {
                    if self.selected_idx > 0 {
                        self.selected_idx -= 1;
                    }
                }
                KeyCode::Down => {
                    if self.selected_idx < self.actions.len() - 1 {
                        self.selected_idx += 1;
                    }
                }
                KeyCode::Enter => {
                    let action = self.actions[self.selected_idx];
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
                        MenuAction::Quit => ctx.quit()
                    }
                }
                _ => {}
            },
        }
    }
}
