/*
 *    SPDX-License-Identifier: AGPL-3.0-or-later
 *    SPDX-FileCopyrightText: 2025 DiabloSat
 *    SPDX-FileCopyrightText: 2025 Shomy
 */

use derive_builder::Builder;
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState};

#[derive(Builder, Clone, Default)]
pub struct ListItemEntry {
    pub label: String,
    #[builder(default, setter(strip_option))]
    pub icon: Option<char>,
    #[builder(default, setter(strip_option))]
    pub style: Option<Style>,
    #[builder(private, default)]
    toggle: bool,
}

#[derive(Builder, Clone, Default)]
pub struct SelectableList {
    #[builder(default)]
    pub items: Vec<ListItemEntry>,
    #[builder(default = "{
        let mut s = ListState::default();
        s.select(Some(0));
        s
    }")]
    pub state: ListState,
    #[builder(setter(custom))]
    pub highlight_symbol: String,
    #[builder(default)]
    pub toggled: bool,
}

impl SelectableList {
    pub fn render(&mut self, area: Rect, f: &mut Frame, block_title: &str) {
        let list_items: Vec<ListItem> = self
            .items
            .iter()
            .enumerate()
            .map(|(i, item)| {
                let mut style = item.style.unwrap_or_else(|| Style::default().fg(Color::White));

                if Some(i) == self.selected_index() {
                    style = style.bg(Color::Gray).fg(Color::Black).add_modifier(Modifier::BOLD);
                }

                let label = {
                    let mut parts = Vec::new();

                    if self.toggled {
                        parts.push(if item.toggle { "[x]" } else { "[ ]" }.to_string());
                    }

                    if let Some(icon) = &item.icon {
                        parts.push(icon.to_string());
                    }

                    parts.push(item.label.clone());
                    parts.join(" ")
                };

                ListItem::new(label).style(style)
            })
            .collect();

        let block = Block::default().title(block_title).borders(Borders::ALL);

        let list = List::new(list_items).block(block).highlight_symbol(&self.highlight_symbol);

        f.render_stateful_widget(list, area, &mut self.state);
    }
}

impl SelectableList {
    pub fn next(&mut self) {
        if !self.items.is_empty() {
            let i = self.state.selected().unwrap_or(0);
            let next = (i + 1) % self.items.len();
            self.state.select(Some(next));
        }
    }

    pub fn previous(&mut self) {
        if !self.items.is_empty() {
            let i = self.state.selected().unwrap_or(0);
            let prev = if i == 0 { self.items.len() - 1 } else { i - 1 };
            self.state.select(Some(prev));
        }
    }

    pub fn selected_index(&self) -> Option<usize> {
        self.state.selected()
    }
}

impl SelectableList {
    pub fn toggle_selected(&mut self) {
        if self.toggled {
            if let Some(i) = self.selected_index() {
                if let Some(item) = self.items.get_mut(i) {
                    item.toggle = !item.toggle;
                }
            }
        }
    }

    pub fn checked_items(&self) -> Vec<&ListItemEntry> {
        self.items.iter().filter(|item| item.toggle).collect()
    }
}

impl SelectableListBuilder {
    pub fn highlight_symbol(&mut self, s: impl Into<String>) -> &mut Self {
        self.highlight_symbol = Some(format!("{} ", s.into().trim_end()));
        self
    }
}

impl ListItemEntryBuilder {
    pub fn new(label: impl Into<String>) -> Self {
        let mut builder = ListItemEntryBuilder::default();
        builder.label(label.into());
        builder
    }
}
