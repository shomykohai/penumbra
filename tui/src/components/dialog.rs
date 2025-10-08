use derive_builder::Builder;
/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 DiabloSat
    SPDX-FileCopyrightText: 2025 Shomy
*/
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph, Widget, Wrap},
};
use strum_macros::AsRefStr;

#[derive(Clone, Copy, AsRefStr, Default)]
#[allow(unused)]
pub enum DialogType {
    #[strum(serialize = "[!] ERROR")]
    Error,
    #[strum(serialize = "[i] INFO")]
    Info,
    #[strum(serialize = "[o] DIALOG")]
    #[default]
    Other
}

pub struct DialogButton {
    pub title: String,
    pub action: Box<dyn FnMut() + Send>,
}

impl DialogButton {
    pub fn new<F>(title: &str, action: F) -> Self
    where
        F: FnMut() + Send + 'static
    {
        Self {
            title: title.to_string(),
            action: Box::new(action),
        }
    }
}

impl Clone for DialogButton {
    fn clone(&self) -> Self {
        Self {
            title: self.title.clone(),
            action: Box::new(|| {}),
        }
    }
}

#[derive(Clone)]
pub struct DialogColors {
    title_color: Color,
    bg_color: Color
}

impl DialogColors {
    pub fn new(title_color: Color, bg_color: Color) -> Self {
        Self {
            title_color,
            bg_color,
        }
    }
}

#[derive(Builder)]
pub struct Dialog {
    #[builder(default)]
    pub dialog_type: DialogType,
    #[builder(setter(into))]
    pub message: String,
    #[builder(default, setter(each = "button"))]
    pub buttons: Vec<DialogButton>,
    #[builder(default)]
    pub selected: usize,
    pub colors: DialogColors
}

impl Dialog {
    pub fn render(&self, area: Rect, buf: &mut Buffer) {
        let width = area.width / 2;
        let height = area.height / 2;
        let x = area.x + (area.width - width) / 2;
        let y = area.y + (area.height - height) / 2;
        let dialog_area = Rect::new(x, y, width, height);

        // Force clear the dialog area so that there is no garbage left on the dialog
        Self::clean_area(&dialog_area, buf, Color::Black);

        let block = Block::default()
            .title(Span::styled(self.dialog_type.as_ref(), Style::default().fg(self.colors.title_color)))
            .borders(Borders::ALL)
            .style(Style::default().bg(self.colors.bg_color).fg(Color::White));

        block.clone().render(dialog_area, buf);

        let inner = block.inner(dialog_area);

        Paragraph::new(&*self.message)
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true })
            .style(Style::default().fg(Color::White).bg(self.colors.bg_color))
            .render(inner, buf);

        // Buttons
        self.init_buttons(&inner, buf);
    }

    fn init_buttons(&self, inner: &Rect, buffer: &mut Buffer) {
        let buttons_y = inner.y + inner.height.saturating_sub(2);
        let total_width: u16 = self.buttons.iter().map(|b| b.title.len() as u16 + 4).sum();
        let mut buttons_x = inner.x + (inner.width.saturating_sub(total_width)) / 2;

        for (i, button) in self.buttons.iter().enumerate() {
            let style = if i == self.selected {
                Style::default().bg(self.colors.title_color).fg(self.colors.bg_color)
            } else {
                Style::default().bg(self.colors.bg_color).fg(self.colors.title_color)
            };

            let label = format!("[ {} ]", button.title);
            buffer.set_string(buttons_x, buttons_y, &label, style);
            buttons_x += label.len() as u16 + 1;
        }
    }

    fn clean_area(area: &Rect, buffer: &mut Buffer, bg_color: Color) {
        for y in area.y..area.y + area.height {
            buffer.set_stringn(area.x, y, " ".repeat(area.width as usize), area.width as usize,
                Style::default().bg(bg_color));
        }
    }
}

// Actions
impl Dialog {
    pub fn press_selected(&mut self) {
        if let Some(button) = self.buttons.get_mut(self.selected) {
            (button.action)();
        }
    }

    pub fn move_left(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
        }
    }

    pub fn move_right(&mut self) {
        if self.selected + 1 < self.buttons.len() {
            self.selected += 1;
        }
    }
}

#[allow(unused)]
impl DialogBuilder {
    pub fn error(message: impl Into<String>) -> Self {
        let mut builder = DialogBuilder::default();
        builder.dialog_type(DialogType::Error);
        builder.colors(DialogColors::new(Color::Red, Color::Black));
        builder.message(message);
        builder
    }

    pub fn info(message: impl Into<String>) -> Self {
        let mut builder = DialogBuilder::default();
        builder.dialog_type(DialogType::Info);
        builder.colors(DialogColors::new(Color::Cyan, Color::Black));
        builder.message(message);
        builder
    }

    pub fn other(message: impl Into<String>) -> Self {
        let mut builder = DialogBuilder::default();
        builder.dialog_type(DialogType::Other);
        builder.colors(DialogColors::new(Color::Gray, Color::Black));
        builder.message(message);
        builder
    }
}
