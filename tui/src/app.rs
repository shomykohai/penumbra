/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/
use crate::pages::{DevicePage, Page, WelcomePage};
use penumbra::da::DAFile;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyModifiers};
use ratatui::{DefaultTerminal, Frame};
use std::path::PathBuf;
use std::{io::Result, time::Duration};

#[derive(PartialEq, Clone, Copy, Default)]
pub enum AppPage {
    #[default]
    Welcome,
    DevicePage,
}

#[derive(Default)]
pub struct AppCtx {
    loader: Option<Loader>,
    exit: bool,
    current_page_id: AppPage,
    next_page_id: Option<AppPage>
}

pub struct App {
    current_page: Box<dyn Page + Send>,
    pub context: AppCtx,
}

pub struct Loader {
    path: PathBuf,
    file: DAFile
}
impl Loader {
    pub fn new(path: PathBuf, file: DAFile) -> Self {
        Self {
            path,
            file
        }
    }
    pub fn file(&self) -> &DAFile {
        &self.file
    }
    pub fn path(&self) -> &PathBuf {
        &self.path
    }
    pub fn loader_name(&self) -> Option<String> {
        self.path().file_name()
            .and_then(|name| name.to_str())
            .map(|s| s.to_string())
    }
}

impl AppCtx {
    pub fn loader(&self) -> Option<&Loader> {
        self.loader.as_ref()
    }
    pub fn set_loader(&mut self, loader_path: PathBuf, loader_file: DAFile) {
        if let Some(loader) = self.loader.as_mut() {
            loader.path = loader_path;
            loader.file = loader_file;
        } else {
            self.loader = Some(Loader::new(loader_path, loader_file));
        }
    }
    pub fn loader_name(&self) -> String {
        self.loader
            .as_ref()
            .and_then(|l| l.loader_name())
            .unwrap_or("Unknown DA".to_string())
    }
    pub fn change_page(&mut self, page: AppPage) {
        self.next_page_id = Some(page);
    }
    pub fn quit(&mut self) {
        self.exit = true;
    }
}

impl App {
    pub fn new() -> App {
        App {
            current_page: Box::new(WelcomePage::new()),
            context: AppCtx::default()
        }
    }

    pub async fn run(&mut self, terminal: &mut DefaultTerminal) -> Result<()> {
        self.current_page.on_enter(&mut self.context).await;

        while !self.context.exit {
            if let Some(next_page) = self.context.next_page_id.take() {
                self.switch_to(next_page).await;
            }

            self.current_page.update(&mut self.context).await;
            terminal.draw(|f: &mut Frame<'_>| self.draw(f))?;

            self.handle_events().await?;
        }
        Ok(())
    }

    async fn handle_events(&mut self) -> Result<()> {
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                // Force exit: [Ctrl + Delete]
                if key.code == KeyCode::Delete && key.modifiers.contains(KeyModifiers::CONTROL)
                {
                    self.context.quit();
                }

                self.current_page.handle_input(&mut self.context, key).await;
            }
        }
        Ok(())
    }

    fn draw(&mut self, frame: &mut Frame<'_>) {
        self.current_page.render(frame, &mut self.context);
    }

    pub async fn switch_to(&mut self, page: AppPage) {
        self.current_page.on_exit(&mut self.context).await;

        self.context.current_page_id = page;

        let new_page: Box<dyn Page + Send> = match page {
            AppPage::Welcome => Box::new(WelcomePage::new()),
            AppPage::DevicePage => Box::new(DevicePage::new()),
        };

        self.current_page = new_page;
        self.current_page.on_enter(&mut self.context).await;
    }
}
