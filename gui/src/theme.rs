/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2026 Shomy, Penumbra Contributors
*/

//! Hardware design system for Penumbra.
//! Warm graphite / signal-amber hardware aesthetic with precise hairline strokes,
//! strict dual-surface hierarchy, and dedicated JetBrains Mono technical typography.

use eframe::egui::style::{Selection, WidgetVisuals, Widgets};
use eframe::egui::{Color32, Rounding, Stroke, Visuals};
use eframe::epaint::Shadow;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ThemeId {
    #[default]
    WarmGraphite,
    SlateDark,
    MidnightOled,
    CyberViolet,
    NordicLight,
}

impl ThemeId {
    pub const ALL: &'static [ThemeId] = &[
        ThemeId::WarmGraphite,
        ThemeId::SlateDark,
        ThemeId::MidnightOled,
        ThemeId::CyberViolet,
        ThemeId::NordicLight,
    ];

    pub fn label(self) -> &'static str {
        match self {
            ThemeId::WarmGraphite => "Warm Graphite (Signal Amber)",
            ThemeId::SlateDark => "Dark Slate (Modern Default)",
            ThemeId::MidnightOled => "Midnight OLED (Deep Black)",
            ThemeId::CyberViolet => "Obsidian Violet (Deep Dark)",
            ThemeId::NordicLight => "Nordic Light (Clean Daylight)",
        }
    }

    pub fn palette(self) -> Palette {
        match self {
            ThemeId::WarmGraphite => Palette {
                background: Color32::from_rgb(0x0D, 0x0E, 0x0A),     // --bg
                sidebar: Color32::from_rgb(0x14, 0x15, 0x0E),        // --panel
                panel: Color32::from_rgb(0x14, 0x15, 0x0E),          // --panel
                panel_alt: Color32::from_rgb(0x19, 0x1A, 0x12),      // --panel-raised
                border: Color32::from_rgb(0x26, 0x27, 0x15),         // --edge
                border_soft: Color32::from_rgb(0x1C, 0x1D, 0x13),    // --edge-soft
                text: Color32::from_rgb(0xEC, 0xEA, 0xDF),           // --text
                text_muted: Color32::from_rgb(0x8D, 0x8F, 0x7C),     // --text-dim
                text_faint: Color32::from_rgb(0x56, 0x5A, 0x45),     // --text-faint
                accent: Color32::from_rgb(0xD9, 0xA4, 0x41),         // --signal-amber
                accent_strong: Color32::from_rgb(0xEA, 0xB3, 0x08),
                accent_dim: Color32::from_rgba_unmultiplied(217, 164, 65, 36), // --signal-amber-dim (0.14)
                success: Color32::from_rgb(0x8F, 0xAE, 0x5C),        // --signal-green
                warn: Color32::from_rgb(0xD9, 0xA4, 0x41),           // --signal-amber
                error: Color32::from_rgb(0xC0, 0x7A, 0x4A),          // --signal-rust
                border_widget: Color32::from_rgb(0x75, 0x7B, 0x64),  // prominent warm olive for checkboxes & inputs
                btn_text_dark: Color32::from_rgb(0x1A, 0x14, 0x00),  // #1a1400
                is_dark: true,
            },
            ThemeId::SlateDark => Palette {
                background: Color32::from_rgb(0x16, 0x18, 0x1D),
                sidebar: Color32::from_rgb(0x0E, 0x10, 0x13),
                panel: Color32::from_rgb(0x1E, 0x21, 0x28),
                panel_alt: Color32::from_rgb(0x27, 0x2B, 0x35),
                border: Color32::from_rgb(0x32, 0x38, 0x46),
                border_soft: Color32::from_rgb(0x22, 0x27, 0x32),
                text: Color32::from_rgb(0xF3, 0xF4, 0xF6),
                text_muted: Color32::from_rgb(0x9C, 0xA3, 0xAF),
                text_faint: Color32::from_rgb(0x6B, 0x72, 0x80),
                accent: Color32::from_rgb(0x3B, 0x82, 0xF6),
                accent_strong: Color32::from_rgb(0x25, 0x63, 0xEB),
                accent_dim: Color32::from_rgba_unmultiplied(59, 130, 246, 36),
                success: Color32::from_rgb(0x22, 0xC5, 0x5E),
                warn: Color32::from_rgb(0xF5, 0x9E, 0x0B),
                error: Color32::from_rgb(0xEF, 0x44, 0x44),
                border_widget: Color32::from_rgb(0x55, 0x62, 0x78),
                btn_text_dark: Color32::from_rgb(0x00, 0x00, 0x00),
                is_dark: true,
            },
            ThemeId::MidnightOled => Palette {
                background: Color32::from_rgb(0x00, 0x00, 0x00),
                sidebar: Color32::from_rgb(0x08, 0x08, 0x0A),
                panel: Color32::from_rgb(0x12, 0x12, 0x16),
                panel_alt: Color32::from_rgb(0x1B, 0x1B, 0x22),
                border: Color32::from_rgb(0x2A, 0x2A, 0x36),
                border_soft: Color32::from_rgb(0x18, 0x18, 0x20),
                text: Color32::from_rgb(0xF5, 0xF5, 0xF8),
                text_muted: Color32::from_rgb(0x82, 0x83, 0x92),
                text_faint: Color32::from_rgb(0x52, 0x52, 0x5E),
                accent: Color32::from_rgb(0x38, 0xBD, 0xF8),
                accent_strong: Color32::from_rgb(0x02, 0x84, 0xC7),
                accent_dim: Color32::from_rgba_unmultiplied(56, 189, 248, 36),
                success: Color32::from_rgb(0x10, 0xB9, 0x81),
                warn: Color32::from_rgb(0xF5, 0x9E, 0x0B),
                error: Color32::from_rgb(0xEF, 0x44, 0x44),
                border_widget: Color32::from_rgb(0x48, 0x48, 0x5C),
                btn_text_dark: Color32::from_rgb(0x00, 0x00, 0x00),
                is_dark: true,
            },
            ThemeId::CyberViolet => Palette {
                background: Color32::from_rgb(0x0F, 0x0D, 0x18),
                sidebar: Color32::from_rgb(0x0A, 0x08, 0x12),
                panel: Color32::from_rgb(0x1A, 0x16, 0x28),
                panel_alt: Color32::from_rgb(0x24, 0x1E, 0x36),
                border: Color32::from_rgb(0x36, 0x2D, 0x50),
                border_soft: Color32::from_rgb(0x25, 0x1F, 0x38),
                text: Color32::from_rgb(0xF6, 0xF4, 0xFF),
                text_muted: Color32::from_rgb(0xA2, 0x97, 0xBD),
                text_faint: Color32::from_rgb(0x6C, 0x62, 0x84),
                accent: Color32::from_rgb(0xA8, 0x55, 0xF7),
                accent_strong: Color32::from_rgb(0x93, 0x33, 0xEA),
                accent_dim: Color32::from_rgba_unmultiplied(168, 85, 247, 36),
                success: Color32::from_rgb(0x10, 0xB9, 0x81),
                warn: Color32::from_rgb(0xFB, 0xBF, 0x24),
                error: Color32::from_rgb(0xEF, 0x44, 0x44),
                border_widget: Color32::from_rgb(0x5C, 0x50, 0x7C),
                btn_text_dark: Color32::from_rgb(0x00, 0x00, 0x00),
                is_dark: true,
            },
            ThemeId::NordicLight => Palette {
                background: Color32::from_rgb(0xF3, 0xF4, 0xF7),
                sidebar: Color32::from_rgb(0xEA, 0xEC, 0xF1),
                panel: Color32::from_rgb(0xFF, 0xFF, 0xFF),
                panel_alt: Color32::from_rgb(0xE3, 0xE6, 0xED),
                border: Color32::from_rgb(0xCE, 0xD3, 0xDD),
                border_soft: Color32::from_rgb(0xE2, 0xE5, 0xEB),
                text: Color32::from_rgb(0x11, 0x18, 0x27),
                text_muted: Color32::from_rgb(0x6B, 0x72, 0x80),
                text_faint: Color32::from_rgb(0x9C, 0xA3, 0xAF),
                accent: Color32::from_rgb(0x25, 0x63, 0xEB),
                accent_strong: Color32::from_rgb(0x1D, 0x4E, 0xD8),
                accent_dim: Color32::from_rgba_unmultiplied(37, 99, 235, 36),
                success: Color32::from_rgb(0x16, 0xA3, 0x4A),
                warn: Color32::from_rgb(0xD9, 0x77, 0x06),
                error: Color32::from_rgb(0xDC, 0x26, 0x26),
                border_widget: Color32::from_rgb(0x94, 0xA3, 0xB8),
                btn_text_dark: Color32::from_rgb(0xFF, 0xFF, 0xFF),
                is_dark: false,
            },
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
pub struct Palette {
    pub background: Color32,
    pub sidebar: Color32,
    pub panel: Color32,
    pub panel_alt: Color32,
    pub border: Color32,
    pub border_soft: Color32,
    pub border_widget: Color32,
    pub text: Color32,
    pub text_muted: Color32,
    pub text_faint: Color32,
    pub accent: Color32,
    pub accent_strong: Color32,
    pub accent_dim: Color32,
    pub success: Color32,
    pub warn: Color32,
    pub error: Color32,
    pub btn_text_dark: Color32,
    pub is_dark: bool,
}

/// Sets up typography ensuring JetBrains Mono is registered for genuinely technical monospace elements.
pub fn setup_fonts(ctx: &eframe::egui::Context) {
    let mut fonts = eframe::egui::FontDefinitions::default();

    let font_candidates = [
        "/usr/share/fonts/TTF/JetBrainsMonoNerdFontMono-Regular.ttf",
        "/usr/share/fonts/TTF/JetBrainsMonoNerdFont-Regular.ttf",
        "/usr/share/fonts/jetbrains-mono/JetBrainsMono-Regular.ttf",
    ];

    for path in font_candidates {
        if let Ok(font_bytes) = std::fs::read(path) {
            fonts.font_data.insert(
                "jetbrains_mono".to_owned(),
                eframe::egui::FontData::from_owned(font_bytes),
            );
            fonts
                .families
                .entry(eframe::egui::FontFamily::Monospace)
                .or_default()
                .insert(0, "jetbrains_mono".to_owned());
            break;
        }
    }

    ctx.set_fonts(fonts);
}

/// Apply `palette` to the egui [`Visuals`] used by the root context.
pub fn apply(palette: Palette, ctx: &eframe::egui::Context) {
    let mut visuals = if palette.is_dark { Visuals::dark() } else { Visuals::light() };

    visuals.override_text_color = Some(palette.text);
    visuals.window_fill = palette.panel;
    visuals.panel_fill = palette.background;
    visuals.extreme_bg_color = palette.panel_alt;
    visuals.faint_bg_color = palette.panel_alt;
    visuals.window_stroke = Stroke::new(1.0_f32, palette.border);
    visuals.window_shadow = Shadow::default();
    visuals.popup_shadow = Shadow::default();
    visuals.selection = Selection {
        bg_fill: palette.accent_dim,
        stroke: Stroke::new(1.0_f32, palette.accent),
    };
    visuals.hyperlink_color = palette.accent;

    // Small border-radius (3px) everywhere, flat panels, hairline 1px borders
    let round = Rounding::same(3.0);
    let widgets = Widgets {
        noninteractive: WidgetVisuals {
            bg_fill: palette.panel,
            weak_bg_fill: palette.panel,
            bg_stroke: Stroke::new(1.0_f32, palette.border),
            rounding: round,
            fg_stroke: Stroke::new(1.0_f32, palette.text_faint),
            expansion: 0.0,
        },
        inactive: WidgetVisuals {
            bg_fill: palette.panel_alt,
            weak_bg_fill: palette.panel_alt,
            bg_stroke: Stroke::new(1.3_f32, palette.border_widget),
            rounding: round,
            fg_stroke: Stroke::new(1.0_f32, palette.text),
            expansion: 0.0,
        },
        hovered: WidgetVisuals {
            bg_fill: palette.accent_dim,
            weak_bg_fill: palette.accent_dim,
            bg_stroke: Stroke::new(1.3_f32, palette.accent),
            rounding: round,
            fg_stroke: Stroke::new(1.0_f32, palette.text),
            expansion: 0.0,
        },
        active: WidgetVisuals {
            bg_fill: palette.accent,
            weak_bg_fill: palette.accent,
            bg_stroke: Stroke::new(1.0_f32, palette.accent),
            rounding: round,
            fg_stroke: Stroke::new(1.0_f32, palette.btn_text_dark), // #1a1400 dark text
            expansion: 0.0,
        },
        open: WidgetVisuals {
            bg_fill: palette.panel_alt,
            weak_bg_fill: palette.panel_alt,
            bg_stroke: Stroke::new(1.0_f32, palette.accent),
            rounding: round,
            fg_stroke: Stroke::new(1.0_f32, palette.text),
            expansion: 0.0,
        },
    };
    visuals.widgets = widgets;

    ctx.set_visuals(visuals);
}

/// Renders a high-contrast hardware-styled checkbox with visible borders and solid accent fill on selection.
pub fn hardware_checkbox(
    ui: &mut eframe::egui::Ui,
    checked: &mut bool,
    palette: &Palette,
) -> eframe::egui::Response {
    let size = eframe::egui::vec2(15.0, 15.0);
    let (rect, mut response) = ui.allocate_exact_size(size, eframe::egui::Sense::click());
    if response.clicked() {
        *checked = !*checked;
        response.mark_changed();
    }
    response.widget_info(|| {
        eframe::egui::WidgetInfo::selected(
            eframe::egui::WidgetType::Checkbox,
            ui.is_enabled(),
            *checked,
            "",
        )
    });

    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        let rounding = eframe::egui::Rounding::same(3.0);
        let hovered = response.hovered();

        if *checked {
            let fill = if hovered {
                palette.accent_strong
            } else {
                palette.accent
            };
            painter.rect_filled(rect, rounding, fill);

            // Draw crisp dark checkmark (#1a1400)
            let stroke = eframe::egui::Stroke::new(2.0_f32, palette.btn_text_dark);
            let p1 = rect.left_center() + eframe::egui::vec2(2.5, -0.5);
            let p2 = rect.center() + eframe::egui::vec2(-1.0, 3.5);
            let p3 = rect.right_center() + eframe::egui::vec2(-2.5, -3.5);
            painter.line_segment([p1, p2], stroke);
            painter.line_segment([p2, p3], stroke);
        } else {
            let bg = if hovered { palette.accent_dim } else { palette.panel_alt };
            let border_stroke = if hovered {
                eframe::egui::Stroke::new(1.5_f32, palette.accent)
            } else {
                eframe::egui::Stroke::new(1.4_f32, palette.border_widget)
            };
            painter.rect(rect, rounding, bg, border_stroke);
        }
    }

    response
}

/// Renders a hardware checkbox with an accompanying text label.
pub fn hardware_checkbox_labeled(
    ui: &mut eframe::egui::Ui,
    checked: &mut bool,
    label: impl Into<eframe::egui::WidgetText>,
    palette: &Palette,
) -> eframe::egui::Response {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 6.0;
        let mut res = hardware_checkbox(ui, checked, palette);
        let label_res = ui.add(eframe::egui::Label::new(label).sense(eframe::egui::Sense::click()));
        if label_res.clicked() {
            *checked = !*checked;
            res.mark_changed();
        }
        res | label_res
    })
    .inner
}

/// Draws a precision hardware LED indicator dot with an outer bezel ring and solid core.
pub fn status_led(ui: &mut eframe::egui::Ui, color: Color32, size: f32) -> eframe::egui::Response {
    let (rect, response) = ui.allocate_exact_size(eframe::egui::vec2(size, size), eframe::egui::Sense::hover());
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        let center = rect.center();
        let radius = (size / 2.0) - 0.5;

        // Subtle outer bezel ring
        painter.circle_stroke(
            center,
            radius,
            eframe::egui::Stroke::new(1.0_f32, color.gamma_multiply(0.4)),
        );
        // Luminous inner LED core
        painter.circle_filled(
            center,
            (radius - 1.2).max(1.5),
            color,
        );
    }
    response
}
