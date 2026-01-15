mod crypto;
mod data;

use arboard::Clipboard;
use clap::Parser;
use data::PasswordStore;
use eframe::egui;
use md5::{Digest, Md5};
use std::collections::HashSet;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

const CLEAR_DELAY_SECS: u64 = 60;

#[derive(Parser)]
#[command(name = "passlock")]
#[command(about = "Encrypted password manager with rofi-style selector")]
struct Cli {
    /// Path to encrypted password file (overrides PASSLOCK_FILE env var)
    file: Option<PathBuf>,

    #[arg(long, help = "Initialize a new encrypted password file")]
    init: bool,

    #[arg(long, help = "Edit the password file in $EDITOR")]
    edit: bool,

    #[arg(long, hide = true, num_args = 2, value_names = ["HASH", "VALUE"])]
    clear_later: Option<Vec<String>>,
}

fn main() {
    let cli = Cli::parse();

    if let Some(args) = cli.clear_later {
        clear_later_mode(&args[0], &args[1]);
        return;
    }

    let file = cli
        .file
        .or_else(|| std::env::var("PASSLOCK_FILE").ok().map(PathBuf::from))
        .unwrap_or_else(|| {
            eprintln!("Error: No password file specified.");
            eprintln!("Provide a file path as argument or set PASSLOCK_FILE environment variable.");
            std::process::exit(1);
        });

    if cli.init {
        init_mode(&file);
        return;
    }

    if cli.edit {
        edit_mode(&file);
        return;
    }

    run_selector(&file);
}

fn clear_later_mode(hash: &str, value: &str) {
    std::thread::sleep(Duration::from_secs(CLEAR_DELAY_SECS));

    let temp_path = std::env::temp_dir().join(format!("passlock_prune_{}", std::process::id()));
    std::fs::write(&temp_path, format!("{}\n", hash)).ok();
    Command::new("greenclip")
        .args(["prune", temp_path.to_str().unwrap()])
        .output()
        .ok();
    std::fs::remove_file(&temp_path).ok();

    if let Ok(mut clipboard) = Clipboard::new() {
        if clipboard.get_text().map(|t| t == value).unwrap_or(false) {
            clipboard.clear().ok();
        }
    }
}

fn spawn_clear_daemon(value: &str) {
    let hash = format!("{:x}", Md5::digest(value.as_bytes()));

    if let Ok(exe) = std::env::current_exe() {
        Command::new(exe)
            .args(["--clear-later", &hash, value])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .ok();
    }

    if let Ok(mut clipboard) = Clipboard::new() {
        clipboard.set_text(value).ok();
    }
}

fn init_mode(path: &PathBuf) {
    if path.exists() {
        eprintln!("File already exists: {}", path.display());
        std::process::exit(1);
    }

    let password = rpassword::prompt_password("New master password: ").unwrap();
    let confirm = rpassword::prompt_password("Confirm password: ").unwrap();

    if password != confirm {
        eprintln!("Passwords don't match");
        std::process::exit(1);
    }

    let store = data::example_store();
    let json = data::serialize(&store).unwrap();
    let encrypted = crypto::encrypt(&json, &password).unwrap();

    std::fs::write(path, encrypted).unwrap();
    println!("Created: {}", path.display());
    println!("Example entries added. Use --edit to customize.");
}

fn edit_mode(path: &PathBuf) {
    let encrypted = std::fs::read(path).unwrap_or_else(|e| {
        eprintln!("Failed to read {}: {}", path.display(), e);
        std::process::exit(1);
    });

    let password = rpassword::prompt_password("Master password: ").unwrap();

    let decrypted = crypto::decrypt(&encrypted, &password).unwrap_or_else(|e| {
        eprintln!("{}", e);
        std::process::exit(1);
    });

    let temp_file = std::env::temp_dir().join("passlock_edit.json");
    std::fs::write(&temp_file, &decrypted).unwrap();

    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vim".to_string());

    loop {
        let status = std::process::Command::new(&editor)
            .arg(&temp_file)
            .status()
            .unwrap_or_else(|e| {
                eprintln!("Failed to launch {}: {}", editor, e);
                std::process::exit(1);
            });

        if !status.success() {
            eprintln!("Editor exited with error");
            std::fs::remove_file(&temp_file).ok();
            std::process::exit(1);
        }

        let edited = std::fs::read(&temp_file).unwrap();

        match data::deserialize(&edited) {
            Ok(_) => {
                std::fs::remove_file(&temp_file).ok();
                let re_encrypted = crypto::encrypt(&edited, &password).unwrap();
                std::fs::write(path, re_encrypted).unwrap();
                println!("Saved: {}", path.display());
                break;
            }
            Err(e) => {
                eprintln!("Invalid JSON: {}", e);
                eprint!("Press Enter to edit again, or Ctrl+C to abort: ");
                std::io::Write::flush(&mut std::io::stderr()).ok();
                let mut buf = String::new();
                std::io::stdin().read_line(&mut buf).ok();
            }
        }
    }
}

fn run_selector(path: &PathBuf) {
    let encrypted_data = std::fs::read(path).unwrap_or_else(|e| {
        eprintln!("Failed to read {}: {}", path.display(), e);
        std::process::exit(1);
    });

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_always_on_top()
            .with_decorations(false)
            .with_window_level(egui::WindowLevel::AlwaysOnTop)
            .with_window_type(egui::X11WindowType::Dialog)
            .with_inner_size([500.0, 350.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Passlock",
        native_options,
        Box::new(move |_| Ok(Box::new(App::new(encrypted_data)))),
    )
    .unwrap();
}

#[derive(Clone, Copy, PartialEq)]
enum AppState {
    Locked,
    Unlocked,
}

#[derive(Clone, Copy, PartialEq)]
enum Level {
    Site,
    Account,
    Field,
}

struct App {
    state: AppState,
    encrypted_data: Vec<u8>,
    master_password: String,
    unlock_error: Option<String>,
    store: Option<PasswordStore>,
    search: String,
    selected_index: usize,
    level: Level,
    selected_site: Option<String>,
    selected_account: Option<String>,
    status_message: Option<(String, std::time::Instant)>,
    copied_fields: HashSet<(String, String, String)>,
}

impl App {
    fn new(encrypted_data: Vec<u8>) -> Self {
        Self {
            state: AppState::Locked,
            encrypted_data,
            master_password: String::new(),
            unlock_error: None,
            store: None,
            search: String::new(),
            selected_index: 0,
            level: Level::Site,
            selected_site: None,
            selected_account: None,
            status_message: None,
            copied_fields: HashSet::new(),
        }
    }

    fn try_unlock(&mut self) {
        match crypto::decrypt(&self.encrypted_data, &self.master_password) {
            Ok(decrypted) => match data::deserialize(&decrypted) {
                Ok(store) => {
                    self.store = Some(store);
                    self.state = AppState::Unlocked;
                    self.unlock_error = None;
                    self.master_password.clear();
                }
                Err(e) => {
                    self.unlock_error = Some(format!("Invalid data: {}", e));
                }
            },
            Err(e) => {
                self.unlock_error = Some(e);
                self.master_password.clear();
            }
        }
    }

    fn current_entries(&self) -> Vec<(String, String)> {
        let store = match &self.store {
            Some(s) => s,
            None => return vec![],
        };
        let search_lower = self.search.to_lowercase();

        match self.level {
            Level::Site => {
                let mut sites: Vec<_> = store.keys().cloned().collect();
                sites.sort();
                sites
                    .into_iter()
                    .filter(|s| search_lower.is_empty() || s.to_lowercase().contains(&search_lower))
                    .map(|s| {
                        let count = store.get(&s).map(|a| a.len()).unwrap_or(0);
                        (s, format!("{} account(s)", count))
                    })
                    .collect()
            }
            Level::Account => {
                let site = self.selected_site.as_ref().unwrap();
                let accounts = store.get(site).unwrap();
                accounts
                    .iter()
                    .filter(|a| {
                        search_lower.is_empty() || a.name.to_lowercase().contains(&search_lower)
                    })
                    .map(|a| {
                        let field_count = a.fields.len();
                        (a.name.clone(), format!("{} field(s)", field_count))
                    })
                    .collect()
            }
            Level::Field => {
                let site = self.selected_site.as_ref().unwrap();
                let account_name = self.selected_account.as_ref().unwrap();
                let accounts = store.get(site).unwrap();
                let account = accounts.iter().find(|a| &a.name == account_name).unwrap();
                let mut fields: Vec<_> = account.fields.keys().cloned().collect();
                fields.sort();
                fields
                    .into_iter()
                    .filter(|f| search_lower.is_empty() || f.to_lowercase().contains(&search_lower))
                    .map(|f| {
                        let key = (site.clone(), account_name.clone(), f.clone());
                        let indicator = if self.copied_fields.contains(&key) {
                            "✓ copied"
                        } else {
                            "•••••"
                        };
                        (f, indicator.to_string())
                    })
                    .collect()
            }
        }
    }

    fn get_selected_field_value(&self) -> Option<String> {
        if self.level != Level::Field {
            return None;
        }
        let entries = self.current_entries();
        let (field_name, _) = entries.get(self.selected_index)?;
        let store = self.store.as_ref()?;
        let site = self.selected_site.as_ref()?;
        let account_name = self.selected_account.as_ref()?;
        let accounts = store.get(site)?;
        let account = accounts.iter().find(|a| &a.name == account_name)?;
        account.fields.get(field_name).cloned()
    }

    fn copy_current(&mut self, exit_after: bool) {
        if let Some(value) = self.get_selected_field_value() {
            spawn_clear_daemon(&value);

            if let (Some(site), Some(account)) =
                (self.selected_site.clone(), self.selected_account.clone())
            {
                let entries = self.current_entries();
                if let Some((field_name, _)) = entries.get(self.selected_index) {
                    self.copied_fields
                        .insert((site, account, field_name.clone()));
                }
            }

            if exit_after {
                std::process::exit(0);
            } else {
                self.status_message = Some((
                    "Copied! (clears in 60s)".to_string(),
                    std::time::Instant::now(),
                ));
            }
        }
    }

    fn select_current(&mut self) {
        let entries = self.current_entries();
        if let Some((name, _)) = entries.get(self.selected_index) {
            match self.level {
                Level::Site => {
                    self.selected_site = Some(name.clone());
                    self.level = Level::Account;
                    self.search.clear();
                    self.selected_index = 0;
                }
                Level::Account => {
                    self.selected_account = Some(name.clone());
                    self.level = Level::Field;
                    self.search.clear();
                    self.selected_index = 0;
                }
                Level::Field => {
                    self.copy_current(true);
                }
            }
        }
    }

    fn go_back(&mut self) {
        match self.level {
            Level::Site => std::process::exit(0),
            Level::Account => {
                self.level = Level::Site;
                self.selected_site = None;
                self.search.clear();
                self.selected_index = 0;
            }
            Level::Field => {
                self.level = Level::Account;
                self.selected_account = None;
                self.search.clear();
                self.selected_index = 0;
            }
        }
    }

    fn breadcrumb(&self) -> String {
        match self.level {
            Level::Site => "Select site".to_string(),
            Level::Account => format!("{} › Select account", self.selected_site.as_ref().unwrap()),
            Level::Field => format!(
                "{} › {} › Select field",
                self.selected_site.as_ref().unwrap(),
                self.selected_account.as_ref().unwrap()
            ),
        }
    }

    fn render_locked(&mut self, ctx: &egui::Context) {
        ctx.input_mut(|i| {
            if i.key_pressed(egui::Key::Escape) {
                std::process::exit(0);
            }
            if i.key_pressed(egui::Key::Enter) {
                self.try_unlock();
            }
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(40.0);
                ui.label(
                    egui::RichText::new("🔒 Passlock")
                        .color(egui::Color32::WHITE)
                        .size(24.0),
                );
                ui.add_space(20.0);

                ui.label(
                    egui::RichText::new("Enter master password")
                        .color(egui::Color32::GRAY)
                        .size(14.0),
                );
                ui.add_space(8.0);

                let response = ui.add(
                    egui::TextEdit::singleline(&mut self.master_password)
                        .password(true)
                        .desired_width(250.0)
                        .font(egui::TextStyle::Heading)
                        .text_color(egui::Color32::WHITE),
                );
                response.request_focus();

                if let Some(err) = &self.unlock_error {
                    ui.add_space(8.0);
                    ui.label(
                        egui::RichText::new(err)
                            .color(egui::Color32::from_rgb(255, 100, 100))
                            .size(12.0),
                    );
                }

                ui.add_space(16.0);
                ui.label(
                    egui::RichText::new("Press Enter to unlock • Esc to quit")
                        .color(egui::Color32::from_rgb(100, 100, 120))
                        .size(11.0),
                );
            });
        });
    }

    fn render_unlocked(&mut self, ctx: &egui::Context) {
        let ctrl_q = egui::KeyboardShortcut::new(egui::Modifiers::CTRL, egui::Key::Q);
        if ctx.input_mut(|i| i.consume_shortcut(&ctrl_q)) {
            std::process::exit(0);
        }

        let ctrl_y = egui::KeyboardShortcut::new(egui::Modifiers::CTRL, egui::Key::Y);
        let copy_without_exit = ctx.input_mut(|i| i.consume_shortcut(&ctrl_y));

        let entry_count = self.current_entries().len();

        ctx.input_mut(|i| {
            if i.key_pressed(egui::Key::Escape) {
                self.go_back();
            }
            if i.key_pressed(egui::Key::ArrowDown)
                || (i.modifiers.ctrl && i.key_pressed(egui::Key::N))
            {
                if entry_count > 0 {
                    self.selected_index = (self.selected_index + 1) % entry_count;
                }
            }
            if i.key_pressed(egui::Key::ArrowUp)
                || (i.modifiers.ctrl && i.key_pressed(egui::Key::P))
            {
                if entry_count > 0 {
                    self.selected_index = self
                        .selected_index
                        .checked_sub(1)
                        .unwrap_or(entry_count - 1);
                }
            }
            if i.key_pressed(egui::Key::Enter) {
                self.select_current();
            }
        });

        if copy_without_exit && self.level == Level::Field {
            self.copy_current(false);
        }

        if let Some((_, time)) = &self.status_message {
            if time.elapsed() > Duration::from_secs(2) {
                self.status_message = None;
            }
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.spacing_mut().item_spacing = egui::vec2(0.0, 4.0);

            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new(self.breadcrumb())
                        .color(egui::Color32::from_rgb(150, 150, 170))
                        .size(12.0),
                );
                if let Some((msg, _)) = &self.status_message {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(
                            egui::RichText::new(msg)
                                .color(egui::Color32::from_rgb(100, 200, 100))
                                .size(12.0),
                        );
                    });
                }
            });

            ui.add_space(4.0);

            let response = ui.add(
                egui::TextEdit::singleline(&mut self.search)
                    .hint_text("Type to filter...")
                    .desired_width(f32::INFINITY)
                    .font(egui::TextStyle::Heading)
                    .text_color(egui::Color32::WHITE),
            );
            response.request_focus();

            if response.changed() {
                self.selected_index = 0;
            }

            ui.add_space(8.0);
            ui.separator();
            ui.add_space(4.0);

            egui::ScrollArea::vertical().show(ui, |ui| {
                let entries = self.current_entries();

                for (idx, (name, desc)) in entries.iter().enumerate() {
                    let is_selected = idx == self.selected_index;

                    let bg_color = if is_selected {
                        egui::Color32::from_rgb(70, 130, 180)
                    } else {
                        egui::Color32::TRANSPARENT
                    };

                    egui::Frame::NONE
                        .fill(bg_color)
                        .inner_margin(egui::Margin::symmetric(8, 4))
                        .corner_radius(4.0)
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(
                                    egui::RichText::new(name)
                                        .color(egui::Color32::WHITE)
                                        .size(16.0),
                                );
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        ui.label(
                                            egui::RichText::new(desc)
                                                .color(egui::Color32::GRAY)
                                                .size(12.0),
                                        );
                                    },
                                );
                            });
                        });
                }

                if entries.is_empty() {
                    ui.centered_and_justified(|ui| {
                        ui.label(
                            egui::RichText::new("No matches found")
                                .color(egui::Color32::GRAY)
                                .italics(),
                        );
                    });
                }
            });

            if self.level == Level::Field {
                ui.add_space(4.0);
                ui.separator();
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new("Enter: copy & exit • Ctrl+Y: copy & stay • Esc: back")
                            .color(egui::Color32::from_rgb(100, 100, 120))
                            .size(11.0),
                    );
                });
            }
        });
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
        let mut style = (*ctx.style()).clone();
        style.visuals.window_fill = egui::Color32::from_rgb(30, 30, 40);
        style.visuals.panel_fill = egui::Color32::from_rgb(30, 30, 40);
        ctx.set_style(style);

        match self.state {
            AppState::Locked => self.render_locked(ctx),
            AppState::Unlocked => self.render_unlocked(ctx),
        }
    }
}
