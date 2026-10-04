use winresource::WindowsResource;

fn windows_binary() {
    let mut res = WindowsResource::new();
    res.set_icon("res/windows/icon.ico");
    res.set_manifest_file("res/windows/manifest.xml");

    res.compile().unwrap();
}

fn main() {
    let target = std::env::var("TARGET").unwrap_or_default();

    if target.contains("windows") {
        windows_binary();
    }
}
