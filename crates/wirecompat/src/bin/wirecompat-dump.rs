//! Writes the Rust-produced wire cases as JSON for `compat/wirefix.sh check`.

fn main() {
    let out = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: wirecompat-dump <out.json>");
        std::process::exit(2);
    });
    let fx = wirecompat::produce();
    let json = serde_json::to_string_pretty(&fx).expect("serialize");
    std::fs::write(&out, json + "\n").expect("write");
    println!(
        "wrote {out}: {} frames, {} session_accept, {} codec, {} compression, {} responses",
        fx.frames.len(),
        fx.session_accept.len(),
        fx.codec.len(),
        fx.compression.len(),
        fx.responses.len()
    );
}
