fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match pipelock_verifier_rs::cli::run(&args) {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(err.exit_code());
        }
    }
}
