include!("storage_content_support.rs");

fn main() {
    let stats = stats::Stats {
        run_id: "fixture-run".to_owned(),
    };
    let raw_content = "raw content".to_owned();
    let mut persistence = persistence::Persistence::new_with_environment(
        false,
        &platform::SystemEnvironment,
    );
    let _ = persistence.store(&stats, &raw_content, "fixture");
}
