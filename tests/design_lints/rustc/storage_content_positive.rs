include!("storage_content_support.rs");

fn main() {
    let content = safety::sanitize_for_storage("safe", "", &redactor::Redactor);
    let empty_content = safety::empty_stored_content();
    let stats = stats::Stats {
        run_id: "fixture-run".to_owned(),
    };
    let mut persistence = persistence::Persistence::new_with_environment(
        false,
        &platform::SystemEnvironment,
    );
    let _receipt = persistence.store(&stats, &content, "fixture");
    let _ = content.stdout();
    let _ = content.stderr();
    let _ = empty_content.stdout();
}
