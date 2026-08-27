include!("storage_content_support.rs");

fn main() {
    let _unchecked = <safety::SanitizedStoredContent as From<(String, String)>>::from((
        "raw stdout".to_owned(),
        "raw stderr".to_owned(),
    ));
}
