

pub fn parse_number(raw: impl Into<String>) -> usize {
    let raw: String = raw.into();
    let raw = raw.replace("_", "");

    let num: usize = match raw.parse::<usize>() {
        Ok(n) => n,
        Err(e) => {
            println!("Invalid number: {}\n{}", raw, e);
            0
        }
    };
    num
}