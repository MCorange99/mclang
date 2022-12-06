use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
pub enum TokenType {
    Integer,
    Word,
    Operator,
    String,
    Char,
    Keyword,
    Intrinsic
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Location {
    line: usize,
    col: usize
}

impl Location {
    pub fn new(ln: usize, col: usize) -> Self {
        Self {
            line: ln,
            col: col
        }
    }
}

#[derive(Debug, Clone)]
pub struct Token {
    pub typ: TokenType,
    pub raw: String,
    pub loc: Location
}

impl Token {
    pub fn new(loc: Location, raw: impl Into<String>, typ: TokenType) -> Self {
        Self {
            loc: loc,
            raw: raw.into(),
            typ: typ
        }
    }
}
pub fn get_operators() -> HashMap<&'static str, &'static str>{
    HashMap::from([
        ("+", "plus"),
        ("-", "minus"),
        ("/", "divide"),
        ("*", "multiply"),
    ])
}

// pub fn get_builtin() -> Vec<&'static str>{
//     vec![
//         "print"
//     ]
// }