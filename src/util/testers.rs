
use regex::Regex;
use lazy_static::lazy_static;
use crate::tokeniser;

pub fn is_word_alphanumeric<'a>(w: impl Into<&'a str>) -> bool {
    lazy_static! {
        /**
         * Only allow ascii alphanumeric words, no empty strings, with _ and -
         */
        static ref RE: Regex = Regex::new(r"^[a-zA-Z\-_][a-zA-Z0-9\-_]+$").unwrap();
    }

    RE.is_match(w.into())
}

pub fn is_word_numeric<'a>(w: impl Into<&'a str>) -> bool {
    lazy_static! {
        /**
         * Only allow ascii numeric words, no empty strings, with _
         */
        static ref RE: Regex = Regex::new(r"^[-+]?[0-9][0-9_]*$").unwrap();
    }

    RE.is_match(w.into())
}

pub fn is_operator<'a>(w: impl Into<&'a str> + Copy) -> bool {
    let ops = tokeniser::get_operators();
    
    ops.get_key_value(w.into()) != None
}