use crate::tokeniser::{
    TokenType,
    Token,
    Location,
};

use crate::util::testers;

pub struct Tokeniser{
    code: String,
    tokens: Vec<Token>
}


impl Tokeniser {
    pub fn new(code: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            tokens: Vec::new()
        }
    }

    pub fn tokenise(&mut self){
        // split the code by spaces and tabs
        let words = self.code.split(|c| {
                                                            c == ' ' || c == '\t'
                                                        });
        
        for word in words {
            match word.clone() {
                w if testers::is_word_alphanumeric(w) => {
                    // println!("Alphanumeric word: '{}'", w);
                    self.tokens.push(Token::new(Location::new(0, 0), w, TokenType::Word))
                },

                w if testers::is_word_numeric(w) => {
                    // println!("Numeric word: '{}'", w);
                    self.tokens.push(Token::new(Location::new(0, 0), w, TokenType::Integer))
                },

                w if testers::is_operator(w) => {
                    // println!("Operator: '{}'", w);
                    self.tokens.push(Token::new(Location::new(0, 0), w, TokenType::Operator))
                },
                
                w => println!("Unknown word {}", w),
            }
        }
    }

    

    pub fn get_tokens(&self) -> Vec<Token> {
        self.tokens.clone()
    }
}