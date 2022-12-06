
use crate::tokeniser::{
    TokenType,
    Token,
    // Location,
};

use crate::util::parsers;

#[derive(Debug, Clone)]
pub struct Interpreter {
    tokens: Vec<Token>,
    stack: Vec<usize>
}

impl Interpreter {

    pub fn new(tokens: Vec<Token>) -> Self {
        Self { 
            tokens: tokens,
            stack: Vec::new()
        }
    }

    fn stack_pop(&mut self) -> Result<usize, &str> {
        match self.stack.pop() {
            Some(i) => Ok(i),
            None => Err("Pop from empty stack")
        }
    }

    fn stack_push(&mut self, item: usize) -> Result<(), &str>{
        self.stack.push(item);
        Ok(())
    }

    pub fn run(&mut self) -> Result<(), String>{
        let tokens = self.tokens.clone();
        for token in tokens {
            match token {
                t if t.typ == TokenType::Integer => {
                    self.stack.push(parsers::parse_number(t.raw));
                }

                t if t.typ == TokenType::Operator => {
                    match t.raw.as_str() {
                        "+" => {
                            let a = self.stack_pop()?;
                            let b = self.stack_pop()?;
                            self.stack_push(b + a)?;
                        },
                        "-" => {
                            let a = self.stack_pop()?;
                            let b = self.stack_pop()?;
                            self.stack_push(b - a)?;
                        }
                        "*" => {
                            let a = self.stack_pop()?;
                            let b = self.stack_pop()?;
                            self.stack_push(b * a)?;
                        }
                        "/" => {
                            let a = self.stack_pop()?;
                            let b = self.stack_pop()?;
                            self.stack_push(b / a)?;
                        }
                        
                        _ => println!("Unknown operator: '{}'", t.raw)
                    }
                }

                t if t.typ == TokenType::Word => {
                    match t.raw.as_str() {

                        "print" => {
                            println!("{}", self.stack_pop()?);
                        }

                        _ => {
                            println!("Unknown word: '{}'", t.raw);
                        }
                    }
                }

                _ => ()
            }
            // println!("Stack: {:#?}", self.stack);
        };
        Ok(())
    }
}