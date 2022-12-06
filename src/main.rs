mod tokeniser;
mod interpreter;
mod util;
mod builtin;

use tokeniser::Tokeniser;
const CODE: &str = "10 14 + print";

fn main() -> Result<(), String>{
    let mut tokens = Tokeniser::new(CODE);
    tokens.tokenise();

    // println!("tokens: {:#?}", tokens.get_tokens());

    let mut runner = interpreter::Interpreter::new(
        tokens.get_tokens()
    );
    runner.run()?;

    Ok(())

}
