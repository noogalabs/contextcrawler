//! Doc comment at top of module — should be preserved
//! Multiple lines of documentation
//! Explaining what this module does

use std::collections::HashMap;

/// Public API doc comment — kept
pub fn add(a: i32, b: i32) -> i32 {
    // Inline comment — stripped
    a + b
}

/* Block comment
 * spanning multiple lines
 * also stripped
 */
fn private_helper() -> Vec<String> {
    vec![] // trailing comment stripped
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works() { assert_eq!(add(1, 2), 3); }
}
