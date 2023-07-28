use std::collections::HashSet;

use ruff_python_ast as ast;
use ruff_python_ast::Constant;
use ruff_python_ast::Expr;
use ruff_text_size::Ranged;

use ruff_diagnostics::{Diagnostic, Violation};
use ruff_macros::{derive_message_formats, violation};

use crate::checkers::ast::Checker;

/// ## What it does
/// Detects an invalid mode for `open()`
///
/// ## Why is this bad?
/// Overly permissive file permissions may allow unintended access and
/// arbitrary code execution.
///
/// ## Example
/// ```python
///
/// fp = open(file, "rwx")
/// ```
///
/// Use instead:
/// ```python
///
/// fp = open(file, "r")
/// ```
///
/// ## References
/// - [Python documentation: `open`](https://docs.python.org/3/library/functions.html#open)
#[violation]
pub struct BadOpenMode {
    mode: String,
}

impl Violation for BadOpenMode {
    #[derive_message_formats]
    fn message(&self) -> String {
        let BadOpenMode { mode } = self;
        format!("`{mode}` is not a valid mode for open")
    }
}

/// W1501
pub(crate) fn bad_open_mode(checker: &mut Checker, call: &ast::ExprCall) {
    // TODO: also check `pathlib.open`
    if checker
        .semantic()
        .resolve_call_path(&call.func)
        .is_some_and(|call_path| matches!(call_path.as_slice(), ["", "open"]))
    {
        if let Some(mode_arg) = call.arguments.find_argument("mode", 1) {
            if let Some(string_value) = str_value(mode_arg) {
                if !is_valid_file_mode(&string_value) {
                    checker.diagnostics.push(Diagnostic::new(
                        BadOpenMode { mode: string_value },
                        mode_arg.range(),
                    ));
                }
            }
        }
    }
}

fn is_valid_file_mode(modes: &String) -> bool {
    let valid_modes = "rwatb+Ux";
    let valid_modes_set: HashSet<char> = valid_modes.chars().collect::<HashSet<_>>();
    let modes_set: HashSet<char> = modes.chars().collect::<HashSet<_>>();

    if modes_set.difference(&valid_modes_set).count() > 0
        || modes.len() > valid_modes.len()
        || modes.len() > modes_set.len()
    {
        return false;
    }

    let creating = modes_set.contains(&'x');
    let writing = modes_set.contains(&'w');
    let mut reading = modes_set.contains(&'r');
    let appending = modes_set.contains(&'a');
    let text = modes_set.contains(&'t');
    let binary = modes_set.contains(&'b');

    if modes_set.contains(&'U') {
        if writing || appending || creating {
            return false;
        }
        reading = true;
    }

    if text && binary {
        return false;
    }

    if [creating, appending, writing, reading]
        .into_iter()
        .filter(|b| *b)
        .count()
        > 1
    {
        return false;
    }

    if creating && writing {
        return false;
    }

    if !(reading || writing || appending || creating) {
        return false;
    }

    true
}

fn str_value(expr: &Expr) -> Option<String> {
    // TODO: does not handle when a variable is used as mode
    match expr {
        Expr::Constant(ast::ExprConstant {
            value: Constant::Str(value),
            ..
        }) => Some(value.to_string()),
        _ => None,
    }
}
