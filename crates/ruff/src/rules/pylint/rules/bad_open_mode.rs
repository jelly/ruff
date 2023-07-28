use num_traits::ToPrimitive;
use ruff_python_ast::{self as ast, Constant, Expr, Keyword, Operator, Ranged};

use ruff_diagnostics::{Diagnostic, Violation};
use ruff_macros::{derive_message_formats, violation};
use ruff_python_ast::call_path::CallPath;
use ruff_python_ast::helpers::CallArguments;
use ruff_python_semantic::SemanticModel;

use crate::checkers::ast::Checker;

/// ## What it does
/// Checks for files with overly permissive permissions.
///
/// ## Why is this bad?
/// Overly permissive file permissions may allow unintended access and
/// arbitrary code execution.
///
/// ## Example
/// ```python
/// import os
///
/// os.chmod("/etc/secrets.txt", 0o666)  # rw-rw-rw-
/// ```
///
/// Use instead:
/// ```python
/// import os
///
/// os.chmod("/etc/secrets.txt", 0o600)  # rw-------
/// ```
///
/// ## References
/// - [Python documentation: `os.chmod`](https://docs.python.org/3/library/os.html#os.chmod)
/// - [Python documentation: `stat`](https://docs.python.org/3/library/stat.html)
/// - [Common Weakness Enumeration: CWE-732](https://cwe.mitre.org/data/definitions/732.html)
#[violation]
pub struct BadOpenMode;

impl Violation for BadOpenMode {
    #[derive_message_formats]
    fn message(&self) -> String {
        format!("error wrong file mode")
    }
}

/// W1501
pub(crate) fn bad_open_mode(
    checker: &mut Checker,
    func: &Expr,
    args: &[Expr],
    keywords: &[Keyword],
) {
    if checker
        .semantic()
        .resolve_call_path(func)
        .map_or(false, |call_path| {
            matches!(call_path.as_slice(), ["", "open"])
        })
    {
        let call_args = CallArguments::new(args, keywords);
        dbg!("call_args {:?} ", args);
        if let Some(mode_arg) = call_args.argument("mode", 1) {
            dbg!("mode={}", mode_arg);
            if str_value(mode_arg, checker.semantic()) {
                checker
                    .diagnostics
                    .push(Diagnostic::new(BadOpenMode, mode_arg.range()));
            }
        }
    }
}

const fn is_valid_file_mode(c: char) -> bool {
    matches!(c, 'a' | 'w' | 'x' | 'r' | 'b' | 't' | '+')
}

fn str_value(expr: &Expr, model: &SemanticModel) -> bool {
    match expr {
        Expr::Constant(ast::ExprConstant {
            value: Constant::Str(value),
            ..
        }) => value.matches(is_valid_file_mode).count() != value.len(),
        _ => false,
    }
}
