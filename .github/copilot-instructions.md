# GitHub Copilot Custom Review Instructions

## Code Review Focus

When reviewing code in pull requests:
- First, validate that the logic introduced or changed is correct.
- Second, check that all code follows the code style and engineering practices below.

## Code Guidelines

### General Style
- Line length must not exceed 100 characters.
- Function length must be ≤ 100 lines.
- All code, including comments, must be in English with correct spelling.
- Comments must be professional and explanatory — no jokes or non-technical remarks.
- Do not mix naming conventions (e.g., snake_case with camelCase) within the same file.
- Variable and function names must be descriptive and searchable.

### Code Quality
- No commented-out code should remain.
- Avoid redundancy: duplicated code should be replaced by functions.
- Do not spam logs. Limit logging at info level to a few lines per block.
- Prefer private methods over public unless necessary.
- Use standard libraries for string manipulation and other common tasks.
- Raw output (e.g., `cout`) is not allowed except during initial/termination stages.
- Do not keep unused functions, variables, or types in the codebase.
- Avoid magic numbers - All numeric constants must be named via constexpr, const, or #define with descriptive names
- Avoid deep nesting — refactor with early returns or helper functions.

### Memory and Safety
- Avoid raw pointers. If used, perform null checks before dereferencing.
- Handle all error cases explicitly.
- All shared data structures accessed concurrently must be properly synchronized.

### Documentation and Comments
- Each new function must have a comment or a descriptive name explaining its purpose.
- Each new global/class field must have a comment or very descriptive name.
- Complex code must be commented sufficiently to explain the algorithm.

### Function Best Practices
- Functions must do one thing only.
- All inputs (preconditions) and outputs (postconditions) must be checked.

### Testing

- For each code change, ensure tests are updated or added where applicable.
- New logic should be covered by unit or integration tests.
- Code that is hard to test should be simplified or split into testable units.
