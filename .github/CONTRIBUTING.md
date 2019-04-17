# Contributing

Thank you for considering to help out with the source code! We welcome
contributions from anyone on the internet, and are grateful for even the
smallest of fixes!

**When contributing to this repository, please first discuss the change you wish**
**to make by opening an issue.**

## I don't want to read this whole thing I just have a question!!!

> **Note:** Please don't file an issue to ask a question. You'll get faster 
results by simply [joining our Discord and asking our team there](https://discord.gg/vvUtWJB).

## Pull Request Philosophy

Patchsets should always be focused. For example, a pull request could add a
feature, fix a bug, or refactor code; but not a mixture. Please also avoid super
pull requests which attempt to do too much, are overly large, or overly complex
as this makes review difficult.

## Branch naming convention

Name your branches with one of the following prefixes (`bug/`, `feature/`, or 
`enhancement/`), add the issue number and add a description: `[type]/[issueNum]-[change-with-hyphens]`. 

Examples:

-   `bug/87-archives-crash-app`
-   `bug/92-font-size-update-not-immediate`
-   `enhancement/56-add-date-search`
-   `enhancement/63-show-number-tweets-in-search-results`

### Features

When adding a new feature, thought must be given to the long term technical debt
and maintenance that feature may require after inclusion. Before proposing a new
feature that will require maintenance, please consider if you are willing to
maintain it (including bug fixing). If features get orphaned with no maintainer
in the future, they may be removed by the Repository Maintainer.

### Refactoring

Refactoring is a necessary part of any software project's evolution. The
following guidelines cover refactoring pull requests for the project.

There are three categories of refactoring, code only moves, code style fixes,
code refactoring. In general refactoring pull requests should not mix these
three kinds of activity in order to make refactoring pull requests easy to
review and uncontroversial. In all cases, refactoring PRs must not change the
behavior of code within the pull request (bugs must be preserved as is).

Project maintainers aim for a quick turnaround on refactoring pull requests, so
where possible keep them concise and easy to verify.

Pull requests that refactor the code should not be made by new contributors. It
requires a certain level of experience to know where the code belongs to and to
understand the full ramification (including rebase effort of open pull requests).

Trivial pull requests or pull requests that refactor the code with no clear
benefits may be immediately closed by the maintainers to reduce unnecessary
workload on reviewing.
