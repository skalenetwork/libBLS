# Contributing

<!-- SPDX-License-Identifier: (AGPL-3.0-only OR CC-BY-4.0) -->

Feedback and contributions are very welcome!

Here's help on how to make contributions, divided into the following sections:

-   general information,
-   documentation changes,
-   code changes, and
-   keeping up with external changes.

## General information

For specific proposals, please provide them as
[pull requests](https://github.com/skalenetwork/libBLS/pulls)
or
[issues](https://github.com/skalenetwork/libBLS/issues)
via our
[GitHub site](https://github.com/skalenetwork/libBLS).
For general discussion, feel free to use 
[![Discord](https://img.shields.io/discord/534485763354787851.svg)](https://discord.gg/vvUtWJB)

### Pull requests and different branches recommended

Pull requests are preferred, since they are specific.
For more about how to create a pull request, see
<https://help.github.com/articles/using-pull-requests/>.

We recommend creating different branches for different (logical)
changes, and creating a pull request when you're done into the master branch.
See the GitHub documentation on
[creating branches](https://help.github.com/articles/creating-and-deleting-branches-within-your-repository/)
and
[using pull requests](https://help.github.com/articles/using-pull-requests/).

### How we handle proposals

We use GitHub to track proposed changes via its
[issue tracker](https://github.com/skalenetwork/libBLS/issues) and
[pull requests](https://github.com/skalenetwork/libBLS/pulls).
Specific changes are proposed using those mechanisms.
Issues are assigned to an individual, who works it and then marks it complete.
If there are questions or objections, the conversation area of that
issue or pull request is used to resolve it.

### Two-person review

Our policy is that at least 50% of all proposed modifications will be reviewed
before release by a person other than the author,
to determine if it is a worthwhile modification and free of known issues
which would argue against its inclusion
(per the Gold requirement two_person_review).

We achieve this by splitting proposals into two kinds:

1.  Low-risk modifications.  These modifications are being proposed by
    people authorized to commit directly, pass all tests, and are unlikely
    to have problems.  These include documentation/text updates
    (other than changes to the criteria) and/or updates to existing gems
    (especially minor updates) where no risk (such as a security risk)
    have been identified.  The project lead can decide that any particular
    modification is low-risk.
2.  Other modifications.  These other modifications need to be
    reviewed by someone else or the project lead can decide to accept
    the modification.  Typically this is done by creating a branch and a
    pull request so that it can be reviewed before accepting it.

### Contributor License Agreement (CLA)

All contributions must agree to the 
[SKALE Network Contributor License Agreement](https://cla.skale.network).
This is derived from Apache Software Foundations’ Individual Contributor License 
Agreement v2.0, and it's purpose is to ensure that the guardian of a project's 
outputs has the necessary ownership or grants of rights over all contributions 
to allow them to distribute under the chosen license.

Simply submitting a contribution implies this agreement, however,
for a pull request to be accepted, you must use the 
[SKALE Network CLA assistant](https://cla.skale.network), which 
is one of the requirement for pull request checks.

### License (AGPL)

All (new) contributed material must be released
under the [AGPL-3.0-only license](./LICENSE), with exception to material included
under the `third_party` directory.
All new contributed material
that is not executable, including all text when not executed,
is also released under the
[Creative Commons Attribution 4.0 International (CC BY 4.0) license](https://creativecommons.org/licenses/by/4.0/) or later.

### We are proactive

In general we try to be proactive to detect and eliminate
mistakes and vulnerabilities as soon as possible,
and to reduce their impact when they do happen.
We use a defensive design and coding style to reduce the likelihood of mistakes,
a variety of tools that try to detect mistakes early,
and an automatic test suite with significant coverage.
We also release the software as open source software so others can review it.

Since early detection and impact reduction can never be perfect, we also try to
detect and repair problems during deployment as quickly as possible.
This is _especially_ true for security issues; see our
[security information](docs/security.md) for more.

### No trailing whitespace

Please do not use or include trailing whitespace
(spaces or tabs at the end of a line).
Since they are often not visible, they can cause silent problems
and misleading unexpected changes.
For example, some editors (e.g., Atom) quietly delete them by default.

## Documentation changes

Most of the documentation is in "markdown" or "mdx" format.
All markdown files use the .md filename extension, otherwise .mdx for mdx files.

Where reasonable, limit yourself to Markdown
that will be accepted by different markdown processors
(e.g., what is specified by CommonMark or the original Markdown)
In practice we use
the version of Markdown implemented by GitHub when it renders .md files,
and you can use its extensions
(in particular, mark code snippets with the programming language used).
This version of markdown is sometimes called
[GitHub-flavored markdown](https://help.github.com/articles/github-flavored-markdown/).
In particular, blank lines separate paragraphs; newlines inside a paragraph
do _not_ force a line break.
Beware - this is _not_
the same markdown algorithm used by GitHub when it renders
issue or pull comments; in those cases
[newlines in paragraph-like content are considered as real line breaks](https://help.github.com/articles/writing-on-github/);
unfortunately this other algorithm is _also_ called
GitHub rendered markdown.
(Yes, it'd be better if there were standard different names
for different things.)

Do not use trailing two spaces for line breaks, since these cannot be
seen and may be silently removed by some tools.
Instead, use <tt>&lt;br /></tt> (an HTML break).

## Code changes

### Code style and formatting

The code style is defined by `.clang-format`, and in general, all C++ files 
should follow it. Files with minor deviations from the defined style are still 
accepted in PRs; however, unless explicitly marked with `// clang-format off` 
and `// clang-format on`, these deviations will be rectified any commit soon 
after.

Exercise the [principle of least privilege](https://en.wikipedia.org/wiki/Principle_of_least_privilege) 
where reasonable and appropriate. Prefer less-coupled cohesive code.

## How to check proposed changes before submitting them

Checking the code on at least one configuration is essential; if you only have
a hasty fix that doesn't even compile, better make an issue and put a link to
your commit into it (with an explanation what it is about and why).

### clang-format

We strongly recommend using clang-format or, even better, use an IDE that
supports it. This will lay a tedious task of following the assumed
code style from your shoulders over to your computer.

## Keeping up with external changes

The installer adds a git remote named 'upstream'.
Running 'git pull upstream master' will pull the current version from
upstream, enabling you to sync with upstream.

You can reset this, if something has happened to it, using:

```bash
git remote add upstream \
    https://github.com/skalenetwork/libBLS.git
```

## Attribution

This text is based on CONTRIBUTING.md from CII Best Practices Badge project, 
which is a collective work of its contributors (many thanks!). The text itself 
is licensed under CC-BY-4.0.