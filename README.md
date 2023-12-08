# Certificate Service

The certificate service allows users to find and create certs using one of our two cert provides, Incommon and UWCA.

SLO: 90% availability. This is a developer-facing tool, and callers are usually willing to wait or
email us if any issues come up.

Links:

*   Prod endpoint: https://iam-tools.u.washington.edu/cs/
*   Test endpoint: https://iam-tools-test.u.washington.edu/cs/

## Cloning

Use `git clone --recurse-submodules` to clone this repo, because it uses
[submodules](https://git-scm.com/book/en/v2/Git-Tools-Submodules).

## Configure

Create cs.properties.[dev|eval] and cs.properties.prod from cs.properties.tmpl

## Build

```
$> mvn clean compile package
```

## Install

```
$> cd ansible

# see the README for configuration steps

$> ./install.sh -h (target)
```

## tools install

```
$> cd util

#see the README for configuration steps
$> ./install.sh -h (target)
```

## Best practices

This repository uses [`pre-commit`](https://pre-commit.com/)
to test and verify the package before commits.
