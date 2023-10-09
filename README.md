# Certificate Service

## Configure

Create cs.properties.[dev|eval] and cs.properties.prod  from cs.properties.tmpl

## Dependencies

See README.dependencies for information on a special step needed to prepare dependencies for the build.

## Build

```bash
mvn clean compile package
```

## Install

```bash
cd ansible

# see the README for configuration steps

./install.sh -h (target)
```

## tools install

```bash
cd util

# see the README for configuration steps

./install.sh -h (target)
```
