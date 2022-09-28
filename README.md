# Certificate Service


## Configure

Create cs.properties.[dev|eval] and cs.properties.prod  from cs.properties.tmpl

```
## Dependencies

See README.dependencies for information on a special step needed to prepare dependencies for the build.


```
## Build

$> mvn clean compile package
```

```
## Install

$> cd ansible

see the README for configuration steps

$> ./install.sh -h (target)
```

```
## tools install

$> cd util

see the README for configuration steps
$> ./install.sh -h (target)
```

