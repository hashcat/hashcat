
This page contains information about packages for hashcat, with guidance [for users](#for-users) and [for package maintainers](#for-package-maintainers).

## For users ##

Many OS packaging systems have a package simply called 'hashcat'.

### Downstream package status ###

Here is a list of downstream packages that include hashcat, as tracked by [Repology](https://repology.org).

[![Packaging status](https://repology.org/badge/vertical-allrepos/hashcat.svg)](https://repology.org/project/hashcat/versions)

## For package maintainers ##

### Runtime requirements ###

[hashcat-requirements.md](hashcat-requirements.md) lists the minimum version of every runtime hashcat
checks, what it does with a device below one, and which libraries are optional. Two points decide most
packaging questions: the CUDA and HIP compiler libraries live in a different package from the driver
and are dependencies of those backends rather than of hashcat, and hardware monitoring is optional
everywhere.

### Packaging guidance ###

If needed, you can disable hardcoded CPU optimization flags with a MAINTAINER_MODE flag.

Compile hashcat with `make MAINTAINER_MODE=1` instead of just `make`.
