##
## Author......: See docs/credits.txt
## License.....: MIT
##

# What the oracles share and what they vendor: the random password helpers, the bodies the m170x0
# and m2001x families have in common, and the two ciphers no package on PyPI supplies.
#
# It is a package rather than another entry on sys.path because tools/test_module_runner.py puts
# tools/test_modules first there. A helper named after a distribution that exists, gpg for one,
# would otherwise shadow that distribution for the whole run, and the module that wanted the real
# one would get this one instead and hash something else.
