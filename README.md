A somewhat [passacre]-compatible password generator with a fast startup.

Configuration is done through `config.h`. Modify it and recompile.


## Caveats

 - YubiKeys are not supported.

 - Skein is not supported.

 - Site name hashing is not supported.

 - Usernames are not supported.
   Prefix your password with a username and a colon for compatibility.

 - Site identifiers are not converted to Punycode automatically.
   Do this manually for compatibility.


## Future features

 - Support for [words in schemata][1] (and therefore Unicode).

 - A switch equivalent to [the `passacre entropy` command][2].

 - Password confirmation, possibly.


[passacre]: https://github.com/habnabit/passacre
[1]: https://passacre.readthedocs.org/en/latest/schema.html#examples
[2]: https://passacre.readthedocs.org/en/latest/commands.html#passacre-entropy
