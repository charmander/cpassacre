# cpassacre

A somewhat [passacre][]-compatible password generator with a fast startup.

Configuration is done through `config.h`. Modify it and recompile.


## Caveats

 - YubiKeys are not supported.

 - Skein is not supported.

 - Site name hashing is not supported.

 - [Words in schemata][1] are not supported.

 - Usernames are not supported.
   Prefix your password with a username and a colon for compatibility.

 - Site identifiers are not converted to Punycode automatically.
   Do this manually for compatibility.

 - Password confirmation is not supported.


[passacre]: https://github.com/habnabit/passacre
[1]: https://passacre.readthedocs.org/en/latest/schema.html#examples
