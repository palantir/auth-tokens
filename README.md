Auth Tokens
===========
Simple wrappers for tokens passed between services that rely on OAuth 2.0 for user authentication and authorization.

BearerToken
-----------
The value class presenting the OAuth 2.0 bearer token.

AuthHeader
----------
The HTTP authentication header for the `BearerToken` that wraps a string in the form of "Bearer [bearer token]".

BearerTokens
------------
Provides utilties for handling the bearer tokens, such as reading tokens from files.

Usage
=====
Gradle:
```
dependencies {
    compile "com.palantir.tokens:auth-tokens:$version"
}
```

Contributors
------------
* Paul Nepywoda ([@pnepywoda](https://github.com/pnepywoda))
* Yang Guan ([@lookuptable](https://github.com/lookuptable))

Contributing
------------
Before working on the code, if you plan to contribute changes, please read the [CONTRIBUTING](CONTRIBUTING.md) document.

License
-------
This repository is made available under the [Apache 2.0 License](http://www.apache.org/licenses/LICENSE-2.0).
