# Auth Tokens

Simple wrappers for tokens passed between services that rely on OAuth 2.0 for user authentication and authorization.

## BearerToken

The value class presenting the OAuth 2.0 [Bearer Token](https://tools.ietf.org/html/rfc6750).

## AuthHeader

A value class used to represent the HTTP Authorization header expected to contain a Bearer Token, and which contains utility methods for extracting the Bearer Token from the header's value.

## BearerTokens

Provides utilities for handling the Bearer Tokens, such as reading tokens from files.

# Usage

Gradle:
```
dependencies {
    compile "com.palantir.tokens:auth-tokens:<version>"
}
```

## Contributing

Before working on the code, if you plan to contribute changes, please read the [CONTRIBUTING](CONTRIBUTING.md) document.

## License

This repository is made available under the [Apache 2.0 License](http://www.apache.org/licenses/LICENSE-2.0).
