<p align="right">
<a href="https://autorelease.general.dmz.palantir.tech/palantir/auth-tokens"><img src="https://img.shields.io/badge/Perform%20an-Autorelease-success.svg" alt="Autorelease"></a>
</p>

[![Circle CI](https://circleci.com/gh/palantir/auth-tokens.svg?style=shield)](https://circleci.com/gh/palantir/auth-tokens)
[ ![Download](https://api.bintray.com/packages/palantir/releases/auth-tokens/images/download.svg) ](https://bintray.com/palantir/releases/auth-tokens/_latestVersion)


# Auth Tokens

Simple wrappers for tokens passed between services that rely on [OAuth 2.0](https://tools.ietf.org/html/rfc6749) for user authentication and authorization.

## BearerToken

The value class presenting the OAuth 2.0 [Bearer Token](https://tools.ietf.org/html/rfc6750).

## AuthHeader

A value class used to represent the HTTP Authorization header expected to contain a Bearer Token, and which contains utility methods for extracting the Bearer Token from the header's value.

## UnverifiedJsonWebToken

Parses and provides insight into a Json Web Token payload.

# Auth Token Filter

Provides a filter to inject user identifier information into slf4j and Jetty logging contexts.

# Usage

Gradle:
```
dependencies {
    compile "com.palantir.tokens:auth-tokens:<version>"
    compile "com.palantir.tokens:auth-tokens-filter:<version>"
}
```

In your server's initialize method:
```java
environment.jersey().register(BearerTokenLoggingFeature.class);
```

This is a jax-rs DynamicFeature which sets up either the `BearerTokenLoggingFilter` or the `BearerTokenCookieLoggingFilter`
in front of each of your endpoints, depending on whether they have a `@HeaderParam("Authorization")` or a `@CookieParam(*) BearerToken`. If your endpoint has neither of these parameters then no filter will be added.

## Contributing

Before working on the code, if you plan to contribute changes, please read the [CONTRIBUTING](CONTRIBUTING.md) document.

## License

This repository is made available under the [Apache 2.0 License](http://www.apache.org/licenses/LICENSE-2.0).
