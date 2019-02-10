# Florentines

Florentines are [the best biscuit in the world](https://www.deliaonline.com/recipes/main-ingredient/chocolate/florentines)
and also now a new secure token format that can be used instead of [JWT](https://jwt.io) or [Macaroons](http://macaroons.io).

Like JWTs, Florentines are a flexible format that supports authentication and encryption. Like Macaroons, Florentines
support *contextual caveats* to allow a security token to be restricted after it has been issued.

## Features
 - Extremely simple HMAC-based authentication. If you can use a `HS256` JWT then you can use a Florentine.
 - Easy [authenticated encryption](https://en.wikipedia.org/wiki/Authenticated_encryption).
 - [Misuse-resistant](https://tools.ietf.org/html/rfc5297#section-1.3.2) encryption.
 - Ensures distinct keys are derived for different types of messages (but can be cached).
 - Supports both secret-key and public-key cryptography, with *the same security properties*.
 - Can support [Macaroon-like caveats](https://ai.google/research/pubs/pub41892), with a simple JSON syntax.
 - Small number of supported algorithms, all of which are interchangeable (no gotchas when switching algorithm).
 - Very simple but secure serialisation format.
 
Non-features:
 - No support for public key signatures at the moment. All messages are *authenticated* rather than signed.
 
See [the spec](doc/spec.md) for details.
