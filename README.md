# Florentines

Florentines are [the best biscuit in the world](https://www.deliaonline.com/recipes/main-ingredient/chocolate/florentines)
and also now a new auth token format that can be used instead of [JWT](https://jwt.io) or [Macaroons](http://macaroons.io).

![Image of Florentine biscuits](https://photos1.blogger.com/hello/164/977/1024/IMG_3466.jpg)
(Image credit: https://becksposhnosh.blogspot.com/2005/11/spiced-sesame-orange-florentines-with.html CC-By-NC-ND)

Like JWTs, Florentines are a flexible format that supports authentication and encryption. Unlike JWTs, Florentines only
support a single algorithm suite and provide no built-in way to specify an alternative, avoiding a whole class of security
vulnerabilities that have plagued JWTs. Like Macaroons, Florentines
support *contextual caveats* to allow a security token to be restricted after it has been issued. Indeed, a Florentine
*is* a Macaroon, with some extra bits:

 - The payload of a Florentine is encrypted using a misuse-resistant authenticated encryption mode (MRAE).
 - Florentines use public key (hybrid) cryptography, so you don't need to share your secret key to let someone verify
   a Florentine. This is in the form of a [multi-recipient authenticated KEM](https://neilmadden.blog/2021/02/16/when-a-kem-is-not-enough/).
   No signature schemes have been harmed (or used) in the construction of Florentines.
 - A standard payload format for identity claims, loosely modelled on JWT Claims Sets, and standard
   caveats to constrain those tokens.
   
## Reply-able encryption

Florentines can be used as a more or less drop-in replacement for JWTs or Macaroons, but they also support some
more advanced features. In particular, Florentines support a `reply` operation which allows a Florentine to be 
constructed in reply to another Floretine that has been received. The encryption and authentication keys for the
reply are derived from the static keys of the sender, fresh ephemeral keys, and the ephemeral public key of the
original Florentine. This ensures that the response Florentine has some stronger security properties:

 - (Perfect) Forward Secrecy: the response message cannot be decrypted even if the long-term secret keys of both
   parties are subsequently compromised.
 - Stronger authentication properties: in particular, replay protection and resistance to Key Compromise Impersonation (KCI)
   attacks.
   
This `reply` operation is useful for implementing challenge-response protocols. For example, you could implement
a version of OAuth or OpenID Connect using Florentines for the authZ/authN request and response. The strong security
properties of the reply message would allow confidential data to be included directly in the response (avoiding an
additional roundtrip), with much stronger protections than existing ID Token encryption schemes. The strong authentication
properties would also allow removing existing anti-replay mechanisms such as state parameters, nonces, and PKCE
challenges.

For more on reply-able encryption, see [my blog post on the topic](https://neilmadden.blog/2021/04/08/from-kems-to-protocols/).

Cryptographers and security types with applied crypto experience can read more in the
[design notes](doc/notes.md). BEWARE! These notes assume considerable crypto background knowledge,
and working knowledge of modern cryptographic schemes.

## Prototype

A working prototype in Java is in the works, which I will push to this repo shortly (Apache 2 licensed).
I'll then see about a Go or Rust version for the cool kids.