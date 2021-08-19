# Florentines Design Notes

## Overview

A Florentine is a Macaroon, where the identifier part of the Macaroon is encrypted and
used as a general payload area. The payload could be a simple random identifier that links
to a database record, or it could be some structured format like Protobuf or JSON. The
Florentine has a *preamble* section that contains encapsulated keys for each recipient.
A recipient decapsulates its encapsulated key blob to recover the MAC and encryption keys
for the rest of the message. The encryption key is used to decrypt the Macaroon identifier,
yielding a normal Macaroon that can then be verified with the MAC key.

The specific flavour of Macaroons that Florentines build on is the "version 2 binary" format
of libmacaroons. Once a Florentine has been decrypted, the resulting Macaroon should verify
with any library compatible with this format.

## Cryptographic Details

Florentines use a KEM/DEM paradigm to guide the design. The KEM is a multi-recipient authenticated
Tag-KEM. The DEM is a compactly-committing mode based on the Synthetic IV (SIV) mode of operation,
providing misuse-resistant authenticated encryption. The overall construction is designed to
provide *insider security*. That is, if Alice sends a message to Bob and Charlie, then Bob should
not be able to use his decapsulated message key to create a forgery that Charlie will think comes
from Alice.

There is currently only a single algorithm suite defined (described in the next sections), with one
variant. There is (deliberately) no way to specify the algorithm in the structure of a Florentine
itself - the sender and all recipients must already know and have agreed on the algorithm suite in
advance.

### DEM

The Data Encapsulation Mechanism (DEM) is based on SIV mode, but with some changes. SIV-AES uses
AES-CMAC as the MAC and AES in CTR mode as the cipher. It also uses a clever construction called `s2v`
to convert CMAC from a MAC that takes a single input to one that takes multiple inputs. Florentines
instead use the mechanisms already present in Macaroons to implement a similar mode:

 - We use HMAC-SHA-256 instead of AES-CMAC as the MAC. This also ensures that the final DEM construction
   is compactly committing.
 - Rather than `s2v`, we use HMAC in a *cascade* construction where the tag output from processing the
   first authenticated data input is used as the key to authenticate the second, and so on. This is
   exactly the same mechanism used by Macaroons to allow appending caveats. To avoid length extension
   attacks, the final tag is passed through HMAC again using a separate key to derive the SIV, which is
   then truncated to 128 bits. The overall construction is essentially identical to NMAC, on which HMAC
   itself is based, except that NMAC is used to convert a fixed-input PRF into a variable-input PRF,
   whereas we are using the same construction to convert a variable-input PRF with one argument into a
   variable-input PRF over multiple inputs.
 - We use XSalsa20 for encryption rather than AES-CTR, because Macaroons already include XSalsa20 for
   encryption of third-party caveats.
   
In pseudocode, the encryption algorithm looks like the following:
```
function dem_encrypt(key, assoc_data[], payload):
  // Expand 256-bit key into 3 separate 256-bit keys
  (macKey, encKey, finKey) := HKDF-Expand(key, <context>, 256*3)
  for block in assoc_data:
    macKey = HMAC-SHA-256(macKey, block)
  end
  macKey = HMAC-SHA-256(macKey, payload)
  siv = HMAC-SHA-256(finKey, macKey)[0..15]
  xsalsa20(encKey, siv, payload)
  return (payload, siv)
end

function dem_decrypt(key, assoc_data[], payload, siv):
  (macKey, encKey, finKey) := HKDF-Expand(key, <context>, 256*3)
  xsalsa20(encKey, siv, payload)
    for block in assoc_data:
    macKey = HMAC-SHA-256(macKey, block)
  end
  macKey = HMAC-SHA-256(macKey, payload)
  siv' = HMAC-SHA-256(finKey, macKey)[0..15]
  if not constant_time_equals(siv, siv'):
    destroy payload
    return error
  end
  return payload
end
```
The `<context>` here is a byte string that is discussed later.

As for SIV mode itself, this encryption scheme only provides Deterministic Authenticated
Encryption (DAE) by default and so is not semantically secure. However, including a random
nonce argument in the associated data inputs (typically as the last input before the payload)
makes it semantically secure, achieving (nonce-reuse) Misuse Resistant Authenticated Encryption (MRAE).
The standard definition of a DEM in the KEM/DEM paradigm allows the DEM to be deterministic
because the KEM is required to output a fresh random DEM key on each use, so keys are never
reused. The use of SIV mode ensures that even if this requirement is violated, a strong measure
of security is still retained - and I'm assuming that it makes no sense to mandate a random
nonce argument if you are worried that generating a random key may fail!

That said, there have been concerns raised in the literature against deterministic DEMs, and also
against SIV mode, when considered in a multi-party setting. In recognition of these concerns,
the Florentines DEM mandates 256-bit keys to ensure at least a 128-bit security level is always met even
in worst-case multi-party assumptions.

Note that for compatibility with libmacaroons, the macKey is not used directly but first
passed through another key-derivation step using a known constant. We will ignore this in
these design notes, but it will be required for interoperability.

### KEM

The Key Encapsulation Mechanism (KEM) is based on X25519 using a combination of
ephemeral-static and static-static key agreement modes to provide sender (origin)
authentication, effectively doing:
```
  (esk, epk) = gen_key_pair()
  es = X25519(esk, recipient_pk)
  ss = X25519(sender_sk, recipient_pk)
  wrapKey = HKDF-Extract(<salt>, es || ss)
```
The `<salt>` argument here defaults to an all zero 32-byte value, but it's also possible
to define variants of the algorithm that use a different value here such as a Pre-Shared
Key (PSK) or a public constant salt value for a specific protocol or application.

To support multiple recipients, this derived key is not used directly as the DEM key.
Instead, a fresh random DEM key is first generated and used to authenticate and encrypt
the payload Macaroon. This random DEM key is then wrapped for each recipient using the
same SIV algorithm described in the last section for the DEM, with the following inputs:

 - The SIV for the DEM payload is included as associated data, so that the entire message
   is authenticated by the KEM. This is what ensures insider security discussed earlier.
   This relies on the DEM being compactly-committing so that it is not possible to find
   another key/message pair which produces the same tag. (Technically, we require the MAC
   to be Target Collision Resistant).
 - A *salted key ID* for the recipient is also included as associated data (described later).
 - As is a JSON header section, also described shortly.
 - The random DEM key is then the payload, and is encrypted as well as authenticated.

Note that in this case there is no nonce/IV input by default, and so this algorithm only
provides Deterministic Authenticated Encryption (DAE), which is what you want for key wrapping
(the random DEM key being encrypted is assumed to be random enough and fresh).

The `<context>` string used to expand the `wrapKey` into encryption, MAC, and finalisation keys
in the KEM is a byte string built up based on the NIST "concatenation format". It includes an
algorithm identifier (`Florentine-Message-X25519-XS-HS256-SIV` is the identifier for the one algorithm
defined here), the sender and recipient public keys, and the ephemeral public key. This ensures
the overall message is not malleable (even "benignly malleable") and is cryptographically bound to
the context it is used.

The KEM outputs a Florentine *preamble* which is prefixed to the Macaroon. It contains the ephemeral
public key (which is shared between all recipients), a sender key ID, a JSON header section (see below),
and then the wrapped keys for each recipient. Each wrapped key consists of a salted Key ID for that recipient,
then the encrypted DEM key and SIV tag output by the key-wrapping process. Each recipient scans through the
blocks until it finds a matching key ID, and then recovers the wrapping key by the following calculations:
```
  es = X25519(recipient_sk, epk)
  ss = X25519(recipient_sk, sender_pk)
  wrapKey = HKDF-Extract(<salt>, es || ss)
```
It then uses the SIV decryption to recover the DEM key, passing in the same associated data.

### Salted Key IDs

As Florentines can be sent to many recipients, it is useful to have a more efficient way of decrypting than
just trying to decrypt each wrapped key in turn until you find one that succeeds. To help with this, wrapped
key blocks are preceeded by a 6-byte salted Key ID that can be matched against locally available keys. The
Key ID is salted and truncated to 6 bytes to reduce potential for abuse as a tracking mechanism.

The salt value is defined as `salt = SHA-256(encode(epk))` - i.e., a hash of the encoded ephemeral public key
used for this message. Salted Key IDs are then calculated as follows:
```
function salted_key_id(salt, pk):
  return HKDF-Extract(salt, encode(pk)) 
end
```
The `encode()` function returns the 32-byte little-endian representation of the x-coordinate of the Curve25519
public key.

Each recipient can calculate the same salted Key ID values for each candidate key-pair it has locally and then
match those against the wrapped key blocks in the Florentine preamble. Because the 6-byte value is not large
enough to guarantee no collisions (deliberately!), recipients should be prepared that key-unwrapping might
still fail: in which case they should continue looking for other matching blocks.

### JSON Header

(Note: this is part that I am least happy with - almost all security vulnerabilities in JWTs have involved the
header in some respect, so they are hazardous material. But I think there are still some genuine uses for them).

Like JWTs, Florentines include a small JSON header section. However, they are almost completely unlike JWTs in
most respects. Crucially, you don't need to parse the header before authenticating the message - nothing in the
header affects the choice or parameters of cryptographic algorithms, which are all determined by the algorithm
suite (which is agreed by all parties ahead of time). Furthermore, unlike JWTs, the header is authenticated by
the KEM and is not included as associated data in the encryption of the message payload. So when a recipient has
successfully decapsulated the DEM key they are already assured that the JSON header is authentic before they
even process the rest of the message. This means that potentially future extensions to Florentines could safely
introduce header elements that influence how the body of the Florentine is processed, but no such headers are
defined initially.

There is no equivalent of the following JWT headers in Florentines: `alg`, `enc`, `jwk`, `jku`, `x5c`, `x5u`.

I recognise that JSON is not an uncontroversial choice, and some people may prefer CBOR or MessagePack or Protobuf,
or something else entirely. I'm also aware that there are often differences between JSON parser implementations,
which can cause problems. On the other hand, JSON is simple and extremely widely supported. To mitigate some of the
issues with JSON, Florentines will use a subset of JSON that I'm referring to as "Rank-2 Regular JSON". Regular JSON
is my name for JSON that is restricted to be a regular language by imposing arbitrary limits on nesting depth. In this
case, elements are limited to a maximum nesting depth of 2 levels. So the overall JSON object used in the header can
have values that are themselves JSON objects or arrays, but those JSON objects or arrays can only have simple scalar
values. I'll probably also ban unnecessary whitespace in the grammar and make certain things like duplicate keys have
a defined semantics (e.g., last one wins).

The following Florentine header values are defined initially:

 - `zip` - defines optional compression algorithm for the payload, probably supporting the same `deflate` algorithm
   supported by JWE, but potentially something more modern and fast like Zippy. I'm aware that compression and
   encryption don't always mix well, but many years experience with encrypted JWTs tells me that sometimes you
   *really* want this, and can accept the risks.
 - `cty` - defines the content-type of the payload contained in the (encrypted) Macaroon identifier part. As for
   JWTs, this is a standard MIME-type value but optionally omitting any `application/` prefix.
 - `mid` - an optional unique message ID. If present, this will be reflected in any reply message (see below)
   as the `irt` (in-response-to) header value.
 - `irt` - in-response-to, as described above. If the Florentine contains this header but is not a reply to any
   known message, then it should be rejected.
 - `crit` - an array of "critical" non-standard header names, as defined for JWTs. A Florentine implementation should
   reject a message if it contains a critical header that is not understood. (Otherwise it should ignore unknown headers).

### Replies

Florentines support a `reply()` operation that constructs a new Florentine in reply to a previously received
Florentine. This works by constructing the new Florentine using the ephemeral public key from the original
Florentine as if it was the recipient's static public key. This means that the X25519 key agreement steps
performed will be an ephemeral-ephemeral agreement (with the fresh ephemeral key pair generated for the reply),
and a static-ephemeral agreement between the sender's static key and the replied-to message's ephemeral key.

To facilitate replies, the API for creating a Florentine should return an opaque state object that encapsulates
the ephemeral secret key, if replies are to be supported. The sender is then responsible for keeping this object
around until any replies have been received and processed, after which it should be destroyed. (To avoid this
key leaking and compromising past communications, it is recommended that libraries take steps to limit the
validity of these ephemeral state objects: for example by encrypting it locally with a symmetric key that is
rotated in-memory regularly).

The use of a fully ephemeral key agreement mode in replies ensures (weak) forward secrecy. If the reply is then
itself replied to then the new reply (and any further exchanges) enjoy strong forward secrecy properties. Replies
also enjoy stronger authentication properties than single-shot messages, as they are resistant to Key Compromise
Impersonation (KCI) attacks, whereas single-shot Florentines are not. Florentines are designed to closely follow
the security properties of [Noise Handshakes](http://noiseprotocol.org/noise.html#payload-security-properties),
with single-shot Florentines corresponding to the `K` one-way handshake pattern, and replies corresponding to
the `KK` interactive handshake pattern. (But I should stress that this correspondence is only very loose, and I
haven't tried to rigorously prove the security properties yet).

If two parties keep replying to each other's Florentine messages then the result is a "ratcheting" protocol along
the lines of Signal, but it is really designed more for simple two-message interactions like challenge-response
protocols, OAuth/OIDC, etc. Florentines are not designed to be a replacement for Signal, and there are some
obviously awkward aspects of using it like that. But in a pinch, it could work to layer some end-to-end security
properties over a multiple-transport-protocol connection like those common in IoT applications.

The algorithm identifier is changed to `Florentine-Reply-X25519-XS20-HS256-SIV` in the KEM calculations, to ensure
domain separation with normal messages. If the original message contained a `mid` header, then this is copied into
the `irt` header of the reply.