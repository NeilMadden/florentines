# Florentines &ndash; delicious auth tokens

Florentines are a [delicious biscuit](https://en.wikipedia.org/wiki/Florentine_biscuit) and now also a 
next-generation security token format, combining elements of:

 * [JWT](https://tools.ietf.org/html/rfc7519) and [JOSE](https://tools.ietf.org/html/rfc7518)
 * [Macaroons](https://ai.google/research/pubs/pub41892)
 * [Paseto](https://paseto.io)
 * and other secure cookie formats.
 
Like JWTs, florentines have a structure based on JSON objects (encoded as [CBOR](http://cbor.io) for efficiency). 
Like macaroons, florentines support adding *caveats* at any time to attenuate the authority granted by a token. 
Anybody can add a caveat but only a key holder can remove them. Like Paseto, florentines only allow a small number of
well-vetted cryptographic primitives and only allows them to be combined in safe combinations. Florentines are 
designed to retain as much security as possible in the face of accidental or deliberate misuse.

## Getting Started

TODO: instructions for various languages

```xml
<!-- Doesn't work yet, needs publishing -->
<dependency>
    <groupId>io.florentine</groupId>
    <artifactId>florentine-core</artifactId>
    <version>0.0.1</version>
</dependency>
```

## Structure

A florentine consists of a header, followed by zero or more content packets, followed by zero or more *caveats*, and 
finally a cryptographic authentication tag. Each packet is 
[URL-safe Base64-encoded](https://en.wikipedia.org/wiki/Base64#URL_applications) and separated from other packets by 
a colon (to make florentines easily distinguishable from JWTs):
```
    base64url(header):base64url(content):...:base64url(caveat):...:base64url(tag)
``` 

A content packet can either be public or secret. Secret packets are encrypted using a misuse-resistant authenticated 
encryption algorithm (MRAE), described below. Each packet is represented by a type (as a single-byte CBOR integer) 
followed by a CBOR-encoded value. The types are:

 1. The header packet. Only valid for the very first packet.
 2. A plaintext content packet.
 3. An encrypted content packet.
 4. A caveat. No content packets can appear after a caveat packet.
 5. The authentication tag (signature) packet.

## Header

The header is a CBOR-encoded JSON object, which can have the following fields (based on JWT):

 * `uid` - a unique identifier for this specific florentine (a nonce). A binary value of at least 64-bits. REQUIRED. 
 It is RECOMMENDED that this is a randomly chosen value of at least 160-bits from a cryptographically secure random 
 number generator (e.g., from /dev/urandom on UNIX or SecureRandom in Java).
 * `kid` - an identifier for the key that can be used to verify this florentine. UTF-8 string. OPTIONAL.
 * `typ` - the content-type of the whole florentine itself. A media-type string. If the media-type starts with 
 `application/` then this can be omitted. OPTIONAL.
 * `cty` - the content-type of all content packets in the florentine. OPTIONAL.
 * `epk` - an ephemeral public key used for encryption (see below). OPTIONAL.
 * `crit` - an array of critical headers (other than this initial set) that must be understood by any recipient of the 
 florentine. OPTIONAL.
 
## Caveats

Just like macaroons, florentines support appending one or more *caveats* that place additional restrictions on the 
usage of a florentine. A caveat can only constrain the usage/authority of a florentine, never enhance it. A caveat is
a predicate that must be true at the point at which the florentine is used. Caveats are represented in florentines as
CBOR objects (maps), where each key of the map is a predicate symbol and the corresponding value forms the arguments 
to that predicate. Some standard caveats exist based upon caveat-like claims in JWT and related standards:

 * `{"exp": <integer>}` - an expiry time after which the florentine is no longer valid, in UTC seconds since the UNIX
  epoch.
 * `{"nbf": <integer>}` - a time before which the florentine cannot be used (not-before).
 * `{"aud": [array of strings]}` - the audience of the florentine. Each recipient must check that its identifier (e.g., 
 URI) appears in the given array and reject the florentine if it does not. Duplicates are not allowed.
 * `{"cnf": { public key claims }}` - a confirmation key associated with the florentine. The recipient should require
  the sender to prove possession of the associated private key. See below for confirmation methods.
 
Where the same caveat is appended more than once, then a caveat-specific method is used to determine the *effective 
caveat* by combining them. Each registered caveat must specify how this combination is performed, or else specify 
that an error occurs if the caveat appears more than once. The combining behaviour for the above standard caveats is 
as follows:
 * `exp` - the earliest time is used as the effective caveat.
 * `nbf` - the latest time is used as the effective caveat.
 * `aud` - the *intersection* of the audience arrays is used as the effective caveat.
 * `cnf` - it is an error to add more than one confirmation key.

## Florentine Web Keys

A florentine web key (FLWK, pronounced "flock") is similar to a [JSON Web Key](https://tools.ietf.org/html/rfc7517), 
but with some important differences:

 * Secret/private key claims are never mixed with public key claims.
 * RSA keys are not supported at all as florentines do not support RSA at this time.
 * Algorithm indicators on the key are mandatory (and illegal in a florentine header) to enforce 
 [key-driven cryptographic agility](https://neilmadden.blog/2018/09/30/key-driven-cryptographic-agility/).

Each key can have two parts:
 1. A set of public claims, containing metadata about the key and public key material. REQUIRED.
 2. A set of secret claims, containing secret/private key material. OPTIONAL.
These two sets of claims are always represented as separate JSON/CBOR objects and never mixed.

### Public claims

The set of public claims allowed in a FLWK are:
 * `kty` - the key type. One of `EC` (elliptic curve) or `sym` (symmetric). REQUIRED.
 * `kid` - a unique identifier for the key. OPTIONAL.
 * `kdf` - the key derivation algorithm. REQUIRED.
 * `mac` - the message authentication code (MAC) algorithm. REQUIRED.
 * `enc` - the encryption algorithm. REQUIRED.
 * `crv` - the elliptic curve for an `EC` key. REQUIRED if `kty` is `EC`, otherwise MUST NOT be present. Currently 
 supported values are `P-256`, `P-384`, `P-521`, `X25519` and `X448`.
 * `x` - the x-coordinate of the `EC` public key. REQUIRED if `kty` is `EC`, otherwise MUST NOT be present.
 * `y` - the y-coordinate of the `EC` public key. REQUIRED if `kty` is `EC` and `crv` is one of `P-256`, `P-384` or 
 `P-521`, otherwise MUST NOT be present.

The `kdf`, `mac` and `enc` parameters are used to enforce 
[key-driven cryptographic agility](https://neilmadden.blog/2018/09/30/key-driven-cryptographic-agility/) and are 
discussed further below.

### Secret key claims

There is just a single secret key claim defined currently:

 * `k` - the secret key material. For an `EC` key this is the private scalar. For a `sym` key this is the raw 
 symmetric key.

### Representing FLWKs as florentines

A FLWK can be represented as a florentine consisting of a header (TODO: determine appropriate `typ` and `cty`), 
followed by the public claims, optionally followed by the encrypted secret claims, and a tag. Caveats can be 
appended, for instance to restrict the times at which a key is a valid (using `exp` and `nbf` caveats).

## Cryptographic Algorithms

Currently florentines only support authenticated and optionally encrypted contents. Digital signatures are not yet 
supported (but you could include a JWS inside a florentine). Each florentine uses three cryptographic algorithms, 
which MUST be associated with the key and not with the message:

 * The `kdf` algorithm determines how the encryption and authentication keys are derived from the input key(s).
 * The `mac` algorithm is used to authenticate each packet.
 * The `enc` algorithm is used to encrypt any encrypted packets.

### Message authentication algorithms

Currently only a single MAC algorithm is supported. Others may be added in future (e.g., using SHA-3 or Blake2).

 * `HS512` - HMAC-SHA-512-256 - i.e., HMAC-SHA-512 truncated to 256-bits. The MAC key MUST be 256-bits exactly.

Authentication of a message uses a chained MAC construction as in macaroons, but with the number of non-caveat 
packets encoded into the MAC output:

```
func florentine-auth(mac_key, header, content, caveats):
    key = mac_key
    tag = mac(key, 1 + len(content))          # +1 for the header
    for packet in [header] ++ content ++ caveats: # ++ is concatenation
        key = tag[0..31]
        tag = mac(key, packet)
    end
    return tag[0..31]
end
```
Fans of functional programming may recognise the loop as a left-fold or reduce operation over the combined list of 
packets. Stated differently, appending a packet to a florentine consists of removing the previous authentication tag 
and using it as the key to authenticate the new packet. The new packet and tag are then appended to the florentine 
and the old tag destroyed. Verification of the tag is as follows:

```
func florentine-veriy(mac_key, header, content, caveats, auth_tag):
    key = mac_key
    tag = mac(key, 1 + len(content))              # +1 for the header
    for packet in [header] ++ content ++ caveats: # ++ is concatenation
        key = tag[0..31]
        tag = mac(key, packet)
    end
    if tag != auth_tag:                           # Use constant-time equality check
        destroy tag, key
        fail "invalid auth tag"
    end
end
```

### Content encryption algorithms

Two content encryption algorithms are supported:

 * `A256SIV` - AES with a 256-bit encryption key operating in synthetic IV (SIV) mode.
 * `XC20SIV` - XChaCha20 stream cipherAlgorithm with a 256-bit encryption key operating in a SIV-like mode.
 
Adding an encrypted content packet proceeds as follows:

 1. First the plaintext of the packet is appended as if it was a normal content packet (but with packet type 3 rather
  than 2).
 2. The new authentication tag is calculated as before.
 3. The last *n* bits of the new authentication tag (where n <= 256), which would normally be discarded, are extracted 
 as the synthetic IV (SIV). For `A256SIV` n = 128, for `XC20SIV` n = 192.
 4. The plaintext of the message (excluding the packet type) is encrypted in-place using the encryption key, SIV and 
 algorithm. For `XC20SIV` the SIV is used as the extended nonce and the block counter is set to 0. For `A256SIV` the 
 content is encrypted using AES in CTR mode with the SIV as the nonce (the 31st and 63rd bits are cleared beforehand 
 as described in RFC 5297).
 5. The SIV is appended to the encrypted ciphertext (in the same packet).
 6. The first 256-bits of the authentication tag from step 2 are appended as normal.
 
When an encrypted packet is encountered when validating a florentine, it can be decrypted in the following way:

 1. The last *n* bits of the packet (according to algorithm) are extracted as the SIV and removed.
 2. The remaining bits of the packet are decrypted using the encryption key, SIV and algorithm.
 3. The plaintext is then authenticated as if it was a normal content packet.
  
In pseudo-code:
```
func florentine-encrypt(enc_key, packet, old_tag, n):
    mac_key = old_tag[0..31]
    new_tag = mac(mac_key, packet)
    siv = new_tag[(64-n/8)..63]
    ciphertext = encrypt(enc_key, siv, packet)
    return (ciphertext + siv, new_tag[0..31])
end
func florentine-decrypt(enc_key, packet, old_tag, n):
    siv = packet[(packet.len-n/8)..(packet.len-1)]
    plaintext = decrypt(enc_key, siv, packet[0..(packet.len-n/8)])
    mac_key = old_tag[0..31]
    new_tag = mac(mac_key, plaintext)
    if new_tag[(64-n/8)..63) != siv:
        fail "invalid tag"
    end
    return (plaintext, new_tag[0..31])
end
```
We can verify the SIV immediately upon decrypting the packet, but the normal authentication tag will also be 
authenticated as part of the normal florentine verification process.

Despite the apparent simplicity of this encryption scheme, it achieves a very strong notion of security, namely 
misuse-resistant authenticated encryption. If the nonce in the header (`uid`) is unique for every florentine then 
this scheme achieves standard notions of authenticated encryption (`IND-CCA` security). If a nonce is accidentally 
reused then no authenticity guarantees are lost and confidentiality is only lost to the extent that an attacker can 
tell if the same plaintext was encrypted with the same key and identical values for all proceeding packets and the 
number of content packets is also identical. While this is the minimum loss of security in this situation, it may 
still represent a significant loss depending on the application, so should not be taken as a green light to do 
without a random nonce in each florentine.

### Key derivation algorithms

Two algorithms are supported for deriving MAC and encryption keys from an initial key or keys:

 * `HKDF` - The input key is a 512-bit random symmetric key that is used with the 
 [HKDF-Expand function](https://tools.ietf.org/html/rfc5869#section-2.3) (using the hash function specified for the MAC,
 so always SHA-512 at present) to derive the MAC and encryption keys. A single call to HKDF-Expand is made passing in
 the master key, and the *info* consists of the UTF-8 bytes of the concatenation of the `kdf`, `mac`, and `enc` 
 algorithms plus the contents of the `typ` header if present (an empty string if not). For example, if the `typ` header 
 is `florentine` and we are using `HS512` for authentication and `A256SIV` for encryption then the info parameter would 
 be the UTF-8 bytes of the string `HKDFHS256A256SIVflorentine`. This ensures that if the same master key is used for 
 multiple algorithms or types of message then unique keys will be derived with very high probability. A 512-bit output
 key is derived, with the first 256-bits being used as the MAC key and the last 256-bits as the encryption key.

 * `ECDH-ESSS` - The input keys consist of a static elliptic curve private key for the sender and a static public key 
 for the recipient. These keys must be on the same elliptic curve. An ephemeral key-pair is generated on the same 
 curve, and the public claims (in FLWK format) are set as the `epk` value in the header. An elliptic curve 
 Diffie-Hellman key agreement is performed between the ephemeral private key and the recipient's public key to derive
 a shared secret. Then another ECDH key agreement is performed between the sender's static private key and the 
 recipient's static public key to derive a second shared secret. The two shared secrets are then concatenated to 
 create a combined secret `s = s_es || s_ss`. This is then fed into HKDF-Extract with an empty salt value to produce 
 a master key. Finally, this master key is fed into HKDF-Expand to derive MAC and encryption keys as for `HKDF` above
 except that the *info* parameter is pre-pended with the bytes of all three public keys (TODO: determine exact 
 encoding). This corresponds to the "One-Pass Unified Model" of section 6.2.1.2 of NIST SP-800-56A revision 3.
 
Both key derivation methods ensure a security goal of *authenticated encryption* is always achieved even in the 
public key setting, eliminating the need for a separate signature for authentication.

Where ECDH-ESSS is used, the sender can store the ephemeral secret key locally and the recipient can then 