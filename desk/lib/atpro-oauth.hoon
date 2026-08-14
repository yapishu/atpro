::  atpro-oauth: PKCE and ES256 DPoP primitives for AT Protocol OAuth
::
::  Keys and tokens remain noun state on the ship.  P-256 is instantiated
::  from the generic SEC curve implementation in Zuse; JOSE framing reuses
::  the MIME base64 implementation already available in Zuse.
::
|%
+$  private-key  @
+$  point  [x=@ y=@]
::
++  p256-domain
  ^-  domain:secp:crypto
  :*  0xffff.ffff.0000.0001.0000.0000.0000.0000.
        0000.0000.ffff.ffff.ffff.ffff.ffff.ffff
      0xffff.ffff.0000.0001.0000.0000.0000.0000.
        0000.0000.ffff.ffff.ffff.ffff.ffff.fffc
      0x5ac6.35d8.aa3a.93e7.b3eb.bd55.7698.86bc.
        651d.06b0.cc53.b0f6.3bce.3c3e.27d2.604b
      :-  0x6b17.d1f2.e12c.4247.f8bc.e6e5.63a4.40f2.
            7703.7d81.2deb.33a0.f4a1.3945.d898.c296
          0x4fe3.42e2.fe1a.7f9b.8ee7.eb4a.7c0f.9e16.
            2bce.3357.6b31.5ece.cbb6.4068.37bf.51f5
      0xffff.ffff.0000.0000.ffff.ffff.ffff.ffff.
        bce6.faad.a717.9e84.f3b9.cac2.fc63.2551
  ==
::
++  base64url
  |=  bytes=octs
  ^-  @t
  =/  b64=@t  (en:base64:mimes:html bytes)
  %-  crip
  %+  turn
    %+  skip  (trip b64)
    |=(c=@tD =(c '='))
  |=  c=@tD
  ?:  =(c '+')  '-'
  ?:  =(c '/')  '_'
  c
::
++  base64url-text
  |=  txt=@t
  ^-  @t
  (base64url [(met 3 txt) txt])
::
++  base64url-number-32
  |=  num=@
  ^-  @t
  (base64url [32 (rev 3 32 num)])
::
++  sha256-base64url
  |=  txt=@t
  ^-  @t
  (base64url [32 (shax txt)])
::
++  make-private-key
  |=  entropy=@
  ^-  private-key
  =/  dom=domain:secp:crypto  p256-domain
  =/  order=@  n.dom
  (add 1 (mod (shax entropy) (dec order)))
::
++  public-point
  |=  key=private-key
  ^-  point
  =/  p256  ~(. secp:secp:crypto 32 p256-domain)
  (priv-to-pub.p256 key)
::
++  public-jwk
  |=  key=private-key
  ^-  json
  =/  pub=point  (public-point key)
  %-  pairs:enjs:format
  :~  ['kty' s+'EC']
      ['crv' s+'P-256']
      ['x' s+(base64url-number-32 x.pub)]
      ['y' s+(base64url-number-32 y.pub)]
  ==
::
++  token
  |=  entropy=@
  ^-  @t
  (base64url [32 (shax entropy)])
::
++  pkce-verifier
  |=  entropy=@
  ^-  @t
  ::  32 bytes encode to 43 unpadded base64url characters.
  (token entropy)
::
++  pkce-challenge
  |=  verifier=@t
  ^-  @t
  (sha256-base64url verifier)
::
++  unix-seconds
  |=  now=@da
  ^-  @ud
  (rsh [6 1] (sub now ~1970.1.1))
::
++  jwt
  |=  [header=json claims=json key=private-key]
  ^-  @t
  =/  protected=@t  (base64url-text (en:json:html header))
  =/  payload=@t  (base64url-text (en:json:html claims))
  =/  signing-input=@t  (rap 3 ~[protected '.' payload])
  ::  +shax is a byte-string atom; ECDSA consumes the digest as a
  ::  big-endian integer, so reverse its 32 octets before curve math.
  =/  digest=@  (rev 3 32 (shax signing-input))
  =/  p256  ~(. secp:secp:crypto 32 p256-domain)
  =/  raw=[r=@ s=@ y=@]  (ecdsa-raw-sign.p256 digest key)
  =/  signature=@
    %+  can  3
    :~  [32 (rev 3 32 r.raw)]
        [32 (rev 3 32 s.raw)]
    ==
  (rap 3 ~[signing-input '.' (base64url [64 signature])])
::
++  dpop-proof
  |=  $:  method=@t
          url=@t
          nonce=(unit @t)
          access-token=(unit @t)
          now=@da
          entropy=@
          key=private-key
      ==
  ^-  @t
  =/  header=json
    %-  pairs:enjs:format
    :~  ['typ' s+'dpop+jwt']
        ['alg' s+'ES256']
        ['jwk' (public-jwk key)]
    ==
  =/  issued=@ud  (unix-seconds now)
  =/  fields=(list [@t json])
    :~  ['jti' s+(token entropy)]
        ['htm' s+method]
        ['htu' s+url]
        ['iat' n+(crip ((d-co:co 1) issued))]
        ['exp' n+(crip ((d-co:co 1) (add issued 30)))]
    ==
  =?  fields  ?=(^ nonce)
    (snoc fields ['nonce' s+u.nonce])
  =?  fields  ?=(^ access-token)
    (snoc fields ['ath' s+(sha256-base64url u.access-token)])
  (jwt header (pairs:enjs:format fields) key)
--
