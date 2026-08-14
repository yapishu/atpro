::  Password hashing and HS256 session JWTs for the single-account PDS.
/+  atpro-oauth
|%
++  hmac-sha256
  |=  [key=octs message=octs]
  ^-  @
  =/  block-size=@ud  64
  =/  material=octs
    ?:  (gth p.key block-size)  [32 (shay key)]  key
  =/  padded=@  q.material
  =/  inner-key=@  (mix padded (fil 3 block-size 0x36))
  =/  outer-key=@  (mix padded (fil 3 block-size 0x5c))
  =/  inner=@  (shay [(add block-size p.message) (cat 3 inner-key q.message)])
  (shay [(add block-size 32) (cat 3 outer-key inner)])
::
++  password-digest
  |=  [salt=@ password=@t]
  ^-  @
  (hmac-sha256 [32 salt] [(met 3 password) password])
::
++  jwt-hs256
  |=  [header=json claims=json key=@]
  ^-  @t
  =/  protected=@t
    (base64url-text:atpro-oauth (en:json:html header))
  =/  payload=@t
    (base64url-text:atpro-oauth (en:json:html claims))
  =/  signing-input=@t  (rap 3 ~[protected '.' payload])
  =/  signature=@
    (hmac-sha256 [32 key] [(met 3 signing-input) signing-input])
  (rap 3 ~[signing-input '.' (base64url:atpro-oauth [32 signature])])
::
++  session-jwt
  |=  $:  typ=@t
          scope=@t
          subject=@t
          audience=@t
          jti=@t
          issued-at=@ud
          expires-at=@ud
          key=@
      ==
  ^-  @t
  =/  header=json
    (pairs:enjs:format ~[['typ' s+typ] ['alg' s+'HS256']])
  =/  claims=json
    %-  pairs:enjs:format
    :~  ['scope' s+scope]
        ['sub' s+subject]
        ['aud' s+audience]
        ['jti' s+jti]
        ['iat' n+(crip ((d-co:co 1) issued-at))]
        ['exp' n+(crip ((d-co:co 1) expires-at))]
    ==
  (jwt-hs256 header claims key)
--
