::  Inbound PKCE and ES256 DPoP validation for the AT OAuth provider.
/+  atpro-oauth
|%
+$  dpop-proof
  $:  jkt=@t
      jti=@t
  ==
::
++  split-on
  |=  [sep=@tD value=@t]
  ^-  (list @t)
  =/  chars=tape  (trip value)
  =/  part=tape  ~
  =/  out=(list @t)  ~
  |-
  ?~  chars  (flop [(crip (flop part)) out])
  ?:  =(i.chars sep)
    $(chars t.chars, part ~, out [(crip (flop part)) out])
  $(chars t.chars, part [i.chars part])
::
++  from-hex
  |=  c=@tD
  ^-  (unit @ud)
  ?:  &((gte c '0') (lte c '9'))  `(sub c '0')
  ?:  &((gte c 'a') (lte c 'f'))  `(add 10 (sub c 'a'))
  ?:  &((gte c 'A') (lte c 'F'))  `(add 10 (sub c 'A'))
  ~
::
++  url-decode
  |=  value=@t
  ^-  @t
  =/  chars=tape  (trip value)
  =/  out=tape  ~
  |-
  ?~  chars  (crip (flop out))
  ?:  =(i.chars '+')
    $(chars t.chars, out [' ' out])
  ?:  &(=(i.chars '%') ?=(^ t.chars) ?=(^ t.t.chars))
    =/  hi=(unit @ud)  (from-hex i.t.chars)
    =/  lo=(unit @ud)  (from-hex i.t.t.chars)
    ?:  |(?=(~ hi) ?=(~ lo))
      $(chars t.chars, out [i.chars out])
    $(chars t.t.t.chars, out [(add (mul 16 u.hi) u.lo) out])
  $(chars t.chars, out [i.chars out])
::
++  form-fields
  |=  body=@t
  ^-  (list [key=@t value=@t])
  %+  turn  (split-on '&' body)
  |=  item=@t
  =/  parts=(list @t)  (split-on '=' item)
  ?~  parts  ['' '']
  ?~  t.parts  [(url-decode i.parts) '']
  [(url-decode i.parts) (url-decode (rap 3 (join '=' t.parts)))]
::
++  field
  |=  [key=@t fields=(list [key=@t value=@t])]
  ^-  (unit @t)
  |-
  ?~  fields  ~
  ?:  =(key key.i.fields)  `value.i.fields
  $(fields t.fields)
::
++  base64url-bytes
  |=  value=@t
  ^-  (unit octs)
  =/  standard=@t
    %-  crip
    %+  turn  (trip value)
    |=  c=@tD
    ?:  =(c '-')  '+'
    ?:  =(c '_')  '/'
    c
  =/  rem=@ud  (mod (met 3 standard) 4)
  ?:  =(rem 1)  ~
  =/  padded=@t
    ?:  =(rem 2)  (cat 3 standard '==')
    ?:  =(rem 3)  (cat 3 standard '=')
    standard
  (de:base64:mimes:html padded)
::
++  json-segment
  |=  value=@t
  ^-  (unit json)
  =/  bytes=(unit octs)  (base64url-bytes value)
  ?~  bytes  ~
  (de:json:html q.u.bytes)
::
++  string-at
  |=  [key=@t jon=json]
  ^-  (unit @t)
  ?.  ?=(%o -.jon)  ~
  =/  val=(unit json)  (~(get by p.jon) key)
  ?~  val  ~
  ?.  ?=(%s -.u.val)  ~
  `p.u.val
::
++  number-at
  |=  [key=@t jon=json]
  ^-  (unit @ud)
  ?.  ?=(%o -.jon)  ~
  =/  val=(unit json)  (~(get by p.jon) key)
  ?~  val  ~
  ?.  ?=(%n -.u.val)  ~
  =/  chars=tape  (trip p.u.val)
  =/  total=@ud  0
  =/  seen=?  %.n
  |-  ^-  (unit @ud)
  ?~  chars  ?:(seen `total ~)
  ?.  &((gte i.chars '0') (lte i.chars '9'))  ~
  $(chars t.chars, total (add (mul total 10) (sub i.chars '0')), seen %.y)
::
++  object-at
  |=  [key=@t jon=json]
  ^-  (unit json)
  ?.  ?=(%o -.jon)  ~
  =/  val=(unit json)  (~(get by p.jon) key)
  ?~  val  ~
  ?.  ?=(%o -.u.val)  ~
  val
::
++  jwk-thumbprint
  |=  [x=@t y=@t]
  ^-  @t
  =/  canonical=@t
    (rap 3 ~['{"crv":"P-256","kty":"EC","x":"' x '","y":"' y '"}'])
  (base64url:atpro-oauth [32 (shax canonical)])
::
++  without-query
  |=  value=@t
  ^-  @t
  =/  chars=tape  (trip value)
  =/  mark=(unit @ud)  (find "?" chars)
  ?~(mark value (crip (scag u.mark chars)))
::
++  verify-es256
  |=  [input=@t signature=octs x-text=@t y-text=@t]
  ^-  ?
  ?.  =(64 p.signature)  %.n
  =/  x-bytes=(unit octs)  (base64url-bytes x-text)
  =/  y-bytes=(unit octs)  (base64url-bytes y-text)
  ?.  ?&  ?=(^ x-bytes)  ?=(^ y-bytes)
          =(32 p.u.x-bytes)  =(32 p.u.y-bytes)
      ==
    %.n
  =/  r=@  (rev 3 32 (cut 3 [0 32] q.signature))
  =/  s=@  (rev 3 32 (cut 3 [32 32] q.signature))
  =/  pub=point:atpro-oauth
    [(rev 3 32 q.u.x-bytes) (rev 3 32 q.u.y-bytes)]
  =/  dom=domain:secp:crypto  p256-domain:atpro-oauth
  ?.  ?&  (gth r 0)  (lth r n.dom)
          (gth s 0)  (lth s n.dom)
          (lth x.pub p.dom)  (lth y.pub p.dom)
          =((mod (mul y.pub y.pub) p.dom) (mod (add (add (mul (mul x.pub x.pub) x.pub) (mul a.dom x.pub)) b.dom) p.dom))
      ==
    %.n
  =/  curve  ~(. secp:secp:crypto 32 dom)
  =/  digest=@  (rev 3 32 (shax input))
  =/  inverse=@  (inv:field-n.curve s)
  =/  left=point:atpro-oauth
    (mul-point-scalar.curve g.dom (mod (mul digest inverse) n.dom))
  =/  right=point:atpro-oauth
    (mul-point-scalar.curve pub (mod (mul r inverse) n.dom))
  =/  point=point:atpro-oauth  (add-points.curve left right)
  =(r (mod x.point n.dom))
::
++  verify-dpop
  |=  $:  jwt=@t
          method=@t
          url=@t
          access-token=(unit @t)
          now=@ud
      ==
  ^-  (unit dpop-proof)
  =/  parts=(list @t)  (split-on '.' jwt)
  ?.  =(3 (lent parts))  ~
  =/  protected=@t  (snag 0 parts)
  =/  payload=@t  (snag 1 parts)
  =/  signature-text=@t  (snag 2 parts)
  =/  header=(unit json)  (json-segment protected)
  =/  claims=(unit json)  (json-segment payload)
  =/  signature=(unit octs)  (base64url-bytes signature-text)
  ?.  ?&(?=(^ header) ?=(^ claims) ?=(^ signature))  ~
  =/  typ=(unit @t)  (string-at 'typ' u.header)
  =/  alg=(unit @t)  (string-at 'alg' u.header)
  =/  jwk=(unit json)  (object-at 'jwk' u.header)
  ?.  ?&  ?=(^ typ)  =('dpop+jwt' u.typ)
          ?=(^ alg)  =('ES256' u.alg)
          ?=(^ jwk)
      ==
    ~
  =/  kty=(unit @t)  (string-at 'kty' u.jwk)
  =/  crv=(unit @t)  (string-at 'crv' u.jwk)
  =/  x=(unit @t)  (string-at 'x' u.jwk)
  =/  y=(unit @t)  (string-at 'y' u.jwk)
  ?.  ?&  ?=(^ kty)  =('EC' u.kty)
          ?=(^ crv)  =('P-256' u.crv)
          ?=(^ x)  ?=(^ y)
      ==
    ~
  ?.  (verify-es256 (rap 3 ~[protected '.' payload]) u.signature u.x u.y)  ~
  =/  jti=(unit @t)  (string-at 'jti' u.claims)
  =/  htm=(unit @t)  (string-at 'htm' u.claims)
  =/  htu=(unit @t)  (string-at 'htu' u.claims)
  =/  iat=(unit @ud)  (number-at 'iat' u.claims)
  =/  exp=(unit @ud)  (number-at 'exp' u.claims)
  =/  exp-ok=?  ?~(exp %.y (gth u.exp now))
  ?.  ?&  ?=(^ jti)  !=('' u.jti)
          ?=(^ htm)  =(method u.htm)
          ?=(^ htu)  =((without-query url) (without-query u.htu))
          ?=(^ iat)
          (lte u.iat (add now 60))
          (lte now (add u.iat 300))
          exp-ok
      ==
    ~
  =/  ath=(unit @t)  (string-at 'ath' u.claims)
  ?~  access-token
    ?:  ?=(^ ath)  ~
    `[(jwk-thumbprint u.x u.y) u.jti]
  ?.  ?&  ?=(^ ath)
          =((sha256-base64url:atpro-oauth u.access-token) u.ath)
      ==
    ~
  `[(jwk-thumbprint u.x u.y) u.jti]
--
