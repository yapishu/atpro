::  Inbound OAuth provider crypto checks.
/+  atpro-oauth, atpro-provider
:-  %say
|=  *
:-  %noun
=/  key=@  (make-private-key:atpro-oauth 42)
=/  now=@da  ~2026.8.14..12.00.00
=/  unix=@ud  (unix-seconds:atpro-oauth now)
=/  proof=@t
  %-  dpop-proof:atpro-oauth
  :*  'POST'
      'https://pds.example/oauth/token'
      ~
      ~
      now
      99
      key
  ==
=/  verified=(unit dpop-proof:atpro-provider)
  (verify-dpop:atpro-provider proof 'POST' 'https://pds.example/oauth/token' ~ unix)
=/  query-proof=@t
  %-  dpop-proof:atpro-oauth
  :*  'GET'
      'https://pds.example/xrpc/app.bsky.feed.getTimeline?limit=50'
      ~
      ~
      now
      100
      key
  ==
=/  query-verified=(unit dpop-proof:atpro-provider)
  (verify-dpop:atpro-provider query-proof 'GET' 'https://pds.example/xrpc/app.bsky.feed.getTimeline' ~ unix)
=/  pub=json  (public-jwk:atpro-oauth key)
=/  x=@t  (need (string-at:atpro-provider 'x' pub))
=/  y=@t  (need (string-at:atpro-provider 'y' pub))
=/  expected=@t  (jwk-thumbprint:atpro-provider x y)
=/  no-exp-header=json
  (pairs:enjs:format ~[['typ' s+'dpop+jwt'] ['alg' s+'ES256'] ['jwk' pub]])
=/  no-exp-claims=json
  %-  pairs:enjs:format
  :~  ['jti' s+'no-expiration-claim']
      ['htm' s+'POST']
      ['htu' s+'https://pds.example/oauth/token']
      ['iat' n+(crip ((d-co:co 1) unix))]
  ==
=/  no-exp=@t  (jwt:atpro-oauth no-exp-header no-exp-claims key)
=/  no-exp-verified=(unit dpop-proof:atpro-provider)
  (verify-dpop:atpro-provider no-exp 'POST' 'https://pds.example/oauth/token' ~ unix)
=/  form=(list [@t @t])
  (form-fields:atpro-provider 'a=hello+world&redirect=https%3A%2F%2Fexample.com%2Fcb')
=/  got-a=(unit @t)  (field:atpro-provider 'a' form)
=/  got-redirect=(unit @t)  (field:atpro-provider 'redirect' form)
=/  parts=(list @t)  (split-on:atpro-provider '.' proof)
=/  sig=(unit octs)  (base64url-bytes:atpro-provider (snag 2 parts))
=/  direct=?
  (verify-es256:atpro-provider (rap 3 ~[(snag 0 parts) '.' (snag 1 parts)]) (need sig) x y)
?>  direct
?>  ?=(^ verified)
?>  ?=(^ query-verified)
?>  ?=(^ no-exp-verified)
?>  =(expected jkt.u.verified)
?>  ?&  ?=(^ got-a)  =('hello world' u.got-a)
        ?=(^ got-redirect)  =('https://example.com/cb' u.got-redirect)
    ==
[%ok expected]
