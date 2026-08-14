::  Development vector for checking Urbit's ES256 output with JOSE tooling.
/+  atpro-oauth
:-  %say
|=  *
:-  %noun
=/  key=private-key:atpro-oauth  1
=/  proof=@t
  %-  dpop-proof:atpro-oauth
  :*  'GET'
      'https://example.com/xrpc/app.bsky.feed.getTimeline'
      (some 'test-nonce')
      (some 'test-access-token')
      ~2026.8.13..12.00.00
      42
      key
  ==
[jwk=(public-jwk:atpro-oauth key) proof=proof]
