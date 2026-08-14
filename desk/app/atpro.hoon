::  atpro: native AT Protocol XRPC and OAuth client
::
::  Credentials, OAuth session keys, PKCE verifiers, and DPoP nonces remain
::  ship-side.  The browser receives only account status and redirect URLs.
::
/-  atpro
/+  atpro-oauth, dbug, default-agent, server
|%
+$  card  card:agent:gall
::
++  starts-with
  |=  [prefix=@t txt=@t]
  ^-  ?
  =/  p=tape  (trip prefix)
  =/  t=tape  (trip txt)
  ?:  (lth (lent t) (lent p))  %.n
  =(p (scag (lent p) t))
::
++  ends-with
  |=  [suffix=@t txt=@t]
  ^-  ?
  =/  s=tape  (trip suffix)
  =/  t=tape  (trip txt)
  ?:  (lth (lent t) (lent s))  %.n
  =(s (slag (sub (lent t) (lent s)) t))
::
++  strip-final-slash
  |=  txt=@t
  ^-  @t
  =/  t=tape  (trip txt)
  ?~  t  txt
  ?.  =('/' (rear t))  txt
  =/  all=tape  t
  (crip (scag (dec (lent all)) all))
::
++  clean-origin-rest
  |=  rest=tape
  ^-  ?
  ?&  !=(~ rest)
      =(~ (find "/" rest))
      =(~ (find "?" rest))
      =(~ (find "#" rest))
      =(~ (find "@" rest))
  ==
::
++  valid-service
  |=  txt=@t
  ^-  ?
  ?.  (starts-with 'https://' txt)  %.n
  (clean-origin-rest (slag 8 (trip txt)))
::
++  valid-oauth-origin
  |=  txt=@t
  ^-  ?
  ?:  (valid-service txt)  %.y
  ?:  (starts-with 'http://localhost' txt)
    (clean-origin-rest (slag 7 (trip txt)))
  ?:  (starts-with 'http://127.0.0.1' txt)
    (clean-origin-rest (slag 7 (trip txt)))
  %.n
::
++  canonical-oauth-origin
  |=  txt=@t
  ^-  @t
  ?.  (starts-with 'http://localhost' txt)  txt
  (rap 3 ~['http://127.0.0.1' (crip (slag 16 (trip txt)))])
::
++  valid-https-url
  |=  txt=@t
  ^-  ?
  ?&  (starts-with 'https://' txt)
      =(~ (find "@" (trip txt)))
      =(~ (find "#" (trip txt)))
  ==
::
++  valid-nsid
  |=  txt=@t
  ^-  ?
  =/  chars=tape  (trip txt)
  =/  saw-dot=?  %.n
  |-
  ?~  chars  saw-dot
  =/  c=@tD  i.chars
  =/  ok=?
    ?|  &((gte c 'a') (lte c 'z'))
        &((gte c 'A') (lte c 'Z'))
        &((gte c '0') (lte c '9'))
        =(c '.')
        =(c '-')
    ==
  ?.  ok  %.n
  $(chars t.chars, saw-dot |(saw-dot =(c '.')))
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
++  json-at
  |=  [key=@t jon=json]
  ^-  (unit json)
  ?.  ?=(%o -.jon)  ~
  (~(get by p.jon) key)
::
++  first-string
  |=  jon=json
  ^-  (unit @t)
  ?.  ?=(%a -.jon)  ~
  ?~  p.jon  ~
  ?.  ?=(%s -.i.p.jon)  ~
  `p.i.p.jon
::
++  find-pds
  |=  did-doc=json
  ^-  (unit @t)
  =/  services=(unit json)  (json-at 'service' did-doc)
  ?~  services  ~
  ?.  ?=(%a -.u.services)  ~
  =/  items=(list json)  p.u.services
  |-
  ?~  items  ~
  =/  typ=(unit @t)  (string-at 'type' i.items)
  =/  endpoint=(unit @t)  (string-at 'serviceEndpoint' i.items)
  ?:  ?&  ?=(^ typ)
          =('AtprotoPersonalDataServer' u.typ)
          ?=(^ endpoint)
      ==
    endpoint
  $(items t.items)
::
++  find-handle
  |=  did-doc=json
  ^-  (unit @t)
  =/  aliases=(unit json)  (json-at 'alsoKnownAs' did-doc)
  ?~  aliases  ~
  ?.  ?=(%a -.u.aliases)  ~
  =/  items=(list json)  p.u.aliases
  |-
  ?~  items  ~
  ?:  ?&  ?=(%s -.i.items)  (starts-with 'at://' p.i.items)  ==
    `(crip (slag 5 (trip p.i.items)))
  $(items t.items)
::
++  did-url
  |=  did=@t
  ^-  (unit @t)
  ?:  (starts-with 'did:plc:' did)
    `(rap 3 ~['https://plc.directory/' did])
  ?.  (starts-with 'did:web:' did)  ~
  =/  domain=@t  (crip (slag 8 (trip did)))
  ?.  ?&  !=('' domain)
          =(~ (find ":" (trip domain)))
          (clean-origin-rest (trip domain))
      ==
    ~
  `(rap 3 ~['https://' domain '/.well-known/did.json'])
::
++  percent-encode
  |=  raw=@t
  ^-  @t
  =/  chars=tape  (trip raw)
  =/  out=tape  ~
  |-
  ?~  chars  (crip out)
  =/  c=@tD  i.chars
  =/  unreserved=?
    ?|  ?&((gte c 'a') (lte c 'z'))
        ?&((gte c 'A') (lte c 'Z'))
        ?&((gte c '0') (lte c '9'))
        =(c '-')  =(c '.')  =(c '_')  =(c '~')
    ==
  ?:  unreserved
    $(chars t.chars, out (snoc out c))
  =/  hex=$-(@ud @tD)
    |=  n=@ud
    ?:  (lth n 10)  `@tD`(add '0' n)
    `@tD`(add 'A' (sub n 10))
  $(chars t.chars, out (weld out ~['%' (hex (div c 16)) (hex (mod c 16))]))
::
++  form-body
  |=  fields=(list [@t @t])
  ^-  @t
  =/  out=(list @t)  ~
  |-
  ?~  fields  (rap 3 (join '&' (flop out)))
  =/  item=@t
    (rap 3 ~[(percent-encode -.i.fields) '=' (percent-encode +.i.fields)])
  $(fields t.fields, out [item out])
::
++  get-param
  |=  [params=(list [key=@t value=@t]) key=@t]
  ^-  (unit @t)
  =/  match=(list [key=@t value=@t])
    (skim params |=([k=@t v=@t] =(k key)))
  ?~  match  ~
  `value.i.match
::
++  dpop-nonce
  |=  headers=header-list:http
  ^-  (unit @t)
  =/  low=(unit @t)  (get-header:http 'dpop-nonce' headers)
  ?^  low  low
  (get-header:http 'DPoP-Nonce' headers)
::
++  json-payload
  |=  [status=@ud jon=json]
  ^-  simple-payload:http
  :_  `(as-octs:mimes:html (en:json:html jon))
  :-  status
  :~  ['content-type' 'application/json']
      ['cache-control' 'no-store']
  ==
::
++  text-payload
  |=  [status=@ud body=@t]
  ^-  simple-payload:http
  :_  `(as-octs:mimes:html body)
  :-  status
  :~  ['content-type' 'application/json']
      ['cache-control' 'no-store']
  ==
::
++  error-json
  |=  [status=@ud message=@t]
  ^-  simple-payload:http
  (json-payload status (pairs:enjs:format ~[['error' s+message]]))
::
++  session-json
  |=  account=(unit session:atpro)
  ^-  json
  ?~  account
    (pairs:enjs:format ~[['connected' b+%.n]])
  %-  pairs:enjs:format
  :~  ['connected' b+%.y]
      ['service' s+service.u.account]
      ['did' s+did.u.account]
      ['handle' s+handle.u.account]
      ['auth' s+?~(oauth.u.account 'app-password' 'oauth')]
  ==
::
++  identity-json
  |=  identity=(unit at-identity:atpro)
  ^-  json
  ?~  identity
    (pairs:enjs:format ~[['published' b+%.n]])
  %-  pairs:enjs:format
  :~  ['published' b+%.y]
      ['did' s+did.u.identity]
      ['handle' s+handle.u.identity]
      ['confirmedAt' s+(scot %da confirmed-at.u.identity)]
  ==
::
++  peer-ships
  |=  [our=@p now=@da]
  ^-  (list @p)
  =/  desks=(set @tas)
    .^((set @tas) %cd /(scot %p our)//(scot %da now))
  ?.  (~(has in desks) %landscape)  ~
  =/  contacts=(set @p)
    =/  res=(each (map * *) tang)
      (mule |.(.^((map * *) %gx /(scot %p our)/contacts/(scot %da now)/v1/book/noun)))
    ?:  ?=(%| -.res)  ~
    %-  silt
    %+  murn  ~(tap in ~(key by p.res))
    |=(key=* ?@(key (some `@p`key) ~))
  %+  scag  64
  %+  skim  ~(tap in contacts)
  |=  ship=@p
  ?&  !=(ship our)
      (lth `@`ship (bex 32))
  ==
::
++  scan-identities-json
  |=  [our=@p now=@da]
  ^-  json
  =/  peers=(list @p)  (peer-ships our now)
  =/  found=(list [@p at-identity:atpro])
    %+  murn  peers
    |=  ship=@p
    =/  result=(each (unit at-identity:atpro) tang)
      (mule |.(.^((unit at-identity:atpro) %gx /(scot %p ship)/atpro/(scot %da now)/identity/noun)))
    ?:  ?=(%| -.result)  ~
    ?~  p.result  ~
    `[ship u.p.result]
  %-  pairs:enjs:format
  :~  :-  'people'
      :-  %a
      %+  turn  found
      |=  [ship=@p identity=at-identity:atpro]
      %-  pairs:enjs:format
      :~  ['ship' s+(scot %p ship)]
          ['did' s+did.identity]
          ['handle' s+handle.identity]
          ['confirmedAt' s+(scot %da confirmed-at.identity)]
      ==
      ['scanned' n+(scot %ud (lent peers))]
  ==
::
++  parse-password-session
  |=  [service=@t body=@t]
  ^-  (unit session:atpro)
  =/  jon=(unit json)  (de:json:html body)
  ?~  jon  ~
  =/  access=(unit @t)  (string-at 'accessJwt' u.jon)
  =/  refresh=(unit @t)  (string-at 'refreshJwt' u.jon)
  =/  did=(unit @t)  (string-at 'did' u.jon)
  =/  handle=(unit @t)  (string-at 'handle' u.jon)
  ?~  access  ~  ?~  refresh  ~  ?~  did  ~  ?~  handle  ~
  `[service u.did u.handle u.access u.refresh ~]
::
++  parse-oauth-token
  |=  body=@t
  ^-  (unit [access=@t refresh=(unit @t) sub=@t scope=@t])
  =/  jon=(unit json)  (de:json:html body)
  ?~  jon  ~
  =/  access=(unit @t)  (string-at 'access_token' u.jon)
  =/  refresh=(unit @t)  (string-at 'refresh_token' u.jon)
  =/  sub=(unit @t)  (string-at 'sub' u.jon)
  =/  scope=(unit @t)  (string-at 'scope' u.jon)
  ?~  access  ~  ?~  sub  ~  ?~  scope  ~
  `[u.access refresh u.sub u.scope]
--
::
%-  agent:dbug
=|  state-0:atpro
=*  state  -
=/  in-flight  *(map @uv request-context:atpro)
=/  request-count=@ud  0
^-  agent:gall
|_  =bowl:gall
+*  this  .
    def   ~(. (default-agent this %|) bowl)
::
++  on-init
  ^-  (quip card _this)
  :_  this
  :~  [%pass /eyre/connect %arvo %e %connect [`/apps/atpro/api dap.bowl]]
  ==
::
++  on-save
  ^-  vase
  !>(state)
::
++  on-load
  |=  old=vase
  ^-  (quip card _this)
  =/  loaded=state-0:atpro  !<(state-0:atpro old)
  :_  this(state loaded, in-flight ~, request-count 0)
  :~  [%pass /eyre/connect %arvo %e %connect [`/apps/atpro/api dap.bowl]]
  ==
::
++  on-poke
  |=  [=mark =vase]
  ^-  (quip card _this)
  |^
  ?+  mark  (on-poke:def mark vase)
      %handle-http-request
    (handle-http !<([@ta inbound-request:eyre] vase))
  ==
::
++  next-id
  ^-  @uv
  `@uv`(shas %atpro-request (cat 3 eny.bowl request-count))
::
++  queue-request
  |=  [ctx=request-context:atpro req=request:http]
  ^-  (quip card _this)
  =/  rid=@uv  next-id
  =.  request-count  +(request-count)
  =.  in-flight  (~(put by in-flight) rid ctx)
  :_  this
  :~  [%pass /iris/(scot %uv rid) %arvo %i %request req *outbound-config:iris]
  ==
::
++  proof
  |=  [method=@t url=@t nonce=(unit @t) access=(unit @t) key=@]
  ^-  @t
  %-  dpop-proof:atpro-oauth
  :*  method  url  nonce  access  now.bowl
      (cat 3 eny.bowl request-count)
      key
  ==
::
++  login-request
  |=  [eyre-id=@ta jon=json]
  ^-  (quip card _this)
  =/  identifier=(unit @t)  (string-at 'identifier' jon)
  =/  password=(unit @t)  (string-at 'password' jon)
  =/  requested=(unit @t)  (string-at 'service' jon)
  ?~  identifier
    :_  this
    (give-simple-payload:app:server eyre-id (error-json 400 'missing identifier'))
  ?~  password
    :_  this
    (give-simple-payload:app:server eyre-id (error-json 400 'missing password'))
  =/  service=@t  (strip-final-slash ?~(requested 'https://bsky.social' u.requested))
  ?.  (valid-service service)
    :_  this
    (give-simple-payload:app:server eyre-id (error-json 400 'service must be an HTTPS origin'))
  =/  payload=json
    (pairs:enjs:format ~[['identifier' s+u.identifier] ['password' s+u.password]])
  =/  req=request:http
    :*  %'POST'
        (rap 3 ~[service '/xrpc/com.atproto.server.createSession'])
        ~[['content-type' 'application/json'] ['accept' 'application/json']]
        `(as-octs:mimes:html (en:json:html payload))
    ==
  (queue-request [eyre-id %login `service ~ ~ ~ ~ %.n] req)
::
++  oauth-start
  |=  [eyre-id=@ta jon=json]
  ^-  (quip card _this)
  =/  identifier=(unit @t)  (string-at 'identifier' jon)
  =/  origin=(unit @t)  (string-at 'origin' jon)
  ?~  identifier
    :_  this
    (give-simple-payload:app:server eyre-id (error-json 400 'missing identifier'))
  ?~  origin
    :_  this
    (give-simple-payload:app:server eyre-id (error-json 400 'missing origin'))
  =/  clean=@t  (canonical-oauth-origin (strip-final-slash u.origin))
  ?.  (valid-oauth-origin clean)
    :_  this
    (give-simple-payload:app:server eyre-id (error-json 400 'OAuth origin must be public HTTPS or localhost'))
  =/  redirect-uri=@t  (rap 3 ~[clean '/apps/atpro/api/oauth/callback'])
  =/  scope=@t  'atproto transition:generic'
  =/  client-id=@t
    ?:  (starts-with 'http://127.0.0.1' clean)
      (rap 3 ~['http://localhost?redirect_uri=' (percent-encode redirect-uri) '&scope=' (percent-encode scope)])
    (rap 3 ~[clean '/apps/atpro/api/oauth/client-metadata'])
  =.  oauth-client  `[client-id redirect-uri scope]
  =/  work=oauth-work:atpro  [u.identifier client-id redirect-uri ~ ~ ~ ~]
  ?:  (starts-with 'did:' u.identifier)
    =/  url=(unit @t)  (did-url u.identifier)
    ?~  url
      :_  this
      (give-simple-payload:app:server eyre-id (error-json 400 'only did:plc and host-only did:web identities are supported'))
    =.  work  work(did `u.identifier)
    (queue-request [eyre-id %oauth-did ~ `work ~ ~ ~ %.n] [%'GET' u.url ~[['accept' 'application/json']] ~])
  =/  url=@t
    (rap 3 ~['https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle?handle=' (percent-encode u.identifier)])
  (queue-request [eyre-id %oauth-identity ~ `work ~ ~ ~ %.n] [%'GET' url ~[['accept' 'application/json']] ~])
::
++  refresh-request
  |=  eyre-id=@ta
  ^-  (quip card _this)
  ?~  account
    :_  this
    (give-simple-payload:app:server eyre-id (error-json 409 'not connected'))
  ?~  oauth.u.account
    =/  req=request:http
      :*  %'POST'
          (rap 3 ~[service.u.account '/xrpc/com.atproto.server.refreshSession'])
          ~[['authorization' (rap 3 ~['Bearer ' refresh-token.u.account])] ['accept' 'application/json']]
          ~
      ==
    (queue-request [eyre-id %refresh ~ ~ ~ ~ ~ %.n] req)
  (oauth-refresh-request eyre-id %.n)
::
++  oauth-refresh-request
  |=  [eyre-id=@ta retry=?]
  ^-  (quip card _this)
  ?~  account
    :_  this
    (give-simple-payload:app:server eyre-id (error-json 409 'not connected'))
  ?~  oauth.u.account
    :_  this
    (give-simple-payload:app:server eyre-id (error-json 409 'not an OAuth session'))
  =/  od=oauth-data:atpro  u.oauth.u.account
  =/  body=@t
    (form-body ~[['grant_type' 'refresh_token'] ['refresh_token' refresh-token.u.account] ['client_id' client-id.od]])
  =/  dpop=@t  (proof 'POST' token-endpoint.od auth-nonce.od ~ key.od)
  =/  req=request:http
    :*  %'POST'  token-endpoint.od
        ~[['content-type' 'application/x-www-form-urlencoded'] ['accept' 'application/json'] ['dpop' dpop]]
        `(as-octs:mimes:html body)
    ==
  (queue-request [eyre-id %refresh ~ ~ ~ ~ ~ retry] req)
::
++  rpc-request
  |=  [eyre-id=@ta jon=json]
  ^-  (quip card _this)
  =/  target=(unit @t)  (string-at 'target' jon)
  =/  method=(unit @t)  (string-at 'method' jon)
  =/  nsid=(unit @t)  (string-at 'nsid' jon)
  =/  query=(unit @t)  (string-at 'query' jon)
  =/  payload=(unit json)  (json-at 'body' jon)
  ?~  target
    :_  this
    (give-simple-payload:app:server eyre-id (error-json 400 'missing target'))
  ?~  method
    :_  this
    (give-simple-payload:app:server eyre-id (error-json 400 'missing method'))
  ?~  nsid
    :_  this
    (give-simple-payload:app:server eyre-id (error-json 400 'missing nsid'))
  ?.  (valid-nsid u.nsid)
    :_  this
    (give-simple-payload:app:server eyre-id (error-json 400 'invalid nsid'))
  =/  is-get=?  =('GET' u.method)
  =/  is-post=?  =('POST' u.method)
  ?.  |(is-get is-post)
    :_  this
    (give-simple-payload:app:server eyre-id (error-json 400 'method must be GET or POST'))
  =/  base=(unit @t)
    ?:  =('public' u.target)  `'https://public.api.bsky.app'
    ?:  =('pds' u.target)  ?~(account ~ `service.u.account)
    ~
  ?~  base
    :_  this
    (give-simple-payload:app:server eyre-id (error-json 409 'target unavailable'))
  =/  suffix=@t  ?~(query '' u.query)
  ?.  ?|  =('' suffix)  =('?' (end 3 suffix))  ==
    :_  this
    (give-simple-payload:app:server eyre-id (error-json 400 'query must begin with ?'))
  =/  url=@t  (rap 3 ~[u.base '/xrpc/' u.nsid suffix])
  =/  headers=(list [@t @t])  ~[['accept' 'application/json'] ['content-type' 'application/json']]
  =/  body=(unit octs)
    ?:  is-get  ~
    ?~  payload  `(as-octs:mimes:html '{}')
    `(as-octs:mimes:html (en:json:html u.payload))
  =/  meth=method:http  ?:(is-get %'GET' %'POST')
  ?:  ?&  =('pds' u.target)  ?=(^ account)  ?=(^ oauth.u.account)  ==
    =/  od=oauth-data:atpro  u.oauth.u.account
    =/  rpc=oauth-rpc:atpro  [meth url headers body]
    =/  req=request:http  (oauth-rpc-request rpc pds-nonce.od)
    (queue-request [eyre-id %rpc ~ ~ ~ `rpc ~ %.n] req)
  =?  headers  &(?=(^ account) =('pds' u.target))
    (snoc headers ['authorization' (rap 3 ~['Bearer ' access-token.u.account])])
  (queue-request [eyre-id %rpc ~ ~ ~ ~ ~ %.n] [meth url headers body])
::
++  blob-request
  |=  [eyre-id=@ta req=inbound-request:eyre]
  ^-  (quip card _this)
  ?~  account
    :_  this
    (give-simple-payload:app:server eyre-id (error-json 409 'not connected'))
  ?~  body.request.req
    :_  this
    (give-simple-payload:app:server eyre-id (error-json 400 'missing blob body'))
  ?:  (gth p.u.body.request.req 10.485.760)
    :_  this
    (give-simple-payload:app:server eyre-id (error-json 413 'blob exceeds 10 MiB'))
  =/  mime=(unit @t)  (get-header:http 'content-type' header-list.request.req)
  ?~  mime
    :_  this
    (give-simple-payload:app:server eyre-id (error-json 400 'missing blob content type'))
  ?.  ?|  =('image/jpeg' u.mime)
          =('image/png' u.mime)
          =('image/gif' u.mime)
          =('image/webp' u.mime)
          =('image/avif' u.mime)
          =('image/heic' u.mime)
          =('image/heif' u.mime)
      ==
    :_  this
    (give-simple-payload:app:server eyre-id (error-json 415 'unsupported image content type'))
  =/  url=@t  (rap 3 ~[service.u.account '/xrpc/com.atproto.repo.uploadBlob'])
  =/  headers=(list [@t @t])  ~[['accept' 'application/json'] ['content-type' u.mime]]
  ?:  ?=(^ oauth.u.account)
    =/  rpc=oauth-rpc:atpro  [%'POST' url headers body.request.req]
    =/  od=oauth-data:atpro  u.oauth.u.account
    (queue-request [eyre-id %rpc ~ ~ ~ `rpc ~ %.n] (oauth-rpc-request rpc pds-nonce.od))
  =.  headers
    (snoc headers ['authorization' (rap 3 ~['Bearer ' access-token.u.account])])
  (queue-request [eyre-id %rpc ~ ~ ~ ~ ~ %.n] [%'POST' url headers body.request.req])
::
++  oauth-rpc-request
  |=  [rpc=oauth-rpc:atpro nonce=(unit @t)]
  ^-  request:http
  ?>  ?=(^ account)
  ?>  ?=(^ oauth.u.account)
  =/  od=oauth-data:atpro  u.oauth.u.account
  =/  method-text=@t  ?:(=(%'GET' method.rpc) 'GET' 'POST')
  =/  dpop=@t  (proof method-text url.rpc nonce `access-token.u.account key.od)
  =/  headers=(list [@t @t])
    (weld headers.rpc ~[['authorization' (rap 3 ~['DPoP ' access-token.u.account])] ['dpop' dpop]])
  [method.rpc url.rpc headers body.rpc]
::
++  par-request
  |=  auth=pending-auth:atpro
  ^-  request:http
  =/  fields=(list [@t @t])
    :~  ['response_type' 'code']
        ['client_id' client-id.auth]
        ['redirect_uri' redirect-uri.auth]
        ['scope' scope.auth]
        ['state' state.auth]
        ['code_challenge' (pkce-challenge:atpro-oauth verifier.auth)]
        ['code_challenge_method' 'S256']
        ['login_hint' handle.auth]
    ==
  =/  body=@t  (form-body fields)
  =/  dpop=@t  (proof 'POST' par-endpoint.auth auth-nonce.auth ~ key.auth)
  :*  %'POST'
      par-endpoint.auth
      :~  ['content-type' 'application/x-www-form-urlencoded']
          ['accept' 'application/json']
          ['dpop' dpop]
      ==
      `(as-octs:mimes:html body)
  ==
::
++  token-request
  |=  [auth=pending-auth:atpro code=@t]
  ^-  request:http
  =/  fields=(list [@t @t])
    :~  ['grant_type' 'authorization_code']
        ['client_id' client-id.auth]
        ['redirect_uri' redirect-uri.auth]
        ['code' code]
        ['code_verifier' verifier.auth]
    ==
  =/  body=@t  (form-body fields)
  =/  dpop=@t  (proof 'POST' token-endpoint.auth auth-nonce.auth ~ key.auth)
  :*  %'POST'
      token-endpoint.auth
      :~  ['content-type' 'application/x-www-form-urlencoded']
          ['accept' 'application/json']
          ['dpop' dpop]
      ==
      `(as-octs:mimes:html body)
  ==
::
++  client-metadata-json
  ^-  json
  ?~  oauth-client
    (pairs:enjs:format ~[['error' s+'OAuth client has not been configured from this origin']])
  %-  pairs:enjs:format
  :~  ['client_id' s+client-id.u.oauth-client]
      ['application_type' s+'web']
      ['grant_types' a+~[s+'authorization_code' s+'refresh_token']]
      ['scope' s+scope.u.oauth-client]
      ['response_types' a+~[s+'code']]
      ['redirect_uris' a+~[s+redirect-uri.u.oauth-client]]
      ['token_endpoint_auth_method' s+'none']
      ['dpop_bound_access_tokens' b+%.y]
  ==
::
++  handle-callback
  |=  [eyre-id=@ta rl=request-line:server]
  ^-  (quip card _this)
  =/  code=(unit @t)  (get-param args.rl 'code')
  =/  st=(unit @t)  (get-param args.rl 'state')
  =/  iss=(unit @t)  (get-param args.rl 'iss')
  ?~  code
    :_  this
    (give-simple-payload:app:server eyre-id (error-json 400 'OAuth callback missing code'))
  ?~  st
    :_  this
    (give-simple-payload:app:server eyre-id (error-json 400 'OAuth callback missing state'))
  =/  auth=(unit pending-auth:atpro)  (~(get by pending) u.st)
  ?~  auth
    :_  this
    (give-simple-payload:app:server eyre-id (error-json 400 'unknown or expired OAuth state'))
  ?:  ?&  ?=(^ iss)  !=(u.iss auth-server.u.auth)  ==
    :_  this
    (give-simple-payload:app:server eyre-id (error-json 400 'OAuth issuer mismatch'))
  =.  pending  (~(del by pending) u.st)
  (queue-request [eyre-id %oauth-token ~ ~ auth ~ code %.n] (token-request u.auth u.code))
::
++  handle-http
  |=  [eyre-id=@ta req=inbound-request:eyre]
  ^-  (quip card _this)
  =/  rl=request-line:server  (parse-request-line:server url.request.req)
  =/  site=(list @t)  site.rl
  ?.  ?=([%apps %atpro %api *] site)
    :_  this
    (give-simple-payload:app:server eyre-id [[301 ~[['location' '/apps/atpro/']]] ~])
  =/  route=(list @t)  t.t.t.site
  ?:  ?&  ?=(%'GET' method.request.req)
          ?=([%oauth %client-metadata ~] route)
      ==
    :_  this
    (give-simple-payload:app:server eyre-id (json-payload ?~(oauth-client 503 200) client-metadata-json))
  ?:  ?&  ?=(%'GET' method.request.req)
          ?=([%oauth %callback ~] route)
      ==
    (handle-callback eyre-id rl)
  ?.  authenticated.req
    :_  this
    (give-simple-payload:app:server eyre-id (login-redirect:gen:server request.req))
  ?:  ?&  ?=(%'GET' method.request.req)  ?=([%status ~] route)  ==
    :_  this
    (give-simple-payload:app:server eyre-id (json-payload 200 (session-json account)))
  ?:  ?&  ?=(%'GET' method.request.req)  ?=([%identity ~] route)  ==
    :_  this
    (give-simple-payload:app:server eyre-id (json-payload 200 (identity-json public-identity)))
  ?.  ?=(%'POST' method.request.req)
    :_  this
    (give-simple-payload:app:server eyre-id (error-json 405 'method not allowed'))
  ?:  ?=([%logout ~] route)
    =.  account  ~
    :_  this
    (give-simple-payload:app:server eyre-id (json-payload 200 (session-json account)))
  ?:  ?=([%refresh ~] route)
    (refresh-request eyre-id)
  ?:  ?=([%blob ~] route)
    (blob-request eyre-id req)
  ?:  ?=([%identity %publish ~] route)
    ?~  account
      :_  this
      (give-simple-payload:app:server eyre-id (error-json 409 'connect an AT Protocol account first'))
    =.  public-identity  `[did.u.account handle.u.account now.bowl]
    :_  this
    (give-simple-payload:app:server eyre-id (json-payload 200 (identity-json public-identity)))
  ?:  ?=([%identity %clear ~] route)
    =.  public-identity  ~
    :_  this
    (give-simple-payload:app:server eyre-id (json-payload 200 (identity-json public-identity)))
  ?:  ?=([%identity %scan ~] route)
    :_  this
    (give-simple-payload:app:server eyre-id (json-payload 200 (scan-identities-json our.bowl now.bowl)))
  ?~  body.request.req
    :_  this
    (give-simple-payload:app:server eyre-id (error-json 400 'missing JSON body'))
  =/  jon=(unit json)  (de:json:html q.u.body.request.req)
  ?~  jon
    :_  this
    (give-simple-payload:app:server eyre-id (error-json 400 'invalid JSON body'))
  ?:  ?=([%login ~] route)  (login-request eyre-id u.jon)
  ?:  ?=([%rpc ~] route)  (rpc-request eyre-id u.jon)
  ?:  ?=([%oauth %start ~] route)  (oauth-start eyre-id u.jon)
  :_  this
  (give-simple-payload:app:server eyre-id (error-json 404 'not found'))
  --
::
++  on-watch
  |=  =path
  ^-  (quip card _this)
  ?+  path  (on-watch:def path)
      [%http-response @ ~]  [~ this]
  ==
::
++  on-peek
  |=  =path
  ^-  (unit (unit cage))
  ?+  path  [~ ~]
      [%x %status ~]  ``json+!>((session-json account))
      [%x %identity ~]       ``noun+!>(public-identity)
      [%x %identity-json ~]  ``json+!>((identity-json public-identity))
  ==
::
++  on-leave  on-leave:def
++  on-agent  on-agent:def
++  on-fail   on-fail:def
::
++  on-arvo
  |=  [=wire sign=sign-arvo]
  ^-  (quip card _this)
  |^
  ?+  wire  (on-arvo:def wire sign)
      [%eyre *]
    ?:  ?=(%bound +<.sign)
      ~?  !accepted.sign  [dap.bowl %binding-rejected binding.sign]
      [~ this]
    [~ this]
  ::
      [%iris @ ~]
    =/  rid=(unit @uv)  (slaw %uv i.t.wire)
    ?~  rid  `this
    =/  ctx=(unit request-context:atpro)  (~(get by in-flight) u.rid)
    ?~  ctx  `this
    =.  in-flight  (~(del by in-flight) u.rid)
    ?.  ?=([%iris %http-response *] sign)
      :_  this
      (give-simple-payload:app:server eyre-id.u.ctx (error-json 502 'remote service unavailable'))
    =/  resp=client-response:iris  client-response.sign
    ?.  ?=(%finished -.resp)
      :_  this
      (give-simple-payload:app:server eyre-id.u.ctx (error-json 502 'incomplete remote response'))
    =/  status=@ud  status-code.response-header.resp
    =/  headers=header-list:http  headers.response-header.resp
    =/  nonce=(unit @t)  (dpop-nonce headers)
    =/  body=@t  ?~(full-file.resp '' `@t`q.data.u.full-file.resp)
    ::
    ?:  =(%oauth-identity kind.u.ctx)
      ?>  ?=(^ work.u.ctx)
      =/  work=oauth-work:atpro  u.work.u.ctx
      ?.  &((gte status 200) (lth status 300))
        :_  this
        (give-simple-payload:app:server eyre-id.u.ctx (text-payload status body))
      =/  jon=(unit json)  (de:json:html body)
      ?~  jon
        :_  this
        (give-simple-payload:app:server eyre-id.u.ctx (error-json 502 'invalid identity response'))
      =/  did=(unit @t)  (string-at 'did' u.jon)
      ?~  did
        :_  this
        (give-simple-payload:app:server eyre-id.u.ctx (error-json 502 'handle resolution response missing DID'))
      =/  url=(unit @t)  (did-url u.did)
      ?~  url
        :_  this
        (give-simple-payload:app:server eyre-id.u.ctx (error-json 502 'resolved DID method is unsupported'))
      =/  next-work=oauth-work:atpro
        work(did `u.did, handle `identifier.work)
      (enqueue [eyre-id.u.ctx %oauth-did ~ `next-work ~ ~ ~ %.n] [%'GET' u.url ~[['accept' 'application/json']] ~])
    ::
    ?:  =(%oauth-did kind.u.ctx)
      ?>  ?=(^ work.u.ctx)
      =/  work=oauth-work:atpro  u.work.u.ctx
      ?>  ?=(^ did.work)
      ?.  &((gte status 200) (lth status 300))
        :_  this
        (give-simple-payload:app:server eyre-id.u.ctx (text-payload status body))
      =/  did-doc=(unit json)  (de:json:html body)
      ?~  did-doc
        :_  this
        (give-simple-payload:app:server eyre-id.u.ctx (error-json 502 'invalid DID document'))
      =/  document-id=(unit @t)  (string-at 'id' u.did-doc)
      ?.  ?&  ?=(^ document-id)  =(u.document-id u.did.work)  ==
        :_  this
        (give-simple-payload:app:server eyre-id.u.ctx (error-json 502 'DID document id mismatch'))
      =/  handle=(unit @t)  (find-handle u.did-doc)
      ?~  handle
        :_  this
        (give-simple-payload:app:server eyre-id.u.ctx (error-json 502 'DID document has no AT Protocol handle alias'))
      ?:  ?&  ?=(^ handle.work)  !=(u.handle u.handle.work)  ==
        :_  this
        %+  give-simple-payload:app:server  eyre-id.u.ctx
        %+  error-json  502
        (rap 3 ~['handle and DID document do not match: ' u.handle.work ' != ' u.handle])
      =/  service=(unit @t)  (find-pds u.did-doc)
      ?~  service
        :_  this
        (give-simple-payload:app:server eyre-id.u.ctx (error-json 502 'DID document has no AT Protocol PDS'))
      =/  clean=@t  (strip-final-slash u.service)
      ?.  (valid-service clean)
        :_  this
        (give-simple-payload:app:server eyre-id.u.ctx (error-json 502 'identity PDS is not a safe HTTPS origin'))
      =/  next-work=oauth-work:atpro
        work(handle `u.handle, service `clean)
      =/  url=@t  (rap 3 ~[clean '/.well-known/oauth-protected-resource'])
      (enqueue [eyre-id.u.ctx %oauth-resource ~ `next-work ~ ~ ~ %.n] [%'GET' url ~[['accept' 'application/json']] ~])
    ::
    ?:  =(%oauth-resource kind.u.ctx)
      ?>  ?=(^ work.u.ctx)
      =/  work=oauth-work:atpro  u.work.u.ctx
      ?.  =(200 status)
        :_  this
        (give-simple-payload:app:server eyre-id.u.ctx (text-payload status body))
      =/  jon=(unit json)  (de:json:html body)
      ?~  jon
        :_  this
        (give-simple-payload:app:server eyre-id.u.ctx (error-json 502 'invalid protected-resource metadata'))
      =/  servers=(unit json)  (json-at 'authorization_servers' u.jon)
      ?~  servers
        :_  this
        (give-simple-payload:app:server eyre-id.u.ctx (error-json 502 'PDS metadata has no authorization server'))
      =/  auth-server=(unit @t)  (first-string u.servers)
      ?~  auth-server
        :_  this
        (give-simple-payload:app:server eyre-id.u.ctx (error-json 502 'invalid authorization server metadata'))
      =/  clean=@t  (strip-final-slash u.auth-server)
      ?.  (valid-service clean)
        :_  this
        (give-simple-payload:app:server eyre-id.u.ctx (error-json 502 'authorization server is not a safe HTTPS origin'))
      =/  next-work=oauth-work:atpro  work(auth-server `clean)
      =/  url=@t  (rap 3 ~[clean '/.well-known/oauth-authorization-server'])
      (enqueue [eyre-id.u.ctx %oauth-metadata ~ `next-work ~ ~ ~ %.n] [%'GET' url ~[['accept' 'application/json']] ~])
    ::
    ?:  =(%oauth-metadata kind.u.ctx)
      ?>  ?=(^ work.u.ctx)
      =/  work=oauth-work:atpro  u.work.u.ctx
      ?.  =(200 status)
        :_  this
        (give-simple-payload:app:server eyre-id.u.ctx (text-payload status body))
      =/  jon=(unit json)  (de:json:html body)
      ?~  jon
        :_  this
        (give-simple-payload:app:server eyre-id.u.ctx (error-json 502 'invalid authorization-server metadata'))
      =/  issuer=(unit @t)  (string-at 'issuer' u.jon)
      =/  authorize=(unit @t)  (string-at 'authorization_endpoint' u.jon)
      =/  token=(unit @t)  (string-at 'token_endpoint' u.jon)
      =/  par=(unit @t)  (string-at 'pushed_authorization_request_endpoint' u.jon)
      ?~  issuer
        :_  this
        (give-simple-payload:app:server eyre-id.u.ctx (error-json 502 'metadata missing issuer'))
      ?~  authorize
        :_  this
        (give-simple-payload:app:server eyre-id.u.ctx (error-json 502 'metadata missing authorization endpoint'))
      ?~  token
        :_  this
        (give-simple-payload:app:server eyre-id.u.ctx (error-json 502 'metadata missing token endpoint'))
      ?~  par
        :_  this
        (give-simple-payload:app:server eyre-id.u.ctx (error-json 502 'metadata missing PAR endpoint'))
      ?>  ?=(^ auth-server.work)
      ?.  ?&  =(u.issuer u.auth-server.work)
              (valid-https-url u.authorize)
              (valid-https-url u.token)
              (valid-https-url u.par)
          ==
        :_  this
        (give-simple-payload:app:server eyre-id.u.ctx (error-json 502 'authorization metadata failed validation'))
      ?>  ?=(^ did.work)
      ?>  ?=(^ handle.work)
      ?>  ?=(^ service.work)
      =/  entropy=@  (cat 3 eny.bowl request-count)
      =/  key=@  (make-private-key:atpro-oauth (shas %oauth-key entropy))
      =/  verifier=@t  (pkce-verifier:atpro-oauth (shas %oauth-pkce entropy))
      =/  state-token=@t  (token:atpro-oauth (shas %oauth-state entropy))
      =/  auth=pending-auth:atpro
        :*  identifier.work  u.did.work  u.handle.work  u.service.work
            u.auth-server.work  u.authorize  u.token  u.par
            client-id.work  redirect-uri.work  'atproto transition:generic'
            state-token  verifier  key  ~
        ==
      (enqueue [eyre-id.u.ctx %oauth-par ~ ~ `auth ~ ~ %.n] (make-par auth))
    ::
    ?:  =(%oauth-par kind.u.ctx)
      ?>  ?=(^ auth.u.ctx)
      =/  auth=pending-auth:atpro  u.auth.u.ctx
      ?:  ?&  |(=(400 status) =(401 status))  ?=(^ nonce)  !retry.u.ctx  ==
        =/  updated=pending-auth:atpro  auth(auth-nonce nonce)
        (enqueue [eyre-id.u.ctx %oauth-par ~ ~ `updated ~ ~ %.y] (make-par updated))
      ?.  &((gte status 200) (lth status 300))
        :_  this
        (give-simple-payload:app:server eyre-id.u.ctx (text-payload status body))
      =?  auth  ?=(^ nonce)  auth(auth-nonce nonce)
      =/  jon=(unit json)  (de:json:html body)
      ?~  jon
        :_  this
        (give-simple-payload:app:server eyre-id.u.ctx (error-json 502 'invalid PAR response'))
      =/  request-uri=(unit @t)  (string-at 'request_uri' u.jon)
      ?~  request-uri
        :_  this
        (give-simple-payload:app:server eyre-id.u.ctx (error-json 502 'PAR response missing request URI'))
      =.  pending  (~(put by pending) state.auth auth)
      =/  url=@t
        %+  rap  3
        :~  authorization-endpoint.auth
            '?client_id='  (percent-encode client-id.auth)
            '&request_uri='  (percent-encode u.request-uri)
        ==
      :_  this
      (give-simple-payload:app:server eyre-id.u.ctx (json-payload 200 (frond:enjs:format 'url' s+url)))
    ::
    ?:  =(%oauth-token kind.u.ctx)
      ?>  ?=(^ auth.u.ctx)
      =/  auth=pending-auth:atpro  u.auth.u.ctx
      ?:  ?&  |(=(400 status) =(401 status))  ?=(^ nonce)  !retry.u.ctx  ==
        =/  updated=pending-auth:atpro  auth(auth-nonce nonce)
        ?>  ?=(^ code.u.ctx)
        (enqueue [eyre-id.u.ctx %oauth-token ~ ~ `updated ~ code.u.ctx %.y] (make-token updated u.code.u.ctx))
      ?.  &((gte status 200) (lth status 300))
        :_  this
        (give-simple-payload:app:server eyre-id.u.ctx (text-payload status body))
      =/  parsed=(unit [access=@t refresh=(unit @t) sub=@t scope=@t])  (parse-oauth-token body)
      ?~  parsed
        :_  this
        (give-simple-payload:app:server eyre-id.u.ctx (error-json 502 'invalid OAuth token response'))
      ?.  =(sub.u.parsed did.auth)
        :_  this
        (give-simple-payload:app:server eyre-id.u.ctx (error-json 403 'OAuth subject does not match requested account'))
      ?~  refresh.u.parsed
        :_  this
        (give-simple-payload:app:server eyre-id.u.ctx (error-json 502 'OAuth response omitted refresh token'))
      ?.  !=(~ (find "atproto" (trip scope.u.parsed)))
        :_  this
        (give-simple-payload:app:server eyre-id.u.ctx (error-json 403 'OAuth response omitted atproto scope'))
      =/  od=oauth-data:atpro
        :*  auth-server.auth  token-endpoint.auth  key.auth
            ?:(?=(^ nonce) nonce auth-nonce.auth)  ~
            client-id.auth  redirect-uri.auth  scope.u.parsed
        ==
      =.  account  `[service.auth did.auth handle.auth access.u.parsed u.refresh.u.parsed `od]
      :_  this
      (give-simple-payload:app:server eyre-id.u.ctx [[303 ~[['location' '/apps/atpro/']]] ~])
    ::
    ?:  =(%login kind.u.ctx)
      ?.  &((gte status 200) (lth status 300))
        :_  this
        (give-simple-payload:app:server eyre-id.u.ctx (text-payload status body))
      =/  requested=@t  ?~(service.u.ctx 'https://bsky.social' u.service.u.ctx)
      =/  parsed=(unit session:atpro)  (parse-password-session requested body)
      ?~  parsed
        :_  this
        (give-simple-payload:app:server eyre-id.u.ctx (error-json 502 'invalid session response'))
      =.  account  parsed
      :_  this
      (give-simple-payload:app:server eyre-id.u.ctx (json-payload 200 (session-json account)))
    ::
    ?:  =(%refresh kind.u.ctx)
      ?~  account
        :_  this
        (give-simple-payload:app:server eyre-id.u.ctx (error-json 409 'not connected'))
      ?~  oauth.u.account
        ?.  &((gte status 200) (lth status 300))
          :_  this
          (give-simple-payload:app:server eyre-id.u.ctx (text-payload status body))
        =/  parsed=(unit session:atpro)  (parse-password-session service.u.account body)
        ?~  parsed
          :_  this
          (give-simple-payload:app:server eyre-id.u.ctx (error-json 502 'invalid refresh response'))
        :_  this(account parsed)
        (give-simple-payload:app:server eyre-id.u.ctx (json-payload 200 (session-json parsed)))
      =/  od=oauth-data:atpro  u.oauth.u.account
      =/  old=session:atpro  u.account
      ?:  ?&  |(=(400 status) =(401 status))  ?=(^ nonce)  !retry.u.ctx  ==
        =/  new-od=oauth-data:atpro  od(auth-nonce nonce)
        =/  next=session:atpro  old(oauth (some new-od))
        =/  req=request:http  (make-refresh next new-od)
        (enqueue-account (some next) [eyre-id.u.ctx %refresh ~ ~ ~ ~ ~ %.y] req)
      ?.  &((gte status 200) (lth status 300))
        :_  this
        (give-simple-payload:app:server eyre-id.u.ctx (text-payload status body))
      =/  parsed=(unit [access=@t refresh=(unit @t) sub=@t scope=@t])  (parse-oauth-token body)
      ?~  parsed
        :_  this
        (give-simple-payload:app:server eyre-id.u.ctx (error-json 502 'invalid OAuth refresh response'))
      ?.  =(sub.u.parsed did.old)
        :_  this
        (give-simple-payload:app:server eyre-id.u.ctx (error-json 403 'OAuth refresh subject mismatch'))
      =/  new-refresh=@t  ?~(refresh.u.parsed refresh-token.old u.refresh.u.parsed)
      =/  new-od=oauth-data:atpro
        od(auth-nonce ?:(?=(^ nonce) nonce auth-nonce.od), scope scope.u.parsed)
      =/  next=session:atpro
        old(access-token access.u.parsed, refresh-token new-refresh, oauth (some new-od))
      :_  (save-account (some next))
      (give-simple-payload:app:server eyre-id.u.ctx (json-payload 200 (session-json (some next))))
    ::
    ?:  ?&  =(%rpc kind.u.ctx)  ?=(^ rpc.u.ctx)  ?=(^ account)  ?=(^ oauth.u.account)  ==
      =/  od=oauth-data:atpro  u.oauth.u.account
      =/  old=session:atpro  u.account
      =?  od  ?=(^ nonce)  od(pds-nonce nonce)
      =/  next=session:atpro  old(oauth (some od))
      ?:  ?&  |(=(400 status) =(401 status))  ?=(^ nonce)  !retry.u.ctx  ==
        =/  req=request:http  (make-rpc u.rpc.u.ctx nonce)
        (enqueue-account (some next) u.ctx(retry %.y) req)
      :_  (save-account (some next))
      (give-simple-payload:app:server eyre-id.u.ctx (text-payload status ?:(=('' body) 'null' body)))
    :_  this
    (give-simple-payload:app:server eyre-id.u.ctx (text-payload status ?:(=('' body) 'null' body)))
  ==
  ::
  ++  enqueue
    |=  [ctx=request-context:atpro req=request:http]
    ^-  (quip card _this)
    =/  rid=@uv  `@uv`(shas %atpro-request (cat 3 eny.bowl request-count))
    =.  request-count  +(request-count)
    =.  in-flight  (~(put by in-flight) rid ctx)
    :_  this
    :~  [%pass /iris/(scot %uv rid) %arvo %i %request req *outbound-config:iris]
    ==
  ::
  ++  enqueue-account
    |=  [next-account=(unit session:atpro) ctx=request-context:atpro req=request:http]
    ^-  (quip card _this)
    =/  rid=@uv  `@uv`(shas %atpro-request (cat 3 eny.bowl request-count))
    =.  account  next-account
    =.  request-count  +(request-count)
    =.  in-flight  (~(put by in-flight) rid ctx)
    :_  this
    :~  [%pass /iris/(scot %uv rid) %arvo %i %request req *outbound-config:iris]
    ==
  ::
  ++  save-account
    |=  next-account=(unit session:atpro)
    ^-  _this
    this(account next-account)
  ::
  ++  arvo-proof
    |=  [method=@t url=@t nonce=(unit @t) access=(unit @t) key=@]
    ^-  @t
    %-  dpop-proof:atpro-oauth
    :*  method  url  nonce  access  now.bowl
        (cat 3 eny.bowl request-count)
        key
    ==
  ::
  ++  make-par
    |=  auth=pending-auth:atpro
    ^-  request:http
    =/  fields=(list [@t @t])
      :~  ['response_type' 'code']
          ['client_id' client-id.auth]
          ['redirect_uri' redirect-uri.auth]
          ['scope' scope.auth]
          ['state' state.auth]
          ['code_challenge' (pkce-challenge:atpro-oauth verifier.auth)]
          ['code_challenge_method' 'S256']
          ['login_hint' handle.auth]
      ==
    =/  body=@t  (form-body fields)
    =/  dpop=@t  (arvo-proof 'POST' par-endpoint.auth auth-nonce.auth ~ key.auth)
    :*  %'POST'
        par-endpoint.auth
        ~[['content-type' 'application/x-www-form-urlencoded'] ['accept' 'application/json'] ['dpop' dpop]]
        `(as-octs:mimes:html body)
    ==
  ::
  ++  make-token
    |=  [auth=pending-auth:atpro code=@t]
    ^-  request:http
    =/  fields=(list [@t @t])
      :~  ['grant_type' 'authorization_code']
          ['client_id' client-id.auth]
          ['redirect_uri' redirect-uri.auth]
          ['code' code]
          ['code_verifier' verifier.auth]
      ==
    =/  body=@t  (form-body fields)
    =/  dpop=@t  (arvo-proof 'POST' token-endpoint.auth auth-nonce.auth ~ key.auth)
    :*  %'POST'
        token-endpoint.auth
        ~[['content-type' 'application/x-www-form-urlencoded'] ['accept' 'application/json'] ['dpop' dpop]]
        `(as-octs:mimes:html body)
    ==
  ::
  ++  make-refresh
    |=  [sess=session:atpro od=oauth-data:atpro]
    ^-  request:http
    =/  body=@t
      (form-body ~[['grant_type' 'refresh_token'] ['refresh_token' refresh-token.sess] ['client_id' client-id.od]])
    =/  dpop=@t  (arvo-proof 'POST' token-endpoint.od auth-nonce.od ~ key.od)
    :*  %'POST'
        token-endpoint.od
        ~[['content-type' 'application/x-www-form-urlencoded'] ['accept' 'application/json'] ['dpop' dpop]]
        `(as-octs:mimes:html body)
    ==
  ::
  ++  make-rpc
    |=  [rpc=oauth-rpc:atpro nonce=(unit @t)]
    ^-  request:http
    ?>  ?=(^ account)
    ?>  ?=(^ oauth.u.account)
    =/  od=oauth-data:atpro  u.oauth.u.account
    =/  method-text=@t  ?:(=(%'GET' method.rpc) 'GET' 'POST')
    =/  dpop=@t  (arvo-proof method-text url.rpc nonce `access-token.u.account key.od)
    =/  headers=(list [@t @t])
      (weld headers.rpc ~[['authorization' (rap 3 ~['DPoP ' access-token.u.account])] ['dpop' dpop]])
    [method.rpc url.rpc headers body.rpc]
  --
--
