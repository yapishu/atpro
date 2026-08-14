::  atpro: native AT Protocol XRPC client
::
::  Owns credentials and sends constrained HTTPS requests through %iris.
::  The browser never receives access or refresh tokens.
::
/-  atpro
/+  dbug, default-agent, server
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
++  strip-final-slash
  |=  txt=@t
  ^-  @t
  =/  t=tape  (trip txt)
  ?~  t  txt
  ?.  =('/' (rear t))  txt
  =/  all=tape  t
  (crip (scag (dec (lent all)) all))
::
++  valid-service
  |=  txt=@t
  ^-  ?
  ?.  (starts-with 'https://' txt)  %.n
  =/  rest=tape  (slag 8 (trip txt))
  ?&  !=(~ rest)
      =(~ (find "/" rest))
      =(~ (find "?" rest))
      =(~ (find "#" rest))
      =(~ (find "@" rest))
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
  ==
::
++  parse-session
  |=  [service=@t body=@t]
  ^-  (unit session:atpro)
  =/  jon=(unit json)  (de:json:html body)
  ?~  jon  ~
  =/  access=(unit @t)  (string-at 'accessJwt' u.jon)
  =/  refresh=(unit @t)  (string-at 'refreshJwt' u.jon)
  =/  did=(unit @t)  (string-at 'did' u.jon)
  =/  handle=(unit @t)  (string-at 'handle' u.jon)
  ?~  access  ~
  ?~  refresh  ~
  ?~  did  ~
  ?~  handle  ~
  `[service u.did u.handle u.access u.refresh]
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
  |=  [eyre-id=@ta kind=request-kind:atpro service=(unit @t) req=request:http]
  ^-  (quip card _this)
  =/  rid=@uv  next-id
  =.  request-count  +(request-count)
  =.  in-flight  (~(put by in-flight) rid [eyre-id kind service])
  :_  this
  :~  [%pass /iris/(scot %uv rid) %arvo %i %request req *outbound-config:iris]
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
  =/  service=@t
    (strip-final-slash ?~(requested 'https://bsky.social' u.requested))
  ?.  (valid-service service)
    :_  this
    (give-simple-payload:app:server eyre-id (error-json 400 'service must be an HTTPS origin'))
  =/  payload=json
    (pairs:enjs:format ~[['identifier' s+u.identifier] ['password' s+u.password]])
  =/  req=request:http
    :*  %'POST'
        (rap 3 ~[service '/xrpc/com.atproto.server.createSession'])
        :~  ['content-type' 'application/json']
            ['accept' 'application/json']
        ==
        `(as-octs:mimes:html (en:json:html payload))
    ==
  (queue-request eyre-id %login `service req)
::
++  refresh-request
  |=  eyre-id=@ta
  ^-  (quip card _this)
  ?~  account
    :_  this
    (give-simple-payload:app:server eyre-id (error-json 409 'not connected'))
  =/  req=request:http
    :*  %'POST'
        (rap 3 ~[service.u.account '/xrpc/com.atproto.server.refreshSession'])
        :~  ['authorization' (rap 3 ~['Bearer ' refresh-jwt.u.account])]
            ['accept' 'application/json']
        ==
        ~
    ==
  (queue-request eyre-id %refresh ~ req)
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
    ?:  =('public' u.target)
      `'https://public.api.bsky.app'
    ?:  =('pds' u.target)
      ?~(account ~ `service.u.account)
    ~
  ?~  base
    :_  this
    (give-simple-payload:app:server eyre-id (error-json 409 'target unavailable'))
  =/  suffix=@t  ?~(query '' u.query)
  ?.  ?|  =('' suffix)
          =('?' (end 3 suffix))
      ==
    :_  this
    (give-simple-payload:app:server eyre-id (error-json 400 'query must begin with ?'))
  =/  url=@t  (rap 3 ~[u.base '/xrpc/' u.nsid suffix])
  =/  headers=(list [@t @t])
    :~  ['accept' 'application/json']
        ['content-type' 'application/json']
    ==
  =?  headers  &(?=(^ account) =('pds' u.target))
    (snoc headers ['authorization' (rap 3 ~['Bearer ' access-jwt.u.account])])
  =/  body=(unit octs)
    ?:  is-get  ~
    ?~  payload  `(as-octs:mimes:html '{}')
    `(as-octs:mimes:html (en:json:html u.payload))
  =/  req=request:http
    [?:(is-get %'GET' %'POST') url headers body]
  (queue-request eyre-id %rpc ~ req)
::
++  handle-http
  |=  [eyre-id=@ta req=inbound-request:eyre]
  ^-  (quip card _this)
  =/  rl=request-line:server
    (parse-request-line:server url.request.req)
  =/  site=(list @t)  site.rl
  ?.  ?=([%apps %atpro %api *] site)
    :_  this
    %+  give-simple-payload:app:server  eyre-id
    [[301 ~[['location' '/apps/atpro/']]] ~]
  ?.  authenticated.req
    :_  this
    %+  give-simple-payload:app:server  eyre-id
    (login-redirect:gen:server request.req)
  =/  route=(list @t)  t.t.t.site
  ?:  ?&  ?=(%'GET' method.request.req)
          ?=([%status ~] route)
      ==
    :_  this
    %+  give-simple-payload:app:server  eyre-id
    (json-payload 200 (session-json account))
  ?.  ?=(%'POST' method.request.req)
    :_  this
    %+  give-simple-payload:app:server  eyre-id
    (error-json 405 'method not allowed')
  ?:  ?=([%logout ~] route)
    =.  account  ~
    :_  this
    %+  give-simple-payload:app:server  eyre-id
    (json-payload 200 (session-json account))
  ?:  ?=([%refresh ~] route)
    (refresh-request eyre-id)
  ?~  body.request.req
    :_  this
    %+  give-simple-payload:app:server  eyre-id
    (error-json 400 'missing JSON body')
  =/  jon=(unit json)  (de:json:html q.u.body.request.req)
  ?~  jon
    :_  this
    %+  give-simple-payload:app:server  eyre-id
    (error-json 400 'invalid JSON body')
  ?:  ?=([%login ~] route)
    (login-request eyre-id u.jon)
  ?:  ?=([%rpc ~] route)
    (rpc-request eyre-id u.jon)
  :_  this
  %+  give-simple-payload:app:server  eyre-id
  (error-json 404 'not found')
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
      [%x %status ~]
    ``json+!>((session-json account))
  ==
::
++  on-leave  on-leave:def
++  on-agent  on-agent:def
++  on-fail   on-fail:def
::
++  on-arvo
  |=  [=wire sign=sign-arvo]
  ^-  (quip card _this)
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
      %+  give-simple-payload:app:server  eyre-id.u.ctx
      (error-json 502 'remote service unavailable')
    =/  resp=client-response:iris  client-response.sign
    ?.  ?=(%finished -.resp)
      :_  this
      %+  give-simple-payload:app:server  eyre-id.u.ctx
      (error-json 502 'incomplete remote response')
    =/  status=@ud  status-code.response-header.resp
    =/  body=@t
      ?~  full-file.resp  ''
      `@t`q.data.u.full-file.resp
    ?:  =(%login kind.u.ctx)
      ?.  &((gte status 200) (lth status 300))
        :_  this
        %+  give-simple-payload:app:server  eyre-id.u.ctx
        (text-payload status body)
      =/  requested-service=@t  ?~(service.u.ctx 'https://bsky.social' u.service.u.ctx)
      =/  parsed=(unit session:atpro)  (parse-session requested-service body)
      ?~  parsed
        :_  this
        %+  give-simple-payload:app:server  eyre-id.u.ctx
        (error-json 502 'invalid session response')
      =.  account  parsed
      :_  this
      %+  give-simple-payload:app:server  eyre-id.u.ctx
      (json-payload 200 (session-json account))
    ?:  =(%refresh kind.u.ctx)
      ?.  &((gte status 200) (lth status 300))
        :_  this
        %+  give-simple-payload:app:server  eyre-id.u.ctx
        (text-payload status body)
      ?~  account
        :_  this
        %+  give-simple-payload:app:server  eyre-id.u.ctx
        (error-json 409 'not connected')
      =/  parsed=(unit session:atpro)  (parse-session service.u.account body)
      ?~  parsed
        :_  this
        %+  give-simple-payload:app:server  eyre-id.u.ctx
        (error-json 502 'invalid refresh response')
      =.  account  parsed
      :_  this
      %+  give-simple-payload:app:server  eyre-id.u.ctx
      (json-payload 200 (session-json account))
    :_  this
    %+  give-simple-payload:app:server  eyre-id.u.ctx
    (text-payload status ?:(=('' body) 'null' body))
  ==
--
