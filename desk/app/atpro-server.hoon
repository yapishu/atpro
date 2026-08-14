::  atpro-server: small AT Feed Generator served through Eyre
::
/-  atpro-server
/+  dbug, default-agent, server
|%
+$  card  card:agent:gall
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
++  bool-at
  |=  [key=@t jon=json]
  ^-  (unit ?)
  ?.  ?=(%o -.jon)  ~
  =/  val=(unit json)  (~(get by p.jon) key)
  ?~  val  ~
  ?.  ?=(%b -.u.val)  ~
  `p.u.val
::
++  arg-at
  |=  [key=@t args=(list [key=@t value=@t])]
  ^-  (unit @t)
  |-
  ?~  args  ~
  ?:  =(key key.i.args)  `value.i.args
  $(args t.args)
::
++  starts-with
  |=  [prefix=@t txt=@t]
  ^-  ?
  =/  p=tape  (trip prefix)
  =/  t=tape  (trip txt)
  ?:  (lth (lent t) (lent p))  %.n
  =(p (scag (lent p) t))
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
++  error-json
  |=  [status=@ud error=@t message=@t]
  ^-  simple-payload:http
  (json-payload status (pairs:enjs:format ~[['error' s+error] ['message' s+message]]))
::
++  config-json
  |=  [config=server-config:atpro-server posts=(list @t)]
  ^-  json
  %-  pairs:enjs:format
  :~  ['enabled' b+enabled.config]
      ['did' s+service-did.config]
      ['endpoint' s+endpoint.config]
      ['feedUri' s+feed-uri.config]
      ['posts' a+(turn posts |=(post=@t s+post))]
  ==
::
++  did-json
  |=  config=server-config:atpro-server
  ^-  json
  =/  service=json
    %-  pairs:enjs:format
    :~  ['id' s+(rap 3 ~[service-did.config '#bsky_fg'])]
        ['type' s+'BskyFeedGenerator']
        ['serviceEndpoint' s+endpoint.config]
    ==
  %-  pairs:enjs:format
  :~  ['@context' a+~[s+'https://www.w3.org/ns/did/v1']]
      ['id' s+service-did.config]
      ['service' a+~[service]]
  ==
::
++  describe-json
  |=  config=server-config:atpro-server
  ^-  json
  =/  feed=json  (pairs:enjs:format ~[['uri' s+feed-uri.config]])
  (pairs:enjs:format ~[['did' s+service-did.config] ['feeds' a+~[feed]]])
::
++  skeleton-json
  |=  [posts=(list @t) limit=@ud offset=@ud]
  ^-  json
  =/  remaining=(list @t)  (slag offset posts)
  =/  page=(list @t)  (scag limit remaining)
  =/  items=(list json)
    %+  turn  page
    |=  post=@t
    (pairs:enjs:format ~[['post' s+post]])
  =/  fields=(list [@t json])  ~[['feed' a+items]]
  =?  fields  (gth (lent remaining) limit)
    [['cursor' s+(scot %ud (add offset limit))] fields]
  (pairs:enjs:format fields)
::
++  did-cache-card
  |=  config=server-config:atpro-server
  ^-  card
  =/  entry=(unit cache-entry:eyre)
    ?.  enabled.config  ~
    `[%.n %payload (json-payload 200 (did-json config))]
  [%pass /eyre/did-cache %arvo %e %set-response '/.well-known/did.json' entry]
--
::
%-  agent:dbug
=|  state-0:atpro-server
=*  state  -
^-  agent:gall
|_  =bowl:gall
+*  this  .
    def   ~(. (default-agent this %|) bowl)
::
++  on-init
  ^-  (quip card _this)
  =.  config  [%.n '' '' '']
  :_  this
  :~  [%pass /eyre/well-known %arvo %e %disconnect [~ ~['.well-known' 'did.json']]]
      [%pass /eyre/xrpc %arvo %e %connect [~ /xrpc] dap.bowl]
      [%pass /eyre/admin %arvo %e %connect [~ /apps/atpro/server] dap.bowl]
      (did-cache-card config)
  ==
::
++  on-save
  ^-  vase
  !>(state)
::
++  on-load
  |=  old=vase
  ^-  (quip card _this)
  =/  loaded=state-0:atpro-server  !<(state-0:atpro-server old)
  :_  this(state loaded)
  :~  [%pass /eyre/well-known %arvo %e %disconnect [~ ~['.well-known' 'did.json']]]
      [%pass /eyre/xrpc %arvo %e %connect [~ /xrpc] dap.bowl]
      [%pass /eyre/admin %arvo %e %connect [~ /apps/atpro/server] dap.bowl]
      (did-cache-card config.loaded)
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
  ++  handle-http
    |=  [eyre-id=@ta req=inbound-request:eyre]
    ^-  (quip card _this)
    =/  rl=request-line:server  (parse-request-line:server url.request.req)
    =/  site=(list @t)  site.rl
    ?~  site
      :_  this
      (give-simple-payload:app:server eyre-id (error-json 404 'NotFound' 'not found'))
    ::
    ?:  =('apps' i.site)
      ?.  ?=([%apps %atpro %server *] site)
        :_  this
        (give-simple-payload:app:server eyre-id (error-json 404 'NotFound' 'not found'))
      ?.  authenticated.req
        :_  this
        (give-simple-payload:app:server eyre-id (login-redirect:gen:server request.req))
      =/  route=(list @t)  t.t.t.site
      ?:  ?&  ?=(%'GET' method.request.req)
              ?=([%status ~] route)
          ==
        :_  this
        (give-simple-payload:app:server eyre-id (json-payload 200 (config-json config posts)))
      ?.  ?=(%'POST' method.request.req)
        :_  this
        (give-simple-payload:app:server eyre-id (error-json 405 'MethodNotAllowed' 'method not allowed'))
      ?~  body.request.req
        :_  this
        (give-simple-payload:app:server eyre-id (error-json 400 'InvalidRequest' 'missing JSON body'))
      =/  jon=(unit json)  (de:json:html q.u.body.request.req)
      ?~  jon
        :_  this
        (give-simple-payload:app:server eyre-id (error-json 400 'InvalidRequest' 'invalid JSON body'))
      ?:  ?=([%configure ~] route)
        =/  enabled=(unit ?)  (bool-at 'enabled' u.jon)
        =/  did=(unit @t)  (string-at 'did' u.jon)
        =/  endpoint=(unit @t)  (string-at 'endpoint' u.jon)
        =/  feed=(unit @t)  (string-at 'feedUri' u.jon)
        ?~  enabled  (admin-error eyre-id 400 'missing enabled')
        ?~  did  (admin-error eyre-id 400 'missing did')
        ?~  endpoint  (admin-error eyre-id 400 'missing endpoint')
        ?~  feed  (admin-error eyre-id 400 'missing feedUri')
        ?.  ?|  !u.enabled
                ?&  (starts-with 'did:web:' u.did)
                    (starts-with 'https://' u.endpoint)
                    (starts-with 'at://' u.feed)
                ==
            ==
          (admin-error eyre-id 400 'enabled service needs did:web, HTTPS endpoint, and AT feed URI')
        =.  config  [u.enabled u.did u.endpoint u.feed]
        :_  this
        %+  weld
          (give-simple-payload:app:server eyre-id (json-payload 200 (config-json config posts)))
        ~[(did-cache-card config)]
      ?:  ?=([%add-post ~] route)
        =/  post=(unit @t)  (string-at 'post' u.jon)
        ?~  post  (admin-error eyre-id 400 'missing post')
        ?.  (starts-with 'at://' u.post)  (admin-error eyre-id 400 'post must be an AT URI')
        =.  posts  [u.post (skip posts |=(item=@t =(item u.post)))]
        :_  this
        (give-simple-payload:app:server eyre-id (json-payload 200 (config-json config posts)))
      ?:  ?=([%remove-post ~] route)
        =/  post=(unit @t)  (string-at 'post' u.jon)
        ?~  post  (admin-error eyre-id 400 'missing post')
        =.  posts  (skip posts |=(item=@t =(item u.post)))
        :_  this
        (give-simple-payload:app:server eyre-id (json-payload 200 (config-json config posts)))
      (admin-error eyre-id 404 'not found')
    ::
    ?.  enabled.config
      :_  this
      (give-simple-payload:app:server eyre-id (error-json 503 'ServiceUnavailable' 'feed generator is disabled'))
    ?.  =('xrpc' i.site)
      :_  this
      (give-simple-payload:app:server eyre-id (error-json 404 'NotFound' 'not found'))
    ?.  ?=(%'GET' method.request.req)
      :_  this
      (give-simple-payload:app:server eyre-id (error-json 405 'MethodNotAllowed' 'method not allowed'))
    ?~  t.site
      :_  this
      (give-simple-payload:app:server eyre-id (error-json 404 'NotFound' 'missing XRPC method'))
    =/  method=@t  i.t.site
    ?:  =('app.bsky.feed.describeFeedGenerator' method)
      :_  this
      (give-simple-payload:app:server eyre-id (json-payload 200 (describe-json config)))
    ?:  =('app.bsky.feed.getFeedSkeleton' method)
      =/  requested=(unit @t)  (arg-at 'feed' args.rl)
      ?.  ?&  ?=(^ requested)
              =(u.requested feed-uri.config)
          ==
        :_  this
        (give-simple-payload:app:server eyre-id (error-json 400 'UnknownFeed' 'unknown feed'))
      =/  asked-limit=(unit @ud)
        =/  raw=(unit @t)  (arg-at 'limit' args.rl)
        ?~(raw ~ (slaw %ud u.raw))
      =/  limit=@ud  ?~(asked-limit 50 (min 100 (max 1 u.asked-limit)))
      =/  asked-offset=(unit @ud)
        =/  raw=(unit @t)  (arg-at 'cursor' args.rl)
        ?~(raw ~ (slaw %ud u.raw))
      =/  offset=@ud  ?~(asked-offset 0 u.asked-offset)
      :_  this
      (give-simple-payload:app:server eyre-id (json-payload 200 (skeleton-json posts limit offset)))
    :_  this
    (give-simple-payload:app:server eyre-id (error-json 404 'XRPCNotSupported' 'method not supported'))
  ::
  ++  admin-error
    |=  [eyre-id=@ta status=@ud message=@t]
    ^-  (quip card _this)
    :_  this
    (give-simple-payload:app:server eyre-id (error-json status 'InvalidRequest' message))
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
      [%x %status ~]  ``json+!>((config-json config posts))
  ==
::
++  on-leave  on-leave:def
++  on-agent  on-agent:def
++  on-arvo
  |=  [=wire sign=sign-arvo]
  ^-  (quip card _this)
  ?+  wire  (on-arvo:def wire sign)
      [%eyre *]
    ?:  ?=(%bound +<.sign)
      ~?  !accepted.sign  [dap.bowl %binding-rejected binding.sign]
      [~ this]
    [~ this]
  ==
::
++  on-fail  on-fail:def
--
