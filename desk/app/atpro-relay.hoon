::  atpro-relay: bounded AT event webhook and Ames/Gall distributor
::
/-  atpro-relay
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
++  strings-at
  |=  [key=@t jon=json]
  ^-  (unit (list @t))
  ?.  ?=(%o -.jon)  ~
  =/  val=(unit json)  (~(get by p.jon) key)
  ?~  val  ~
  ?.  ?=(%a -.u.val)  ~
  =/  strings=(list @t)
    %+  murn  p.u.val
    |=  item=json
    ?.  ?=(%s -.item)  ~
    `p.item
  `strings
::
++  starts-with
  |=  [prefix=@t txt=@t]
  ^-  ?
  =/  p=tape  (trip prefix)
  =/  t=tape  (trip txt)
  ?:  (lth (lent t) (lent p))  %.n
  =(p (scag (lent p) t))
::
++  event-key
  |=  evt=event:atpro-relay
  ^-  @t
  (rap 3 ~[source.evt '|' cursor.evt])
::
++  event-json
  |=  evt=event:atpro-relay
  ^-  json
  %-  pairs:enjs:format
  :~  ['source' s+source.evt]
      ['cursor' s+cursor.evt]
      ['did' s+did.evt]
      ['collection' s+collection.evt]
      ['rkey' s+rkey.evt]
      ['operation' s+operation.evt]
      ['received' s+(scot %da received.evt)]
  ==
::
++  config-json
  |=  [cfg=config:atpro-relay events=(list event:atpro-relay)]
  ^-  json
  =/  upstream-json=json
    ?~  upstream.cfg  ~
    s+(scot %p u.upstream.cfg)
  =/  ships=(list json)
    (turn ~(tap in allowlist.cfg) |=(who=@p s+(scot %p who)))
  %-  pairs:enjs:format
  :~  ['enabled' b+enabled.cfg]
      ['hasToken' b+!=(webhook-token.cfg '')]
      ['upstream' upstream-json]
      ['allowlist' a+ships]
      ['maxEvents' s+(scot %ud max-events.cfg)]
      ['eventCount' s+(scot %ud (lent events))]
      ['hook' s+'/apps/atpro/hook']
  ==
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
  |=  [status=@ud message=@t]
  ^-  simple-payload:http
  (json-payload status (pairs:enjs:format ~[['error' s+message]]))
::
++  parse-event
  |=  [jon=json now=@da]
  ^-  (unit event:atpro-relay)
  =/  source=(unit @t)  (string-at 'source' jon)
  =/  cursor=(unit @t)  (string-at 'cursor' jon)
  =/  did=(unit @t)  (string-at 'did' jon)
  =/  collection=(unit @t)  (string-at 'collection' jon)
  =/  rkey=(unit @t)  (string-at 'rkey' jon)
  =/  operation=(unit @t)  (string-at 'operation' jon)
  ?~  source  ~  ?~  cursor  ~  ?~  did  ~
  ?~  collection  ~  ?~  rkey  ~  ?~  operation  ~
  `[u.source u.cursor u.did u.collection u.rkey u.operation now]
--
::
%-  agent:dbug
=|  state-0:atpro-relay
=*  state  -
^-  agent:gall
|_  =bowl:gall
+*  this  .
    def   ~(. (default-agent this %|) bowl)
::
++  on-init
  ^-  (quip card _this)
  =.  config  [%.n '' ~ *(set @p) 250]
  :_  this
  :~  [%pass /eyre/hook %arvo %e %connect [~ /apps/atpro/hook] dap.bowl]
      [%pass /eyre/admin %arvo %e %connect [~ /apps/atpro/relay] dap.bowl]
  ==
::
++  on-save  !>(state)
::
++  on-load
  |=  old=vase
  ^-  (quip card _this)
  =/  loaded=state-0:atpro-relay  !<(state-0:atpro-relay old)
  =/  cards=(list card)
    :~  [%pass /eyre/hook %arvo %e %connect [~ /apps/atpro/hook] dap.bowl]
        [%pass /eyre/admin %arvo %e %connect [~ /apps/atpro/relay] dap.bowl]
    ==
  =?  cards  ?=(^ upstream.config.loaded)
    (snoc cards [%pass /upstream %agent [u.upstream.config.loaded %atpro-relay] %watch /events])
  [cards this(state loaded)]
::
++  on-poke
  |=  [=mark =vase]
  ^-  (quip card _this)
  |^
  ?+  mark  (on-poke:def mark vase)
      %handle-http-request
    (handle-http !<([@ta inbound-request:eyre] vase))
  ::
      %atpro-relay-action
    ?>  =(our.bowl src.bowl)
    (handle-action !<(action:atpro-relay vase))
  ==
  ::
  ++  ingest
    |=  evt=event:atpro-relay
    ^-  (quip card _this)
    =/  key=@t  (event-key evt)
    ?:  (~(has in seen) key)  `this
    =/  limit=@ud  (min 1.000 (max 1 max-events.config))
    =/  next-events=(list event:atpro-relay)  [evt events]
    =.  events  (scag limit next-events)
    =.  seen
      (~(gas in *(set @t)) (turn events event-key))
    :_  this
    :~  [%give %fact [/events]~ %atpro-event !>(evt)]
    ==
  ::
  ++  upstream-cards
    |=  [old=(unit @p) new=(unit @p)]
    ^-  (list card)
    =/  cards=(list card)  ~
    =?  cards  ?=(^ old)
      (snoc cards [%pass /upstream %agent [u.old %atpro-relay] %leave ~])
    =?  cards  ?=(^ new)
      (snoc cards [%pass /upstream %agent [u.new %atpro-relay] %watch /events])
    cards
  ::
  ++  handle-action
    |=  act=action:atpro-relay
    ^-  (quip card _this)
    ?-  -.act
        %clear
      =.  events  ~
      =.  seen  *(set @t)
      `this
    ::
        %ingest
      (ingest event.act)
    ::
        %configure
      =/  old=(unit @p)  upstream.config
      =.  config  config.act(max-events (min 1.000 (max 1 max-events.config.act)))
      :_  this
      (upstream-cards old upstream.config)
    ==
  ::
  ++  handle-http
    |=  [eyre-id=@ta req=inbound-request:eyre]
    ^-  (quip card _this)
    =/  rl=request-line:server  (parse-request-line:server url.request.req)
    =/  site=(list @t)  site.rl
    ?:  ?=([%apps %atpro %hook ~] site)
      ?.  enabled.config
        :_  this
        (give-simple-payload:app:server eyre-id (error-json 503 'event hook disabled'))
      ?.  ?=(%'POST' method.request.req)
        :_  this
        (give-simple-payload:app:server eyre-id (error-json 405 'method not allowed'))
      =/  authorization=(unit @t)
        (get-header:http 'authorization' header-list.request.req)
      ?.  ?&  !=('' webhook-token.config)
              ?=(^ authorization)
              =((rap 3 ~['Bearer ' webhook-token.config]) u.authorization)
          ==
        :_  this
        (give-simple-payload:app:server eyre-id (error-json 401 'invalid hook token'))
      ?~  body.request.req
        :_  this
        (give-simple-payload:app:server eyre-id (error-json 400 'missing JSON body'))
      =/  jon=(unit json)  (de:json:html q.u.body.request.req)
      ?~  jon
        :_  this
        (give-simple-payload:app:server eyre-id (error-json 400 'invalid JSON body'))
      =/  evt=(unit event:atpro-relay)  (parse-event u.jon now.bowl)
      ?~  evt
        :_  this
        (give-simple-payload:app:server eyre-id (error-json 400 'event fields must be strings'))
      =/  result  (ingest u.evt)
      :_  +.result
      (weld -.result (give-simple-payload:app:server eyre-id (json-payload 202 (event-json u.evt))))
    ?.  ?=([%apps %atpro %relay *] site)
      :_  this
      (give-simple-payload:app:server eyre-id (error-json 404 'not found'))
    ?.  authenticated.req
      :_  this
      (give-simple-payload:app:server eyre-id (login-redirect:gen:server request.req))
    =/  route=(list @t)  t.t.t.site
    ?:  ?&  ?=(%'GET' method.request.req)  ?=([%status ~] route)  ==
      :_  this
      (give-simple-payload:app:server eyre-id (json-payload 200 (config-json config events)))
    ?.  ?=(%'POST' method.request.req)
      :_  this
      (give-simple-payload:app:server eyre-id (error-json 405 'method not allowed'))
    ?:  ?=([%clear ~] route)
      =.  events  ~
      =.  seen  *(set @t)
      :_  this
      (give-simple-payload:app:server eyre-id (json-payload 200 (config-json config events)))
    ?.  ?=([%configure ~] route)
      :_  this
      (give-simple-payload:app:server eyre-id (error-json 404 'not found'))
    ?~  body.request.req
      :_  this
      (give-simple-payload:app:server eyre-id (error-json 400 'missing JSON body'))
    =/  jon=(unit json)  (de:json:html q.u.body.request.req)
    ?~  jon
      :_  this
      (give-simple-payload:app:server eyre-id (error-json 400 'invalid JSON body'))
    =/  enabled=(unit ?)  (bool-at 'enabled' u.jon)
    =/  token=(unit @t)  (string-at 'token' u.jon)
    =/  upstream-text=(unit @t)  (string-at 'upstream' u.jon)
    =/  allow-text=(unit (list @t))  (strings-at 'allowlist' u.jon)
    =/  max-text=(unit @t)  (string-at 'maxEvents' u.jon)
    =/  next-enabled=?  ?~(enabled enabled.config u.enabled)
    =/  next-token=@t  ?~(token webhook-token.config u.token)
    =/  next-upstream=(unit @p)
      ?~  upstream-text  upstream.config
      ?:  =('' u.upstream-text)  ~
      (slaw %p u.upstream-text)
    =/  next-max=@ud
      ?~  max-text  max-events.config
      =/  parsed=(unit @ud)  (slaw %ud u.max-text)
      ?~(parsed max-events.config (min 1.000 (max 1 u.parsed)))
    =/  next-allow=(set @p)
      ?~  allow-text  allowlist.config
      =/  ships=(list @p)
        (murn u.allow-text |=(txt=@t (slaw %p txt)))
      (~(gas in *(set @p)) ships)
    ?:  &(next-enabled =('' next-token))
      :_  this
      (give-simple-payload:app:server eyre-id (error-json 400 'enabled hook requires a token'))
    =/  old-upstream=(unit @p)  upstream.config
    =.  config  [next-enabled next-token next-upstream next-allow next-max]
    :_  this
    (weld (upstream-cards old-upstream next-upstream) (give-simple-payload:app:server eyre-id (json-payload 200 (config-json config events))))
  --
::
++  on-watch
  |=  =path
  ^-  (quip card _this)
  ?+  path  (on-watch:def path)
      [%http-response @ ~]  `this
  ::
      [%events ~]
    ?.  |(=(our.bowl src.bowl) (~(has in allowlist.config) src.bowl))
      ~|(%atpro-relay-not-allowed !!)
    :_  this
    (turn (flop events) |=(evt=event:atpro-relay [%give %fact ~ %atpro-event !>(evt)]))
  ==
::
++  on-peek
  |=  =path
  ^-  (unit (unit cage))
  ?+  path  [~ ~]
      [%x %status ~]  ``json+!>((config-json config events))
  ==
::
++  on-agent
  |=  [=wire sign=sign:agent:gall]
  ^-  (quip card _this)
  ?+  wire  (on-agent:def wire sign)
      [%upstream ~]
    ?+  -.sign  (on-agent:def wire sign)
        %fact
      ?.  =(%atpro-event p.cage.sign)  `this
      =/  evt=event:atpro-relay  !<(event:atpro-relay q.cage.sign)
      =/  key=@t  (event-key evt)
      ?:  (~(has in seen) key)  `this
      =/  limit=@ud  (min 1.000 (max 1 max-events.config))
      =/  next-events=(list event:atpro-relay)  [evt events]
      =.  events  (scag limit next-events)
      =.  seen  (~(gas in *(set @t)) (turn events event-key))
      :_  this
      :~  [%give %fact [/events]~ %atpro-event !>(evt)]
      ==
    ::
        %kick
      ?~  upstream.config  `this
      :_  this
      :~  [%pass /upstream %agent [u.upstream.config %atpro-relay] %watch /events]
      ==
    ::
        %watch-ack
      `this
    ==
  ==
::
++  on-arvo
  |=  [=wire sign=sign-arvo]
  ^-  (quip card _this)
  ?+  wire  (on-arvo:def wire sign)
      [%eyre *]
    ?:  ?=(%bound +<.sign)
      ~?  !accepted.sign  [dap.bowl %binding-rejected binding.sign]
      `this
    `this
  ==
::
++  on-leave  on-leave:def
++  on-fail   on-fail:def
--
