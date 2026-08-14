::  Ship-native single-account AT Protocol PDS through Eyre.
/-  atpro-pds, atpro-repo-types
/+  atpro-oauth, atpro-repo, atpro-repository, atpro-commit, atpro-tid
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
++  json-at
  |=  [key=@t jon=json]
  ^-  (unit json)
  ?.  ?=(%o -.jon)  ~
  (~(get by p.jon) key)
::
++  arg-at
  |=  [key=@t args=(list [key=@t value=@t])]
  ^-  (unit @t)
  |-
  ?~  args  ~
  ?:  =(key key.i.args)  `value.i.args
  $(args t.args)
::
++  json-ipld
  |=  jon=json
  ^-  ipld:atpro-repo-types
  ?-  jon
      [%a *]
    =/  values=(list *)
      %+  turn  p.jon
      |=(child=json (json-ipld child))
    [%list values]
  ::
      [%b *]
    [%bool p.jon]
  ::
      [%n *]
    =/  parsed=(unit @s)  (slaw %si p.jon)
    ?>  ?=(^ parsed)
    [%int u.parsed]
  ::
      [%o *]
    =/  entries=(list [@t *])
      %+  turn  ~(tap by p.jon)
      |=  [key=@t value=json]
      [key (json-ipld value)]
    [%map entries]
  ::
      [%s *]
    [%text p.jon]
  ::
      ~
    [%null ~]
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
++  bytes-payload
  |=  [mime=@t bytes=octs]
  ^-  simple-payload:http
  [[200 ~[['content-type' mime] ['cache-control' 'no-store']]] `bytes]
::
++  error-json
  |=  [status=@ud error=@t message=@t]
  ^-  simple-payload:http
  (json-payload status (pairs:enjs:format ~[['error' s+error] ['message' s+message]]))
::
++  record-json
  |=  [did=@t record=stored-record:atpro-pds]
  ^-  json
  %-  pairs:enjs:format
  :~  ['uri' s+(rap 3 ~['at://' did '/' key.record])]
      ['cid' s+(cid-text:atpro-repo cid.record)]
      ['value' value.record]
  ==
::
++  make-stored
  |=  [collection=@t rkey=@t value=json]
  ^-  stored-record:atpro-pds
  =/  key=@t  (rap 3 ~[collection '/' rkey])
  =/  ipld=ipld:atpro-repo-types  (json-ipld value)
  =/  block=octs  (encode:atpro-repo ipld)
  =/  cid=cid:atpro-repo-types  (cid-for-cbor:atpro-repo block)
  [key collection rkey cid block value]
::
++  apply-write
  |=  [write=json records=(map @t stored-record:atpro-pds)]
  ^-  (unit (map @t stored-record:atpro-pds))
  =/  action=(unit @t)  (string-at '$type' write)
  =/  collection=(unit @t)  (string-at 'collection' write)
  =/  rkey=(unit @t)  (string-at 'rkey' write)
  ?.  ?&(?=(^ action) ?=(^ collection) ?=(^ rkey))  ~
  =/  key=@t  (rap 3 ~[u.collection '/' u.rkey])
  =/  exists=?  (~(has by records) key)
  ?:  =('com.atproto.repo.applyWrites#delete' u.action)
    ?.  exists  ~
    `(~(del by records) key)
  =/  create=?  =('com.atproto.repo.applyWrites#create' u.action)
  =/  update=?  =('com.atproto.repo.applyWrites#update' u.action)
  ?.  |(create update)  ~
  ?:  &(create exists)  ~
  ?:  &(update !exists)  ~
  =/  value=(unit json)  (json-at 'value' write)
  ?~  value  ~
  =/  stored=stored-record:atpro-pds  (make-stored u.collection u.rkey u.value)
  `(~(put by records) key stored)
::
++  config-json
  |=  $:  config=pds-config:atpro-pds
          records=@ud
          head=(unit cid:atpro-repo-types)
          rev=(unit @t)
          sequence=@ud
      ==
  ^-  json
  %-  pairs:enjs:format
  :~  ['enabled' b+enabled.config]
      ['origin' s+origin.config]
      ['did' s+did.config]
      ['handle' s+handle.config]
      ['signingKey' s+(did-key:atpro-commit private-key.config)]
      ['records' n+(scot %ud records)]
      ['head' ?~(head ~+(~) s+(cid-text:atpro-repo u.head))]
      ['rev' ?~(rev ~+(~) s+u.rev)]
      ['sequence' n+(scot %ud sequence)]
  ==
--
::
%-  agent:dbug
=|  state-0:atpro-pds
=*  state  -
^-  agent:gall
|_  =bowl:gall
+*  this  .
    def   ~(. (default-agent this %|) bowl)
::
++  on-init
  ^-  (quip card _this)
  =/  key=@  (make-private-key:atpro-oauth (shas %atpro-pds-key eny.bowl))
  =.  state  [%0 [%.n '' '' '' key (mod eny.bowl 32)] *(map @t stored-record:atpro-pds) ~ ~ ~ ~ [0 0] 0 ~]
  :_  this
  :~  [%pass /eyre/xrpc %arvo %e %connect [~ /xrpc] dap.bowl]
      [%pass /eyre/admin %arvo %e %connect [~ /apps/atpro/pds] dap.bowl]
  ==
::
++  on-save  !>(state)
::
++  on-load
  |=  old=vase
  ^-  (quip card _this)
  =/  loaded=state-0:atpro-pds  !<(state-0:atpro-pds old)
  :_  this(state loaded)
  :~  [%pass /eyre/xrpc %arvo %e %connect [~ /xrpc] dap.bowl]
      [%pass /eyre/admin %arvo %e %connect [~ /apps/atpro/pds] dap.bowl]
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
  ++  reply
    |=  [eyre-id=@ta payload=simple-payload:http]
    ^-  (quip card _this)
    [(give-simple-payload:app:server eyre-id payload) this]
  ::
  ++  parse-body
    |=  req=inbound-request:eyre
    ^-  (unit json)
    ?~  body.request.req  ~
    (de:json:html q.u.body.request.req)
  ::
  ++  rebuild
    |=  [operation=@tas changed-key=@t]
    ^-  _this
    =/  next-tid=[tid=@t timestamp=@ud]
      (next:atpro-tid now.bowl last-timestamp clock.config)
    =/  values=(list record-value:atpro-repo-types)
      %+  turn  ~(tap by records)
      |=  [map-key=@t record=stored-record:atpro-pds]
      [map-key (json-ipld value.record)]
    =/  snap=repo-snapshot:atpro-repo-types
      (snapshot:atpro-repository did.config tid.next-tid head values private-key.config)
    =.  head  `head.snap
    =.  rev  `rev.snap
    =.  last-timestamp  `timestamp.next-tid
    =.  blocks  blocks.snap
    =.  car  car.snap
    =.  sequence  +(sequence)
    =.  events  [[sequence rev.snap head.snap operation changed-key] events]
    this
  ::
  ++  write-result
    |=  record=stored-record:atpro-pds
    ^-  json
    =/  commit=json
      (pairs:enjs:format ~[['cid' s+(cid-text:atpro-repo (need head))] ['rev' s+(need rev)]])
    %-  pairs:enjs:format
    :~  ['uri' s+(rap 3 ~['at://' did.config '/' key.record])]
        ['cid' s+(cid-text:atpro-repo cid.record)]
        ['commit' commit]
        ['validationStatus' s+'valid']
    ==
  ::
  ++  put-record
    |=  [eyre-id=@ta jon=json create-only=?]
    ^-  (quip card _this)
    =/  collection=(unit @t)  (string-at 'collection' jon)
    =/  repo=(unit @t)  (string-at 'repo' jon)
    =/  value=(unit json)  (json-at 'record' jon)
    ?.  ?&  ?=(^ repo)
            ?|(=(u.repo did.config) =(u.repo handle.config))
        ==
      (reply eyre-id (error-json 400 'InvalidRequest' 'repo does not match this account'))
    ?~  collection  (reply eyre-id (error-json 400 'InvalidRequest' 'missing collection'))
    ?~  value  (reply eyre-id (error-json 400 'InvalidRequest' 'missing record'))
    =/  requested=(unit @t)  (string-at 'rkey' jon)
    =/  generated=[tid=@t timestamp=@ud]
      (next:atpro-tid now.bowl last-timestamp clock.config)
    =/  rkey=@t  ?~(requested tid.generated u.requested)
    =/  key=@t  (rap 3 ~[u.collection '/' rkey])
    =/  existing=(unit stored-record:atpro-pds)  (~(get by records) key)
    ?:  &(create-only ?=(^ existing))
      (reply eyre-id (error-json 400 'RecordAlreadyExists' 'record already exists'))
    =/  stored=stored-record:atpro-pds  (make-stored u.collection rkey u.value)
    =.  records  (~(put by records) key stored)
    =.  this  (rebuild ?:(?=(^ existing) %update %create) key)
    (reply eyre-id (json-payload 200 (write-result stored)))
  ::
  ++  handle-http
    |=  [eyre-id=@ta req=inbound-request:eyre]
    ^-  (quip card _this)
    =/  rl=request-line:server  (parse-request-line:server url.request.req)
    =/  site=(list @t)  site.rl
    ?~  site  (reply eyre-id (error-json 404 'NotFound' 'not found'))
    ?:  =('apps' i.site)
      ?.  ?=([%apps %atpro %pds *] site)
        (reply eyre-id (error-json 404 'NotFound' 'not found'))
      ?.  authenticated.req
        (reply eyre-id (login-redirect:gen:server request.req))
      ?:  ?&  ?=(%'GET' method.request.req)
              ?=([%status ~] t.t.t.site)
          ==
        (reply eyre-id (json-payload 200 (config-json config (lent ~(tap by records)) head rev sequence)))
      ?.  ?&  ?=(%'POST' method.request.req)
              ?=([%configure ~] t.t.t.site)
          ==
        (reply eyre-id (error-json 404 'NotFound' 'not found'))
      =/  jon=(unit json)  (parse-body req)
      ?~  jon  (reply eyre-id (error-json 400 'InvalidRequest' 'invalid JSON body'))
      =/  enabled=(unit ?)  (bool-at 'enabled' u.jon)
      =/  origin=(unit @t)  (string-at 'origin' u.jon)
      =/  did=(unit @t)  (string-at 'did' u.jon)
      =/  handle=(unit @t)  (string-at 'handle' u.jon)
      ?~  enabled  (reply eyre-id (error-json 400 'InvalidRequest' 'missing enabled'))
      ?~  origin  (reply eyre-id (error-json 400 'InvalidRequest' 'missing origin'))
      ?~  did  (reply eyre-id (error-json 400 'InvalidRequest' 'missing did'))
      ?~  handle  (reply eyre-id (error-json 400 'InvalidRequest' 'missing handle'))
      =.  config  [u.enabled u.origin u.did u.handle private-key.config clock.config]
      =?  this  &(u.enabled ?=(~ head))  (rebuild %init '')
      (reply eyre-id (json-payload 200 (config-json config (lent ~(tap by records)) head rev sequence)))
    ?.  enabled.config
      (reply eyre-id (error-json 503 'ServiceUnavailable' 'PDS is disabled'))
    ?.  =('xrpc' i.site)
      (reply eyre-id (error-json 404 'NotFound' 'not found'))
    ?~  t.site  (reply eyre-id (error-json 404 'XRPCNotSupported' 'missing method'))
    =/  method=@t  i.t.site
    ?:  =('com.atproto.repo.describeRepo' method)
      =/  collections=(list json)
        %+  turn  ~(tap by records)
        |=  [key=@t record=stored-record:atpro-pds]
        s+collection.record
      =/  jon=json
        %-  pairs:enjs:format
        :~  ['handle' s+handle.config]
            ['did' s+did.config]
            ['didDoc' ~+(~)]
            ['collections' a+collections]
            ['handleIsCorrect' b+%.y]
        ==
      (reply eyre-id (json-payload 200 jon))
    ?:  =('com.atproto.repo.getRecord' method)
      =/  collection=(unit @t)  (arg-at 'collection' args.rl)
      =/  rkey=(unit @t)  (arg-at 'rkey' args.rl)
      ?.  ?&(?=(^ collection) ?=(^ rkey))
        (reply eyre-id (error-json 400 'InvalidRequest' 'missing collection or rkey'))
      =/  found=(unit stored-record:atpro-pds)
        (~(get by records) (rap 3 ~[u.collection '/' u.rkey]))
      ?~  found  (reply eyre-id (error-json 400 'RecordNotFound' 'record not found'))
      (reply eyre-id (json-payload 200 (record-json did.config u.found)))
    ?:  =('com.atproto.repo.listRecords' method)
      =/  collection=(unit @t)  (arg-at 'collection' args.rl)
      ?~  collection
        (reply eyre-id (error-json 400 'InvalidRequest' 'missing collection'))
      =/  matching=(list stored-record:atpro-pds)
        %+  turn
          %+  skim  ~(tap by records)
          |=  [key=@t record=stored-record:atpro-pds]
          =(collection.record u.collection)
        |=  [key=@t record=stored-record:atpro-pds]
        record
      =/  asked-limit=(unit @ud)
        =/  raw=(unit @t)  (arg-at 'limit' args.rl)
        ?~(raw ~ (slaw %ud u.raw))
      =/  limit=@ud  ?~(asked-limit 50 (min 100 (max 1 u.asked-limit)))
      =/  asked-offset=(unit @ud)
        =/  raw=(unit @t)  (arg-at 'cursor' args.rl)
        ?~(raw ~ (slaw %ud u.raw))
      =/  offset=@ud  ?~(asked-offset 0 u.asked-offset)
      =/  remaining=(list stored-record:atpro-pds)  (slag offset matching)
      =/  page=(list stored-record:atpro-pds)  (scag limit remaining)
      =/  fields=(list [@t json])
        ~[['records' a+(turn page |=(record=stored-record:atpro-pds (record-json did.config record)))]]
      =?  fields  (gth (lent remaining) limit)
        (snoc fields ['cursor' s+(scot %ud (add offset limit))])
      (reply eyre-id (json-payload 200 (pairs:enjs:format fields)))
    ?:  =('com.atproto.sync.getLatestCommit' method)
      =/  jon=json
        (pairs:enjs:format ~[['cid' s+(cid-text:atpro-repo (need head))] ['rev' s+(need rev)]])
      (reply eyre-id (json-payload 200 jon))
    ?:  =('com.atproto.sync.getRepo' method)
      (reply eyre-id (bytes-payload 'application/vnd.ipld.car' car))
    ?:  =('com.atproto.sync.getBlocks' method)
      =/  requested=(list @t)
        %+  turn
          %+  skim  args.rl
          |=  [key=@t value=@t]
          =(key 'cids')
        |=  [key=@t value=@t]
        value
      ?:  =(~ requested)
        (reply eyre-id (error-json 400 'InvalidRequest' 'missing cids'))
      =/  selected=(list block:atpro-repo-types)
        %+  skim  blocks
        |=  block=block:atpro-repo-types
        %+  lien  requested
        |=  requested-cid=@t
        =(requested-cid (cid-text:atpro-repo cid.block))
      ?.  =((lent requested) (lent selected))
        (reply eyre-id (error-json 400 'InvalidRequest' 'one or more blocks are unavailable'))
      (reply eyre-id (bytes-payload 'application/vnd.ipld.car' (car-v1-roots:atpro-repo ~ selected)))
    ?.  ?=(%'POST' method.request.req)
      (reply eyre-id (error-json 404 'XRPCNotSupported' 'method not supported'))
    ?.  authenticated.req
      (reply eyre-id (error-json 401 'AuthenticationRequired' 'write authentication required'))
    =/  jon=(unit json)  (parse-body req)
    ?~  jon  (reply eyre-id (error-json 400 'InvalidRequest' 'invalid JSON body'))
    ?:  =('com.atproto.repo.createRecord' method)
      (put-record eyre-id u.jon %.y)
    ?:  =('com.atproto.repo.putRecord' method)
      (put-record eyre-id u.jon %.n)
    ?:  =('com.atproto.repo.deleteRecord' method)
      =/  repo=(unit @t)  (string-at 'repo' u.jon)
      =/  collection=(unit @t)  (string-at 'collection' u.jon)
      =/  rkey=(unit @t)  (string-at 'rkey' u.jon)
      ?.  ?&  ?=(^ repo)
              ?|(=(u.repo did.config) =(u.repo handle.config))
              ?=(^ collection)
              ?=(^ rkey)
          ==
        (reply eyre-id (error-json 400 'InvalidRequest' 'invalid repo, collection, or rkey'))
      =/  key=@t  (rap 3 ~[u.collection '/' u.rkey])
      ?.  (~(has by records) key)
        (reply eyre-id (error-json 400 'RecordNotFound' 'record not found'))
      =.  records  (~(del by records) key)
      =.  this  (rebuild %delete key)
      =/  commit=json
        (pairs:enjs:format ~[['cid' s+(cid-text:atpro-repo (need head))] ['rev' s+(need rev)]])
      (reply eyre-id (json-payload 200 (pairs:enjs:format ~[['commit' commit]])))
    ?:  =('com.atproto.repo.applyWrites' method)
      =/  repo=(unit @t)  (string-at 'repo' u.jon)
      =/  writes=(unit json)  (json-at 'writes' u.jon)
      ?.  ?&  ?=(^ repo)
              ?|(=(u.repo did.config) =(u.repo handle.config))
              ?=(^ writes)
              ?=(%a -.u.writes)
          ==
        (reply eyre-id (error-json 400 'InvalidRequest' 'invalid repo or writes'))
      =/  items=(list json)  p.u.writes
      ?:  (gth (lent items) 200)
        (reply eyre-id (error-json 400 'InvalidRequest' 'too many writes'))
      =/  working=(map @t stored-record:atpro-pds)  records
      |-
      ?~  items
        =.  records  working
        =.  this  (rebuild %apply '')
        =/  commit=json
          (pairs:enjs:format ~[['cid' s+(cid-text:atpro-repo (need head))] ['rev' s+(need rev)]])
        (reply eyre-id (json-payload 200 (pairs:enjs:format ~[['commit' commit] ['results' a+~]])))
      =/  next=(unit (map @t stored-record:atpro-pds))  (apply-write i.items working)
      ?~  next
        (reply eyre-id (error-json 400 'InvalidRequest' 'invalid write operation'))
      $(items t.items, working u.next)
    (reply eyre-id (error-json 404 'XRPCNotSupported' 'method not supported'))
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
    ``json+!>((config-json config (lent ~(tap by records)) head rev sequence))
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
