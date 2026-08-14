::  Ship-native single-account AT Protocol PDS through Eyre.
/-  atpro-pds, atpro-repo-types
/+  atpro-oauth, atpro-repo, atpro-repository, atpro-commit, atpro-tid
/+  atpro-s3, atpro-session, dbug, default-agent, server
|%
+$  card  card:agent:gall
+$  blob-request
  $%  [%put eyre-id=@ta blob=stored-blob:atpro-pds]
      [%get eyre-id=@ta blob=stored-blob:atpro-pds]
  ==
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
++  starts-with
  |=  [prefix=@t value=@t]
  ^-  ?
  =/  pre=tape  (trip prefix)
  =/  val=tape  (trip value)
  ?:  (gth (lent pre) (lent val))  %.n
  =(pre (scag (lent pre) val))
::
++  bearer-token
  |=  headers=header-list:http
  ^-  (unit @t)
  =/  authorization=(unit @t)  (get-header:http 'authorization' headers)
  ?~  authorization  ~
  ?.  (starts-with 'Bearer ' u.authorization)  ~
  `(crip (slag 7 (trip u.authorization)))
::
++  find-access
  |=  [token=@t sessions=(map @t pds-session:atpro-pds) now=@ud]
  ^-  (unit [id=@t session=pds-session:atpro-pds])
  =/  entries=(list [id=@t session=pds-session:atpro-pds])
    ~(tap by sessions)
  |-
  ?~  entries  ~
  ?:  ?&  =(token access-jwt.session.i.entries)
          (gth access-expires.session.i.entries now)
      ==
    `i.entries
  $(entries t.entries)
::
++  find-refresh
  |=  [token=@t sessions=(map @t pds-session:atpro-pds) now=@ud]
  ^-  (unit [id=@t session=pds-session:atpro-pds])
  =/  entries=(list [id=@t session=pds-session:atpro-pds])
    ~(tap by sessions)
  |-
  ?~  entries  ~
  ?:  ?&  =(token refresh-jwt.session.i.entries)
          (gth refresh-expires.session.i.entries now)
      ==
    `i.entries
  $(entries t.entries)
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
++  blob-json
  |=  blob=stored-blob:atpro-pds
  ^-  json
  =/  ref=json
    (frond:enjs:format '$link' s+(cid-text:atpro-repo cid.blob))
  %-  pairs:enjs:format
  :~  ['$type' s+'blob']
      ['ref' ref]
      ['mimeType' s+mime.blob]
      ['size' n+(scot %ud size.blob)]
  ==
::
++  storage-settings
  |=  [our=@p now=@da]
  ^-  (unit [credentials=credentials:atpro-s3 configuration=configuration:atpro-s3])
  =/  found-credentials=(unit json)
    %-  mole
    |.(.^(json %gx /(scot %p our)/storage/(scot %da now)/credentials/json))
  ?~  found-credentials  ~
  =/  found-configuration=(unit json)
    %-  mole
    |.(.^(json %gx /(scot %p our)/storage/(scot %da now)/configuration/json))
  ?~  found-configuration  ~
  =/  get-string
    |=  [jon=json keys=(list @t)]
    ^-  @t
    ?~  keys  ?:(?=([%s *] jon) p.jon '')
    ?.  ?=([%o *] jon)  ''
    =/  value=(unit json)  (~(get by p.jon) i.keys)
    ?~  value  ''
    $(jon u.value, keys t.keys)
  =/  credentials=credentials:atpro-s3
    :*  (get-string u.found-credentials ~['storage-update' 'credentials' 'endpoint'])
        (get-string u.found-credentials ~['storage-update' 'credentials' 'accessKeyId'])
        (get-string u.found-credentials ~['storage-update' 'credentials' 'secretAccessKey'])
    ==
  =/  configuration=configuration:atpro-s3
    :*  (get-string u.found-configuration ~['storage-update' 'configuration' 'currentBucket'])
        (get-string u.found-configuration ~['storage-update' 'configuration' 'region'])
    ==
  =/  service=@t
    (get-string u.found-configuration ~['storage-update' 'configuration' 'service'])
  ?.  =('credentials' service)  ~
  ?.  ?&  !=('' access-key-id.credentials)
          !=('' secret-access-key.credentials)
          !=('' endpoint.credentials)
          !=('' current-bucket.configuration)
          !=('' region.configuration)
      ==
    ~
  `[credentials configuration]
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
++  commit-swap-ok
  |=  [jon=json head=(unit cid:atpro-repo-types)]
  ^-  ?
  =/  swap=(unit @t)  (string-at 'swapCommit' jon)
  ?~  swap  %.y
  ?~  head  %.n
  =(u.swap (cid-text:atpro-repo u.head))
::
++  record-swap-ok
  |=  [jon=json record=(unit stored-record:atpro-pds)]
  ^-  ?
  =/  swap=(unit json)  (json-at 'swapRecord' jon)
  ?~  swap  %.y
  ?:  =(~ u.swap)
    ?=(~ record)
  ?.  ?=(%s -.u.swap)  %.n
  ?~  record  %.n
  =(p.u.swap (cid-text:atpro-repo cid.u.record))
::
++  find-block
  |=  [text=@t blocks=(list block:atpro-repo-types)]
  ^-  (unit block:atpro-repo-types)
  |-
  ?~  blocks  ~
  ?:  =(text (cid-text:atpro-repo cid.i.blocks))
    `i.blocks
  $(blocks t.blocks)
::
++  make-session
  |=  $:  config=pds-config:atpro-pds
          auth=pds-auth:atpro-pds
          now=@ud
          entropy=@
      ==
  ^-  pds-session:atpro-pds
  =/  id=@t  (token:atpro-oauth (shas %atpro-pds-session-id entropy))
  =/  access-id=@t
    (token:atpro-oauth (shas %atpro-pds-access-id entropy))
  =/  access-expires=@ud  (add now 7.200)
  =/  refresh-expires=@ud  (add now 7.776.000)
  =/  access=@t
    %-  session-jwt:atpro-session
    :*  'at+jwt'
        'com.atproto.access'
        did.config
        service-did.config
        access-id
        now
        access-expires
        jwt-key.auth
    ==
  =/  refresh=@t
    %-  session-jwt:atpro-session
    :*  'refresh+jwt'
        'com.atproto.refresh'
        did.config
        service-did.config
        id
        now
        refresh-expires
        jwt-key.auth
    ==
  [id access refresh access-expires refresh-expires]
::
++  session-json
  |=  [config=pds-config:atpro-pds session=pds-session:atpro-pds]
  ^-  json
  %-  pairs:enjs:format
  :~  ['accessJwt' s+access-jwt.session]
      ['refreshJwt' s+refresh-jwt.session]
      ['handle' s+handle.config]
      ['did' s+did.config]
      ['active' b+%.y]
  ==
::
++  account-json
  |=  config=pds-config:atpro-pds
  ^-  json
  %-  pairs:enjs:format
  :~  ['handle' s+handle.config]
      ['did' s+did.config]
      ['active' b+%.y]
  ==
::
++  config-json
  |=  $:  config=pds-config:atpro-pds
          auth=pds-auth:atpro-pds
          sessions=@ud
          records=@ud
          blobs=@ud
          head=(unit cid:atpro-repo-types)
          rev=(unit @t)
          sequence=@ud
          history=@ud
      ==
  ^-  json
  %-  pairs:enjs:format
  :~  ['enabled' b+enabled.config]
      ['origin' s+origin.config]
      ['serviceDid' s+service-did.config]
      ['did' s+did.config]
      ['handle' s+handle.config]
      ['appPasswordConfigured' b+?=(^ password-hash.auth)]
      ['sessions' n+(scot %ud sessions)]
      ['signingKey' s+(did-key:atpro-commit private-key.config)]
      ['records' n+(scot %ud records)]
      ['blobs' n+(scot %ud blobs)]
      ['head' ?~(head ~+(~) s+(cid-text:atpro-repo u.head))]
      ['rev' ?~(rev ~+(~) s+u.rev)]
      ['sequence' n+(scot %ud sequence)]
      ['history' n+(scot %ud history)]
  ==
--
::
%-  agent:dbug
=|  state-0:atpro-pds
=*  state  -
=/  in-flight  *(map @uv blob-request)
=/  request-count=@ud  0
^-  agent:gall
|_  =bowl:gall
+*  this  .
    def   ~(. (default-agent this %|) bowl)
::
++  on-init
  ^-  (quip card _this)
  =/  key=@  (make-private-key:atpro-oauth (shas %atpro-pds-key eny.bowl))
  =/  salt=@  (shas %atpro-pds-password-salt eny.bowl)
  =/  jwt-key=@  (shas %atpro-pds-jwt-key eny.bowl)
  =.  state
    :*  %0
        [%.n '' '' '' '' key (mod eny.bowl 32)]
        [salt ~ jwt-key]
        *(map @t pds-session:atpro-pds)
        0
        *(map @t stored-record:atpro-pds)
        *(map @t stored-blob:atpro-pds)
        ~  ~  ~  ~  [0 0]  ~  0  ~
    ==
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
  :_  this(state loaded, in-flight ~, request-count 0)
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
  ++  queue-blob
    |=  [context=blob-request request=request:http]
    ^-  (quip card _this)
    =/  request-id=@uv
      `@uv`(shas %atpro-pds-request (cat 3 eny.bowl request-count))
    =.  request-count  +(request-count)
    =.  in-flight  (~(put by in-flight) request-id context)
    :_  this
    :~  [%pass /iris/(scot %uv request-id) %arvo %i %request request *outbound-config:iris]
    ==
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
    =/  since=(unit @t)  rev
    =.  head  `head.snap
    =.  rev  `rev.snap
    =.  last-timestamp  `timestamp.next-tid
    =.  blocks  blocks.snap
    =.  car  car.snap
    =.  sequence  +(sequence)
    =.  history  [[head.snap rev.snap since blocks.snap car.snap sequence] history]
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
    ?.  (commit-swap-ok jon head)
      (reply eyre-id (error-json 400 'InvalidSwap' 'swapCommit does not match the current commit'))
    ?.  (record-swap-ok jon existing)
      (reply eyre-id (error-json 400 'InvalidSwap' 'swapRecord does not match the current record'))
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
        (reply eyre-id (json-payload 200 (config-json config auth (lent ~(tap by sessions)) (lent ~(tap by records)) (lent ~(tap by blobs)) head rev sequence (lent history))))
      ?.  ?&  ?=(%'POST' method.request.req)
              ?=([%configure ~] t.t.t.site)
          ==
        (reply eyre-id (error-json 404 'NotFound' 'not found'))
      =/  jon=(unit json)  (parse-body req)
      ?~  jon  (reply eyre-id (error-json 400 'InvalidRequest' 'invalid JSON body'))
      =/  enabled=(unit ?)  (bool-at 'enabled' u.jon)
      =/  origin=(unit @t)  (string-at 'origin' u.jon)
      =/  service-did=(unit @t)  (string-at 'serviceDid' u.jon)
      =/  did=(unit @t)  (string-at 'did' u.jon)
      =/  handle=(unit @t)  (string-at 'handle' u.jon)
      =/  password=(unit @t)  (string-at 'appPassword' u.jon)
      =/  clear-password=(unit ?)  (bool-at 'clearAppPassword' u.jon)
      ?~  enabled  (reply eyre-id (error-json 400 'InvalidRequest' 'missing enabled'))
      ?~  origin  (reply eyre-id (error-json 400 'InvalidRequest' 'missing origin'))
      ?~  service-did  (reply eyre-id (error-json 400 'InvalidRequest' 'missing serviceDid'))
      ?~  did  (reply eyre-id (error-json 400 'InvalidRequest' 'missing did'))
      ?~  handle  (reply eyre-id (error-json 400 'InvalidRequest' 'missing handle'))
      ?:  ?&  ?=(^ password)
              |((lth (met 3 u.password) 8) (gth (met 3 u.password) 256))
          ==
        (reply eyre-id (error-json 400 'InvalidRequest' 'appPassword must be 8 to 256 bytes'))
      =/  identity-changed=?
        ?|  !=(u.service-did service-did.config)
            !=(u.did did.config)
            !=(u.handle handle.config)
        ==
      =/  clear=?  ?&(?=(^ clear-password) u.clear-password)
      =.  config
        [u.enabled u.origin u.service-did u.did u.handle private-key.config clock.config]
      =?  auth  ?=(^ password)
        auth(password-hash `(password-digest:atpro-session password-salt.auth u.password))
      =?  auth  clear
        auth(password-hash ~)
      =?  sessions  |(identity-changed ?=(^ password) clear)
        ~
      =?  this  &(u.enabled ?=(~ head))  (rebuild %init '')
      (reply eyre-id (json-payload 200 (config-json config auth (lent ~(tap by sessions)) (lent ~(tap by records)) (lent ~(tap by blobs)) head rev sequence (lent history))))
    ?.  enabled.config
      (reply eyre-id (error-json 503 'ServiceUnavailable' 'PDS is disabled'))
    ?.  =('xrpc' i.site)
      (reply eyre-id (error-json 404 'NotFound' 'not found'))
    ?~  t.site  (reply eyre-id (error-json 404 'XRPCNotSupported' 'missing method'))
    =/  method=@t  i.t.site
    =/  unix-now=@ud  (unix-seconds:atpro-oauth now.bowl)
    =/  bearer=(unit @t)
      (bearer-token header-list.request.req)
    =/  access=(unit [id=@t session=pds-session:atpro-pds])
      ?~(bearer ~ (find-access u.bearer sessions unix-now))
    =/  refresh=(unit [id=@t session=pds-session:atpro-pds])
      ?~(bearer ~ (find-refresh u.bearer sessions unix-now))
    ?:  =('com.atproto.server.describeServer' method)
      ?.  ?=(%'GET' method.request.req)
        (reply eyre-id (error-json 405 'MethodNotAllowed' 'method not allowed'))
      =/  jon=json
        %-  pairs:enjs:format
        :~  ['did' s+service-did.config]
            ['availableUserDomains' a+~]
            ['inviteCodeRequired' b+%.n]
            ['phoneVerificationRequired' b+%.n]
            ['blobUploadLimit' n+'52428800']
        ==
      (reply eyre-id (json-payload 200 jon))
    ?:  =('com.atproto.server.createSession' method)
      ?.  ?=(%'POST' method.request.req)
        (reply eyre-id (error-json 405 'MethodNotAllowed' 'method not allowed'))
      =/  jon=(unit json)  (parse-body req)
      ?~  jon
        (reply eyre-id (error-json 400 'InvalidRequest' 'invalid JSON body'))
      =/  identifier=(unit @t)  (string-at 'identifier' u.jon)
      =/  password=(unit @t)  (string-at 'password' u.jon)
      ?.  ?&  ?=(^ identifier)
              ?|(=(u.identifier did.config) =(u.identifier handle.config))
          ==
        (reply eyre-id (error-json 401 'AuthenticationRequired' 'invalid identifier or password'))
      ?~  password
        (reply eyre-id (error-json 401 'AuthenticationRequired' 'invalid identifier or password'))
      ?~  password-hash.auth
        (reply eyre-id (error-json 401 'AuthenticationRequired' 'app-password sessions are not configured'))
      ?.  =(u.password-hash.auth (password-digest:atpro-session password-salt.auth u.password))
        (reply eyre-id (error-json 401 'AuthenticationRequired' 'invalid identifier or password'))
      =/  created=pds-session:atpro-pds
        (make-session config auth unix-now (cat 3 eny.bowl session-count))
      =.  session-count  +(session-count)
      =.  sessions  (~(put by sessions) id.created created)
      (reply eyre-id (json-payload 200 (session-json config created)))
    ?:  =('com.atproto.server.getSession' method)
      ?.  ?=(%'GET' method.request.req)
        (reply eyre-id (error-json 405 'MethodNotAllowed' 'method not allowed'))
      ?~  access
        (reply eyre-id (error-json 401 'AuthenticationRequired' 'valid access token required'))
      (reply eyre-id (json-payload 200 (account-json config)))
    ?:  =('com.atproto.server.refreshSession' method)
      ?.  ?=(%'POST' method.request.req)
        (reply eyre-id (error-json 405 'MethodNotAllowed' 'method not allowed'))
      ?~  refresh
        (reply eyre-id (error-json 400 'InvalidToken' 'valid refresh token required'))
      =/  created=pds-session:atpro-pds
        (make-session config auth unix-now (cat 3 eny.bowl session-count))
      =.  session-count  +(session-count)
      =.  sessions  (~(del by sessions) id.u.refresh)
      =.  sessions  (~(put by sessions) id.created created)
      (reply eyre-id (json-payload 200 (session-json config created)))
    ?:  =('com.atproto.server.deleteSession' method)
      ?.  ?=(%'POST' method.request.req)
        (reply eyre-id (error-json 405 'MethodNotAllowed' 'method not allowed'))
      ?~  refresh
        (reply eyre-id (error-json 400 'InvalidToken' 'valid refresh token required'))
      =.  sessions  (~(del by sessions) id.u.refresh)
      (reply eyre-id (json-payload 200 ~))
    ?:  =('com.atproto.repo.describeRepo' method)
      =/  requested=(unit @t)  (arg-at 'repo' args.rl)
      ?.  ?&  ?=(^ requested)
              ?|(=(u.requested did.config) =(u.requested handle.config))
          ==
        (reply eyre-id (error-json 400 'RepoNotFound' 'repository is not hosted here'))
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
      =/  requested=(unit @t)  (arg-at 'repo' args.rl)
      =/  collection=(unit @t)  (arg-at 'collection' args.rl)
      =/  rkey=(unit @t)  (arg-at 'rkey' args.rl)
      ?.  ?&  ?=(^ requested)
              ?|(=(u.requested did.config) =(u.requested handle.config))
              ?=(^ collection)
              ?=(^ rkey)
          ==
        (reply eyre-id (error-json 400 'InvalidRequest' 'invalid repo, collection, or rkey'))
      =/  found=(unit stored-record:atpro-pds)
        (~(get by records) (rap 3 ~[u.collection '/' u.rkey]))
      ?~  found  (reply eyre-id (error-json 400 'RecordNotFound' 'record not found'))
      (reply eyre-id (json-payload 200 (record-json did.config u.found)))
    ?:  =('com.atproto.repo.listRecords' method)
      =/  requested=(unit @t)  (arg-at 'repo' args.rl)
      =/  collection=(unit @t)  (arg-at 'collection' args.rl)
      ?.  ?&  ?=(^ requested)
              ?|(=(u.requested did.config) =(u.requested handle.config))
          ==
        (reply eyre-id (error-json 400 'RepoNotFound' 'repository is not hosted here'))
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
      =/  requested=(unit @t)  (arg-at 'did' args.rl)
      ?.  ?&  ?=(^ requested)
              =(u.requested did.config)
          ==
        (reply eyre-id (error-json 400 'RepoNotFound' 'repository is not hosted here'))
      =/  jon=json
        (pairs:enjs:format ~[['cid' s+(cid-text:atpro-repo (need head))] ['rev' s+(need rev)]])
      (reply eyre-id (json-payload 200 jon))
    ?:  =('com.atproto.sync.getRepoStatus' method)
      =/  requested=(unit @t)  (arg-at 'did' args.rl)
      ?.  ?&  ?=(^ requested)
              =(u.requested did.config)
          ==
        (reply eyre-id (error-json 400 'RepoNotFound' 'repository is not hosted here'))
      =/  jon=json
        %-  pairs:enjs:format
        :~  ['did' s+did.config]
            ['active' b+%.y]
            ['rev' s+(need rev)]
        ==
      (reply eyre-id (json-payload 200 jon))
    ?:  =('com.atproto.sync.listRepos' method)
      =/  cursor=(unit @t)  (arg-at 'cursor' args.rl)
      =/  repos=(list json)
        ?:  ?=(^ cursor)  ~
        :~  %-  pairs:enjs:format
            :~  ['did' s+did.config]
                ['head' s+(cid-text:atpro-repo (need head))]
                ['rev' s+(need rev)]
                ['active' b+%.y]
            ==
        ==
      (reply eyre-id (json-payload 200 (pairs:enjs:format ~[['repos' a+repos]])))
    ?:  =('com.atproto.sync.getRepo' method)
      =/  requested=(unit @t)  (arg-at 'did' args.rl)
      ?.  ?&  ?=(^ requested)
              =(u.requested did.config)
          ==
        (reply eyre-id (error-json 400 'RepoNotFound' 'repository is not hosted here'))
      =/  requested-since=(unit @t)  (arg-at 'since' args.rl)
      =/  since-ok=?
        ?~  requested-since  %.y
        (lien history |=(version=repo-version:atpro-pds =(rev.version u.requested-since)))
      ?.  since-ok
        (reply eyre-id (error-json 400 'InvalidRequest' 'since revision is unavailable'))
      (reply eyre-id (bytes-payload 'application/vnd.ipld.car' car))
    ?:  =('com.atproto.sync.getBlocks' method)
      =/  requested-did=(unit @t)  (arg-at 'did' args.rl)
      ?.  ?&  ?=(^ requested-did)
              =(u.requested-did did.config)
          ==
        (reply eyre-id (error-json 400 'RepoNotFound' 'repository is not hosted here'))
      =/  requested=(list @t)
        %+  turn
          %+  skim  args.rl
          |=  [key=@t value=@t]
          =(key 'cids')
        |=  [key=@t value=@t]
        value
      ?:  =(~ requested)
        (reply eyre-id (error-json 400 'InvalidRequest' 'missing cids'))
      =/  all-blocks=(list block:atpro-repo-types)
        (zing (turn history |=(version=repo-version:atpro-pds blocks.version)))
      ?.  (levy requested |=(requested-cid=@t ?=(^ (find-block requested-cid all-blocks))))
        (reply eyre-id (error-json 400 'InvalidRequest' 'one or more blocks are unavailable'))
      =/  selected=(list block:atpro-repo-types)
        (turn requested |=(requested-cid=@t (need (find-block requested-cid all-blocks))))
      (reply eyre-id (bytes-payload 'application/vnd.ipld.car' (car-v1-roots:atpro-repo ~ selected)))
    ?:  =('com.atproto.sync.getBlob' method)
      =/  requested-did=(unit @t)  (arg-at 'did' args.rl)
      =/  requested-cid=(unit @t)  (arg-at 'cid' args.rl)
      ?.  ?&  ?=(^ requested-did)
              =(u.requested-did did.config)
          ==
        (reply eyre-id (error-json 400 'RepoNotFound' 'repository is not hosted here'))
      ?~  requested-cid
        (reply eyre-id (error-json 400 'InvalidRequest' 'missing cid'))
      =/  blob=(unit stored-blob:atpro-pds)  (~(get by blobs) u.requested-cid)
      ?~  blob
        (reply eyre-id (error-json 400 'BlobNotFound' 'blob not found'))
      =/  settings=(unit [credentials=credentials:atpro-s3 configuration=configuration:atpro-s3])
        (storage-settings our.bowl now.bowl)
      ?~  settings
        (reply eyre-id (error-json 503 'ServiceUnavailable' 'S3 credentials are not configured in Storage'))
      =/  signed=signed-request:atpro-s3
        (sign:atpro-s3 'GET' mime.u.blob [0 0] credentials.u.settings configuration.u.settings object-key.u.blob now.bowl)
      (queue-blob [%get eyre-id u.blob] [%'GET' url.signed headers.signed ~])
    ?:  =('com.atproto.sync.listBlobs' method)
      =/  requested-did=(unit @t)  (arg-at 'did' args.rl)
      ?.  ?&  ?=(^ requested-did)
              =(u.requested-did did.config)
          ==
        (reply eyre-id (error-json 400 'RepoNotFound' 'repository is not hosted here'))
      =/  requested-since=(unit @t)  (arg-at 'since' args.rl)
      =/  since-ok=?
        ?~  requested-since  %.y
        (lien history |=(version=repo-version:atpro-pds =(rev.version u.requested-since)))
      ?.  since-ok
        (reply eyre-id (error-json 400 'InvalidRequest' 'since revision is unavailable'))
      =/  asked-limit=(unit @ud)
        =/  raw=(unit @t)  (arg-at 'limit' args.rl)
        ?~(raw ~ (slaw %ud u.raw))
      =/  limit=@ud  ?~(asked-limit 500 (min 1.000 (max 1 u.asked-limit)))
      =/  asked-offset=(unit @ud)
        =/  raw=(unit @t)  (arg-at 'cursor' args.rl)
        ?~(raw ~ (slaw %ud u.raw))
      =/  offset=@ud  ?~(asked-offset 0 u.asked-offset)
      =/  all=(list [@t stored-blob:atpro-pds])  ~(tap by blobs)
      =/  remaining=(list [@t stored-blob:atpro-pds])  (slag offset all)
      =/  page=(list [@t stored-blob:atpro-pds])  (scag limit remaining)
      =/  fields=(list [@t json])
        ~[['cids' a+(turn page |=([cid-text=@t blob=stored-blob:atpro-pds] s+cid-text))]]
      =?  fields  (gth (lent remaining) limit)
        (snoc fields ['cursor' s+(scot %ud (add offset limit))])
      (reply eyre-id (json-payload 200 (pairs:enjs:format fields)))
    ?.  ?=(%'POST' method.request.req)
      (reply eyre-id (error-json 404 'XRPCNotSupported' 'method not supported'))
    ?.  |(authenticated.req ?=(^ access))
      (reply eyre-id (error-json 401 'AuthenticationRequired' 'write authentication required'))
    ?:  =('com.atproto.repo.uploadBlob' method)
      ?~  body.request.req
        (reply eyre-id (error-json 400 'InvalidRequest' 'missing blob body'))
      ?:  (gth p.u.body.request.req 52.428.800)
        (reply eyre-id (error-json 413 'PayloadTooLarge' 'blob exceeds 50 MiB'))
      =/  content-type=(unit @t)
        (get-header:http 'content-type' header-list.request.req)
      ?~  content-type
        (reply eyre-id (error-json 400 'InvalidRequest' 'missing blob content type'))
      =/  cid=cid:atpro-repo-types  (cid-for-raw:atpro-repo u.body.request.req)
      =/  cid-text=@t  (cid-text:atpro-repo cid)
      =/  object-key=@t  (rap 3 ~['atpro/' did.config '/' cid-text])
      =/  blob=stored-blob:atpro-pds
        [cid u.content-type p.u.body.request.req object-key rev]
      =/  settings=(unit [credentials=credentials:atpro-s3 configuration=configuration:atpro-s3])
        (storage-settings our.bowl now.bowl)
      ?~  settings
        (reply eyre-id (error-json 503 'ServiceUnavailable' 'S3 credentials are not configured in Storage'))
      =/  signed=signed-request:atpro-s3
        (sign:atpro-s3 'PUT' u.content-type u.body.request.req credentials.u.settings configuration.u.settings object-key now.bowl)
      (queue-blob [%put eyre-id blob] [%'PUT' url.signed headers.signed `u.body.request.req])
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
      =/  existing=(unit stored-record:atpro-pds)  (~(get by records) key)
      ?~  existing
        (reply eyre-id (error-json 400 'RecordNotFound' 'record not found'))
      ?.  (commit-swap-ok u.jon head)
        (reply eyre-id (error-json 400 'InvalidSwap' 'swapCommit does not match the current commit'))
      ?.  (record-swap-ok u.jon existing)
        (reply eyre-id (error-json 400 'InvalidSwap' 'swapRecord does not match the current record'))
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
      ?.  (commit-swap-ok u.jon head)
        (reply eyre-id (error-json 400 'InvalidSwap' 'swapCommit does not match the current commit'))
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
    ``json+!>((config-json config auth (lent ~(tap by sessions)) (lent ~(tap by records)) (lent ~(tap by blobs)) head rev sequence (lent history)))
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
  ::
      [%iris @ ~]
    =/  request-id=(unit @uv)  (slaw %uv i.t.wire)
    ?~  request-id  `this
    =/  context=(unit blob-request)  (~(get by in-flight) u.request-id)
    ?~  context  `this
    =.  in-flight  (~(del by in-flight) u.request-id)
    =/  eyre-id=@ta
      ?-  -.u.context
          %put  eyre-id.u.context
          %get  eyre-id.u.context
      ==
    ?.  ?=([%iris %http-response *] sign)
      :_  this
      (give-simple-payload:app:server eyre-id (error-json 502 'UpstreamFailure' 'S3 request failed'))
    =/  response=client-response:iris  client-response.sign
    ?.  ?=(%finished -.response)
      :_  this
      (give-simple-payload:app:server eyre-id (error-json 502 'UpstreamFailure' 'S3 response was incomplete'))
    =/  status=@ud  status-code.response-header.response
    ?.  &((gte status 200) (lth status 300))
      :_  this
      (give-simple-payload:app:server eyre-id (error-json 502 'UpstreamFailure' 'S3 rejected the request'))
    ?-  -.u.context
        %put
      =/  text=@t  (cid-text:atpro-repo cid.blob.u.context)
      =.  blobs  (~(put by blobs) text blob.u.context)
      =/  jon=json
        (frond:enjs:format 'blob' (blob-json blob.u.context))
      :_  this
      (give-simple-payload:app:server eyre-id (json-payload 200 jon))
    ::
        %get
      =/  data=octs
        ?~(full-file.response [0 0] data.u.full-file.response)
      :_  this
      (give-simple-payload:app:server eyre-id (bytes-payload mime.blob.u.context data))
    ==
  ==
::
++  on-fail  on-fail:def
--
