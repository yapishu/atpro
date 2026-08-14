/-  atpro-repo-types
|%
+$  pds-config
  $:  enabled=?
      origin=@t
      service-did=@t
      did=@t
      handle=@t
      private-key=@
      clock=@ud
  ==
+$  pds-auth
  $:  password-salt=@
      password-hash=(unit @)
      jwt-key=@
  ==
+$  pds-session
  $:  id=@t
      access-jwt=@t
      refresh-jwt=@t
      access-expires=@ud
      refresh-expires=@ud
  ==
+$  stored-record
  $:  key=@t
      collection=@t
      rkey=@t
      cid=cid:atpro-repo-types
      block=octs
      value=json
  ==
+$  stored-blob
  $:  cid=cid:atpro-repo-types
      mime=@t
      size=@ud
      object-key=@t
      uploaded-at=(unit @t)
  ==
+$  repo-event
  $:  sequence=@ud
      rev=@t
      head=cid:atpro-repo-types
      operation=@tas
      key=@t
  ==
+$  repo-version
  $:  head=cid:atpro-repo-types
      rev=@t
      since=(unit @t)
      blocks=(list block:atpro-repo-types)
      car=octs
      sequence=@ud
  ==
+$  state-0
  $:  %0
      config=pds-config
      auth=pds-auth
      sessions=(map @t pds-session)
      session-count=@ud
      records=(map @t stored-record)
      blobs=(map @t stored-blob)
      head=(unit cid:atpro-repo-types)
      rev=(unit @t)
      last-timestamp=(unit @ud)
      blocks=(list block:atpro-repo-types)
      car=octs
      history=(list repo-version)
      sequence=@ud
      events=(list repo-event)
  ==
--
