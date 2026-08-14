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
+$  oauth-request
  $:  id=@t
      client-id=@t
      redirect-uri=@t
      scope=@t
      state=(unit @t)
      code-challenge=@t
      dpop-jkt=@t
      expires-at=@ud
  ==
+$  oauth-code
  $:  request=oauth-request
      code=@t
      expires-at=@ud
  ==
+$  oauth-session
  $:  id=@t
      client-id=@t
      scope=@t
      dpop-jkt=@t
      access-token=@t
      refresh-token=@t
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
      uploaded-at=@ud
      tethered=?
      referenced-at=(unit @t)
      references=(set @t)
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
      oauth-requests=(map @t oauth-request)
      oauth-codes=(map @t oauth-code)
      oauth-sessions=(map @t oauth-session)
      dpop-jtis=(map @t @ud)
      oauth-count=@ud
      preferences=(list json)
      records=(map @t stored-record)
      blobs=(map @t stored-blob)
      pending-blob-deletes=(map @t stored-blob)
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
