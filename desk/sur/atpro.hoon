|%
+$  oauth-data
  $:  auth-server=@t
      token-endpoint=@t
      key=@
      auth-nonce=(unit @t)
      pds-nonce=(unit @t)
      client-id=@t
      redirect-uri=@t
      scope=@t
  ==
::
+$  session
  $:  service=@t
      did=@t
      handle=@t
      access-token=@t
      refresh-token=@t
      oauth=(unit oauth-data)
  ==
::
+$  oauth-client
  $:  client-id=@t
      redirect-uri=@t
      scope=@t
  ==
::
+$  pending-auth
  $:  identifier=@t
      did=@t
      handle=@t
      service=@t
      auth-server=@t
      authorization-endpoint=@t
      token-endpoint=@t
      par-endpoint=@t
      client-id=@t
      redirect-uri=@t
      scope=@t
      state=@t
      verifier=@t
      key=@
      auth-nonce=(unit @t)
  ==
::
+$  oauth-work
  $:  identifier=@t
      client-id=@t
      redirect-uri=@t
      did=(unit @t)
      handle=(unit @t)
      service=(unit @t)
      auth-server=(unit @t)
  ==
::
+$  oauth-rpc
  $:  method=method:http
      url=@t
      headers=(list [@t @t])
      body=(unit octs)
  ==
::
+$  at-identity
  $:  did=@t
      handle=@t
      confirmed-at=@da
  ==
::
+$  state-0
  $:  %0
      account=(unit session)
      oauth-client=(unit oauth-client)
      pending=(map @t pending-auth)
      public-identity=(unit at-identity)
  ==
::
+$  request-kind
  $?  %login
      %refresh
      %rpc
      %oauth-identity
      %oauth-did
      %oauth-resource
      %oauth-metadata
      %oauth-par
      %oauth-token
  ==
::
+$  request-context
  $:  eyre-id=@ta
      kind=request-kind
      service=(unit @t)
      work=(unit oauth-work)
      auth=(unit pending-auth)
      rpc=(unit oauth-rpc)
      code=(unit @t)
      retry=?
  ==
--
