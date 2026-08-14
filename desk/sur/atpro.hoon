|%
+$  session
  $:  service=@t
      did=@t
      handle=@t
      access-jwt=@t
      refresh-jwt=@t
  ==
::
+$  state-0
  $:  %0
      account=(unit session)
  ==
::
+$  request-kind  ?(%login %refresh %rpc)
+$  request-context
  $:  eyre-id=@ta
      kind=request-kind
      service=(unit @t)
  ==
--
