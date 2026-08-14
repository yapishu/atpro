/-  atpro-repo-types
|%
+$  pds-config
  $:  enabled=?
      origin=@t
      did=@t
      handle=@t
      private-key=@
      clock=@ud
  ==
+$  stored-record
  $:  key=@t
      collection=@t
      rkey=@t
      cid=cid:atpro-repo-types
      block=octs
      value=json
  ==
+$  repo-event
  $:  sequence=@ud
      rev=@t
      head=cid:atpro-repo-types
      operation=@tas
      key=@t
  ==
+$  state-0
  $:  %0
      config=pds-config
      records=(map @t stored-record)
      head=(unit cid:atpro-repo-types)
      rev=(unit @t)
      last-timestamp=(unit @ud)
      blocks=(list block:atpro-repo-types)
      car=octs
      sequence=@ud
      events=(list repo-event)
  ==
--
