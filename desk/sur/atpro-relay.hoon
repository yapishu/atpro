|%
+$  event
  $:  source=@t
      cursor=@t
      did=@t
      collection=@t
      rkey=@t
      operation=@t
      received=@da
  ==
::
+$  config
  $:  enabled=?
      webhook-token=@t
      upstream=(unit @p)
      allowlist=(set @p)
      max-events=@ud
  ==
::
+$  action
  $%  [%configure =config]
      [%ingest =event]
      [%clear ~]
  ==
::
+$  state-0
  $:  %0
      =config
      events=(list event)
      seen=(set @t)
  ==
--
