|%
+$  server-config
  $:  enabled=?
      service-did=@t
      endpoint=@t
      feed-uri=@t
  ==
::
+$  state-0
  $:  %0
      config=server-config
      posts=(list @t)
  ==
--
