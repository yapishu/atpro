|%
+$  cid  octs
::
+$  ipld
  $%  [%null ~]
      [%bool value=?]
      [%int value=@s]
      [%bytes value=octs]
      [%text value=@t]
      [%list values=(list *)]
      [%map entries=(list [@t *])]
      [%link value=cid]
  ==
::
+$  mst-record  [key=@t value=cid]
+$  mst-leaf    [key=@t value=cid layer=@ud]
+$  mst-entry
  $:  prefix=@ud
      suffix=octs
      value=cid
      subtree=(unit cid)
  ==
+$  block  [cid=cid data=octs]
+$  mst-result
  $:  root=cid
      blocks=(list block)
      layer=@ud
      leaves=@ud
  ==
::
+$  unsigned-commit
  $:  did=@t
      rev=@t
      prev=(unit cid)
      data=cid
  ==
+$  commit-result
  $:  root=cid
      block=octs
      unsigned=octs
      signature=octs
  ==
+$  record-value  [key=@t value=*]
+$  encoded-record  [key=@t cid=cid block=octs]
+$  repo-snapshot
  $:  head=cid
      rev=@t
      records=(list encoded-record)
      blocks=(list block)
      car=octs
  ==
--
