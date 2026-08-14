::  Canonical AT Protocol Merkle Search Tree construction.
/-  atpro-repo-types
/+  atpro-repo
|%
+$  node-result  [root=cid:atpro-repo-types blocks=(list block:atpro-repo-types)]
+$  split-result
  $:  before=(list mst-leaf:atpro-repo-types)
      match=(unit mst-leaf:atpro-repo-types)
      after=(list mst-leaf:atpro-repo-types)
  ==
+$  entries-result
  $:  entries=(list mst-entry:atpro-repo-types)
      blocks=(list block:atpro-repo-types)
  ==
::
++  text-less
  |=  [a=@t b=@t]
  ^-  ?
  =/  left=tape   (trip a)
  =/  right=tape  (trip b)
  |-
  ?~  left  ?=(^ right)
  ?~  right  %.n
  ?:  =(i.left i.right)
    $(left t.left, right t.right)
  (lth i.left i.right)
::
++  insert-leaf
  |=  [leaf=mst-leaf:atpro-repo-types leaves=(list mst-leaf:atpro-repo-types)]
  ^-  (list mst-leaf:atpro-repo-types)
  ?~  leaves  ~[leaf]
  ?:  (text-less key.leaf key.i.leaves)
    [leaf leaves]
  [i.leaves $(leaves t.leaves)]
::
++  sort-leaves
  |=  leaves=(list mst-leaf:atpro-repo-types)
  ^-  (list mst-leaf:atpro-repo-types)
  ?~  leaves  ~
  (insert-leaf i.leaves $(leaves t.leaves))
::
++  prefix-length
  |=  [a=@t b=@t]
  ^-  @ud
  =/  left=tape   (trip a)
  =/  right=tape  (trip b)
  =/  count=@ud  0
  |-
  ?~  left  count
  ?~  right  count
  ?.  =(i.left i.right)  count
  $(left t.left, right t.right, count +(count))
::
++  key-layer
  |=  key=@t
  ^-  @ud
  =/  bytes=octs  [(met 3 key) key]
  =/  digest=@    (shay bytes)
  =/  offset=@ud  0
  =/  count=@ud   0
  |-
  ?>  (lth offset 32)
  =/  byte=@ud  (cut 3 [offset 1] digest)
  =/  zeros=@ud  0
  =?  zeros  (lth byte 64)  +(zeros)
  =?  zeros  (lth byte 16)  +(zeros)
  =?  zeros  (lth byte 4)   +(zeros)
  =?  zeros  =(byte 0)      +(zeros)
  ?.  =(byte 0)  (add count zeros)
  $(offset +(offset), count (add count zeros))
::
++  max-layer
  |=  leaves=(list mst-leaf:atpro-repo-types)
  ^-  @ud
  =/  highest=@ud  0
  |-
  ?~  leaves  highest
  $(leaves t.leaves, highest (max highest layer.i.leaves))
::
++  split-layer
  |=  [leaves=(list mst-leaf:atpro-repo-types) target=@ud]
  ^-  split-result
  ?~  leaves  [~ ~ ~]
  ?:  =(layer.i.leaves target)
    [~ `i.leaves t.leaves]
  =/  rest=split-result  $(leaves t.leaves)
  [[i.leaves before.rest] match.rest after.rest]
::
++  nullable-link
  |=  value=(unit cid:atpro-repo-types)
  ^-  ipld:atpro-repo-types
  ?~(value [%null ~] [%link u.value])
::
++  entry-ipld
  |=  entry=mst-entry:atpro-repo-types
  ^-  *
  :*  %map
      :~  ['p' [%int (new:si %.y prefix.entry)]]
          ['k' [%bytes suffix.entry]]
          ['v' [%link value.entry]]
          ['t' (nullable-link subtree.entry)]
      ==
  ==
::
++  build-entries
  |=  $:  previous=@t
          current=mst-leaf:atpro-repo-types
          remaining=(list mst-leaf:atpro-repo-types)
          target=@ud
      ==
  ^-  entries-result
  =/  split=split-result  (split-layer remaining target)
  =/  child=(unit node-result)
    ?~  before.split  ~
    ?>  (gth target 0)
    `(build-node before.split (dec target))
  =/  prefix=@ud  (prefix-length previous key.current)
  =/  suffix-text=@t  (crip (slag prefix (trip key.current)))
  =/  subtree=(unit cid:atpro-repo-types)
    ?~(child ~ `root.u.child)
  =/  entry=mst-entry:atpro-repo-types
    [prefix [(met 3 suffix-text) suffix-text] value.current subtree]
  =/  child-blocks=(list block:atpro-repo-types)
    ?~(child ~ blocks.u.child)
  ?~  match.split
    [~[entry] child-blocks]
  =/  rest=entries-result
    $(previous key.current, current u.match.split, remaining after.split)
  [[entry entries.rest] (weld child-blocks blocks.rest)]
::
++  build-node
  |=  [leaves=(list mst-leaf:atpro-repo-types) target=@ud]
  ^-  node-result
  =/  split=split-result  (split-layer leaves target)
  =/  left=(unit node-result)
    ?~  before.split  ~
    ?>  (gth target 0)
    `(build-node before.split (dec target))
  =/  left-link=(unit cid:atpro-repo-types)
    ?~(left ~ `root.u.left)
  =/  made=entries-result
    ?~  match.split
      [~ ?~(left ~ blocks.u.left)]
    (build-entries '' u.match.split after.split target)
  =/  node=ipld:atpro-repo-types
    =/  encoded-entries=(list *)
      %+  turn  entries.made
      |=  entry=mst-entry:atpro-repo-types
      (entry-ipld entry)
    :*  %map
        :~  ['l' (nullable-link left-link)]
            ['e' [%list encoded-entries]]
        ==
    ==
  =/  data=octs  (encode:atpro-repo node)
  =/  root=cid:atpro-repo-types  (cid-for-cbor:atpro-repo data)
  =/  child-blocks=(list block:atpro-repo-types)
    (weld ?~(left ~ blocks.u.left) blocks.made)
  [root (snoc child-blocks [root data])]
::
++  build
  |=  records=(list mst-record:atpro-repo-types)
  ^-  mst-result:atpro-repo-types
  =/  leaves=(list mst-leaf:atpro-repo-types)
    %+  turn  records
    |=  record=mst-record:atpro-repo-types
    [key.record value.record (key-layer key.record)]
  =.  leaves  (sort-leaves leaves)
  =/  layer=@ud  (max-layer leaves)
  =/  node=node-result  (build-node leaves layer)
  [root.node blocks.node layer (lent leaves)]
--
