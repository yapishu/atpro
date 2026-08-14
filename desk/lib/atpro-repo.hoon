::  Deterministic AT repository encodings.
::
::  DAG-CBOR maps use the RFC 8949 deterministic order: encoded key length,
::  then bytewise lexical order.  CIDs are raw CIDv1 byte strings; textual
::  multibase presentation belongs at the HTTP/UI boundary.
::
/-  atpro-repo-types
|%
++  oct
  |=  byte=@
  ^-  octs
  ?>  (lth byte 256)
  [1 byte]
::
++  join
  |=  [left=octs right=octs]
  ^-  octs
  [(add p.left p.right) (can 3 ~[[p.left q.left] [p.right q.right]])]
::
++  join-all
  |=  parts=(list octs)
  ^-  octs
  (reel parts join)
::
++  big-endian
  |=  [width=@ud value=@]
  ^-  octs
  [width (rev 3 width value)]
::
++  head
  |=  [major=@ud argument=@]
  ^-  octs
  ?>  (lth major 8)
  =/  base=@  (mul major 32)
  ?:  (lth argument 24)
    (oct (add base argument))
  ?:  (lth argument 256)
    (join (oct (add base 24)) (big-endian 1 argument))
  ?:  (lth argument 65.536)
    (join (oct (add base 25)) (big-endian 2 argument))
  ?:  (lth argument 4.294.967.296)
    (join (oct (add base 26)) (big-endian 4 argument))
  ?>  (lth argument (bex 64))
  (join (oct (add base 27)) (big-endian 8 argument))
::
++  key-less
  |=  [[a-key=@t a-value=*] [b-key=@t b-value=*]]
  ^-  ?
  =/  a-len=@ud  (met 3 a-key)
  =/  b-len=@ud  (met 3 b-key)
  ?:  !=(a-len b-len)
    (lth a-len b-len)
  (lth (rev 3 a-len a-key) (rev 3 b-len b-key))
::
++  insert-entry
  |=  [item=[@t *] items=(list [@t *])]
  ^-  (list [@t *])
  ?~  items  ~[item]
  ?:  (key-less item i.items)
    [item items]
  [i.items $(items t.items)]
::
++  sort-entries
  |=  items=(list [@t *])
  ^-  (list [@t *])
  ?~  items  ~
  (insert-entry i.items $(items t.items))
::
++  encode
  |=  value=ipld:atpro-repo-types
  ^-  octs
  ?-  value
      [%null ~]
    (oct 246)
  ::
      [%bool *]
    (oct ?:(value.value 245 244))
  ::
      [%int *]
    =/  magnitude=@  +:(old:si value.value)
    ?:  (syn:si value.value)
      (head 0 magnitude)
    ?>  (gth magnitude 0)
    (head 1 (dec magnitude))
  ::
      [%bytes *]
    (join (head 2 p.value.value) value.value)
  ::
      [%text *]
    =/  length=@ud  (met 3 value.value)
    (join (head 3 length) [length value.value])
  ::
      [%list *]
    %+  join  (head 4 (lent values.value))
    %-  join-all
    %+  turn  values.value
    |=(child=* (encode ;;(ipld:atpro-repo-types child)))
  ::
      [%map *]
    =/  sorted=(list [@t *])
      (sort-entries entries.value)
    =/  encoded=(list octs)
      %+  turn  sorted
      |=  [key=@t child=*]
      (join (encode [%text key]) (encode ;;(ipld:atpro-repo-types child)))
    (join (head 5 (lent sorted)) (join-all encoded))
  ::
      [%link *]
    =/  tagged=octs  (join (oct 0) value.value)
    (join (head 6 42) (join (head 2 p.tagged) tagged))
  ==
::
++  cid-for-cbor
  |=  bytes=octs
  ^-  cid:atpro-repo-types
  =/  digest=@  (shay bytes)
  ::  CIDv1, dag-cbor (0x71), sha2-256 (0x12), 32-byte digest.
  [36 (cat 3 0x2012.7101 digest)]
::
++  cid-for-raw
  |=  bytes=octs
  ^-  cid:atpro-repo-types
  =/  digest=@  (shay bytes)
  ::  CIDv1, raw binary (0x55), sha2-256 (0x12), 32-byte digest.
  [36 (cat 3 0x2012.5501 digest)]
::
++  cid-for-ipld
  |=  value=ipld:atpro-repo-types
  ^-  cid:atpro-repo-types
  (cid-for-cbor (encode value))
::
++  base32-lower
  |=  bytes=octs
  ^-  @t
  =/  alphabet=@t  'abcdefghijklmnopqrstuvwxyz234567'
  =/  bits=@ud  (mul 8 p.bytes)
  =/  width=@ud  (div (add bits 4) 5)
  =/  padding=@ud  (sub (mul width 5) bits)
  =/  value=@  (lsh [0 padding] (rev 3 p.bytes q.bytes))
  =/  chars=tape  ~
  |-
  ?:  =(width 0)
    (crip chars)
  =/  digit=@ud  (mod value 32)
  =/  char=@tD  (cut 3 [digit 1] alphabet)
  $(value (div value 32), width (dec width), chars [char chars])
::
++  cid-text
  |=  cid=cid:atpro-repo-types
  ^-  @t
  (rap 3 ~['b' (base32-lower cid)])
::
++  byte-at
  |=  [bytes=octs offset=@ud]
  ^-  @ud
  ?>  (lth offset p.bytes)
  (cut 3 [offset 1] q.bytes)
::
++  slice
  |=  [bytes=octs offset=@ud count=@ud]
  ^-  octs
  ?>  (lte (add offset count) p.bytes)
  [count (cut 3 [offset count] q.bytes)]
::
++  read-head
  |=  [bytes=octs offset=@ud]
  ^-  [major=@ud argument=@ next=@ud]
  =/  first=@ud  (byte-at bytes offset)
  =/  major=@ud  (div first 32)
  =/  info=@ud   (mod first 32)
  ?:  (lth info 24)
    [major info +(offset)]
  =/  width=@ud
    ?:  =(info 24)  1
    ?:  =(info 25)  2
    ?:  =(info 26)  4
    ?:  =(info 27)  8
    !!
  =/  raw=octs  (slice bytes +(offset) width)
  [major (rev 3 width q.raw) (add +(offset) width)]
::
++  decode-list
  |=  [bytes=octs offset=@ud count=@ud]
  ^-  [values=(list *) next=@ud]
  ?:  =(count 0)  [~ offset]
  =/  [value=ipld:atpro-repo-types after=@ud]  (decode-at bytes offset)
  =/  [rest=(list *) next=@ud]  $(offset after, count (dec count))
  [[value rest] next]
::
++  decode-map
  |=  [bytes=octs offset=@ud count=@ud]
  ^-  [entries=(list [@t *]) next=@ud]
  ?:  =(count 0)  [~ offset]
  =/  [key-node=ipld:atpro-repo-types after-key=@ud]
    (decode-at bytes offset)
  ?>  ?=([%text *] key-node)
  =/  key=@t  value.key-node
  =/  [value=ipld:atpro-repo-types after-value=@ud]
    (decode-at bytes after-key)
  =/  [rest=(list [@t *]) next=@ud]
    $(offset after-value, count (dec count))
  [[[key value] rest] next]
::
++  decode-at
  |=  [bytes=octs offset=@ud]
  ^-  [value=ipld:atpro-repo-types next=@ud]
  =/  [major=@ud argument=@ next=@ud]  (read-head bytes offset)
  ?:  =(major 0)
    [[%int (new:si %.y argument)] next]
  ?:  =(major 1)
    [[%int (new:si %.n +(argument))] next]
  ?:  =(major 2)
    =/  value=octs  (slice bytes next argument)
    [[%bytes value] (add next argument)]
  ?:  =(major 3)
    =/  value=octs  (slice bytes next argument)
    [[%text `@t`q.value] (add next argument)]
  ?:  =(major 4)
    =/  [values=(list *) after=@ud]  (decode-list bytes next argument)
    [[%list values] after]
  ?:  =(major 5)
    =/  [entries=(list [@t *]) after=@ud]  (decode-map bytes next argument)
    [[%map entries] after]
  ?:  =(major 6)
    ?>  =(argument 42)
    =/  [tagged=ipld:atpro-repo-types after=@ud]  $(offset next)
    ?>  ?=([%bytes *] tagged)
    ?>  (gth p.value.tagged 0)
    ?>  =(0 (byte-at value.tagged 0))
    [[%link (slice value.tagged 1 (dec p.value.tagged))] after]
  ?>  =(major 7)
  ?:  =(argument 20)  [[%bool %.n] next]
  ?:  =(argument 21)  [[%bool %.y] next]
  ?:  =(argument 22)  [[%null ~] next]
  !!
::
++  decode
  |=  bytes=octs
  ^-  ipld:atpro-repo-types
  =/  [value=ipld:atpro-repo-types next=@ud]  (decode-at bytes 0)
  ?>  =(next p.bytes)
  value
::
++  varint
  |=  value=@
  ^-  octs
  ?:  (lth value 128)
    (oct value)
  (join (oct (add 128 (mod value 128))) $(value (div value 128)))
::
++  car-v1
  |=  [root=cid:atpro-repo-types blocks=(list [cid:atpro-repo-types octs])]
  ^-  octs
  (car-v1-roots ~[root] blocks)
::
++  car-v1-roots
  |=  [roots=(list cid:atpro-repo-types) blocks=(list [cid:atpro-repo-types octs])]
  ^-  octs
  =/  header-value=ipld:atpro-repo-types
    :*  %map
        :~  ['roots' [%list (turn roots |=(root=cid:atpro-repo-types [%link root]))]]
            ['version' [%int --1]]
        ==
    ==
  =/  header=octs  (encode header-value)
  =/  framed-header=octs  (join (varint p.header) header)
  =/  framed-blocks=(list octs)
    %+  turn  blocks
    |=  [cid=cid:atpro-repo-types block=octs]
    =/  length=@ud  (add p.cid p.block)
    (join (varint length) (join cid block))
  (join framed-header (join-all framed-blocks))
--
