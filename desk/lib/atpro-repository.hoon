::  Atomic construction of a complete single-account AT repository snapshot.
/-  atpro-repo-types
/+  atpro-repo, atpro-mst, atpro-commit
|%
++  encode-record
  |=  record=record-value:atpro-repo-types
  ^-  encoded-record:atpro-repo-types
  =/  value=ipld:atpro-repo-types  ;;(ipld:atpro-repo-types value.record)
  =/  block=octs  (encode:atpro-repo value)
  =/  cid=cid:atpro-repo-types  (cid-for-cbor:atpro-repo block)
  [key.record cid block]
::
++  snapshot
  |=  $:  did=@t
          rev=@t
          prev=(unit cid:atpro-repo-types)
          records=(list record-value:atpro-repo-types)
          private-key=@
      ==
  ^-  repo-snapshot:atpro-repo-types
  =/  encoded=(list encoded-record:atpro-repo-types)
    (turn records encode-record)
  =/  leaves=(list mst-record:atpro-repo-types)
    %+  turn  encoded
    |=  record=encoded-record:atpro-repo-types
    [key.record cid.record]
  =/  mst=mst-result:atpro-repo-types  (build:atpro-mst leaves)
  =/  unsigned=unsigned-commit:atpro-repo-types
    [did rev prev root.mst]
  =/  commit=commit-result:atpro-repo-types
    (sign:atpro-commit unsigned private-key)
  =/  record-blocks=(list block:atpro-repo-types)
    %+  turn  encoded
    |=  record=encoded-record:atpro-repo-types
    [cid.record block.record]
  =/  blocks=(list block:atpro-repo-types)
    (weld record-blocks (weld blocks.mst ~[[root.commit block.commit]]))
  =/  car=octs  (car-v1:atpro-repo root.commit blocks)
  [root.commit rev encoded blocks car]
--
