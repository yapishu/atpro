::  AT Protocol repository commit construction and P-256 signing.
/-  atpro-repo-types
/+  atpro-repo, atpro-oauth
|%
++  nullable-link
  |=  value=(unit cid:atpro-repo-types)
  ^-  ipld:atpro-repo-types
  ?~(value [%null ~] [%link u.value])
::
++  unsigned-ipld
  |=  commit=unsigned-commit:atpro-repo-types
  ^-  ipld:atpro-repo-types
  :*  %map
      :~  ['did' [%text did.commit]]
          ['version' [%int (new:si %.y 3)]]
          ['data' [%link data.commit]]
          ['rev' [%text rev.commit]]
          ['prev' (nullable-link prev.commit)]
      ==
  ==
::
++  signature
  |=  [message=octs private-key=@]
  ^-  octs
  =/  digest=@  (rev 3 32 (shay message))
  =/  domain=domain:secp:crypto  p256-domain:atpro-oauth
  =/  p256  ~(. secp:secp:crypto 32 domain)
  =/  raw=[r=@ s=@ y=@]  (ecdsa-raw-sign.p256 digest private-key)
  =/  order=@  n.domain
  =/  low-s=@
    ?:  (gth (mul 2 s.raw) order)
      (sub order s.raw)
    s.raw
  =/  bytes=@
    %+  can  3
    :~  [32 (rev 3 32 r.raw)]
        [32 (rev 3 32 low-s)]
    ==
  [64 bytes]
::
++  signed-ipld
  |=  [commit=unsigned-commit:atpro-repo-types sig=octs]
  ^-  ipld:atpro-repo-types
  :*  %map
      :~  ['did' [%text did.commit]]
          ['version' [%int (new:si %.y 3)]]
          ['data' [%link data.commit]]
          ['rev' [%text rev.commit]]
          ['prev' (nullable-link prev.commit)]
          ['sig' [%bytes sig]]
      ==
  ==
::
++  sign
  |=  [commit=unsigned-commit:atpro-repo-types private-key=@]
  ^-  commit-result:atpro-repo-types
  =/  unsigned=octs  (encode:atpro-repo (unsigned-ipld commit))
  =/  sig=octs  (signature unsigned private-key)
  =/  block=octs  (encode:atpro-repo (signed-ipld commit sig))
  =/  root=cid:atpro-repo-types  (cid-for-cbor:atpro-repo block)
  [root block unsigned sig]
::
++  did-key
  |=  private-key=@
  ^-  @t
  =/  point=point:atpro-oauth  (public-point:atpro-oauth private-key)
  =/  prefix=@ud  ?:(=(0 (mod y.point 2)) 2 3)
  =/  compressed=octs
    [33 (can 3 ~[[1 prefix] [32 (rev 3 32 x.point)]])]
  ::  unsigned-varint(0x1200), the multicodec for a P-256 public key.
  =/  multikey=octs  (join:atpro-repo [2 0x2480] compressed)
  =/  encoded=@t
    (crip (en-base58:mimes:html (rev 3 p.multikey q.multikey)))
  (rap 3 ~['did:key:z' encoded])
--
