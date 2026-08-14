::  Focused byte fixtures from the AT DAG-CBOR encoding rules.
/-  atpro-repo-types
/+  atpro-repo
:-  %say
|=  *
:-  %noun
:-  ~
=/  canonical=ipld:atpro-repo-types
  [%map ~[['b' [%int --2]] ['a' [%int --1]]]]
=/  nested=ipld:atpro-repo-types
  [%list ~[[%null ~] [%bool %.y] [%text 'ö']]]
=/  canonical-bytes=octs  (encode:atpro-repo canonical)
=/  nested-bytes=octs     (encode:atpro-repo nested)
=/  canonical-ok=?  =(canonical-bytes [7 0x2.6261.0161.61a2])
=/  nested-ok=?     =(nested-bytes [6 0xb6c3.62f5.f683])
=/  canonical-roundtrip=?
  =(canonical-bytes (encode:atpro-repo (decode:atpro-repo canonical-bytes)))
=/  nested-roundtrip=?     =(nested (decode:atpro-repo nested-bytes))
=/  cid=cid:atpro-repo-types  (cid-for-cbor:atpro-repo canonical-bytes)
=/  expected-cid=cid:atpro-repo-types
  :*  36
      0xe3b5.93c8.7490.7533.6b8d.4c89.9938.d0b7.f3c6.e257.06ad.
        9b72.7f51.e586.9eaf.d3a0.2012.7101
  ==
=/  car=octs  (car-v1:atpro-repo cid ~[[cid canonical-bytes]])
:*  canonical-ok=canonical-ok
    nested-ok=nested-ok
    canonical-roundtrip=canonical-roundtrip
    nested-roundtrip=nested-roundtrip
    cid-ok==(cid expected-cid)
    cid-text-ok==((cid-text:atpro-repo cid) 'bafyreifa2oxz5bxfkf7xfg5nazl6frxtw7idrgmjjsgwwm3vsb2mre5v4m')
    varint-ok==((varint:atpro-repo 300) [2 0x2ac])
    car-size-ok==(p.car 103)
    car-header-size-ok==((byte-at:atpro-repo car 0) 58)
    car-block-size-ok==((byte-at:atpro-repo car 59) 43)
    car-block-byte=(byte-at:atpro-repo car 59)
    canonical-bytes=canonical-bytes
    nested-bytes=nested-bytes
    cid=cid
==
