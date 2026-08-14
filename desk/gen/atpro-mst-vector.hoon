::  Empty-tree interop fixture from ../atproto/packages/repo/tests/mst.test.ts
/-  atpro-repo-types
/+  atpro-mst
:-  %say
|=  *
:-  %noun
:-  ~
=/  value=cid:atpro-repo-types
  [36 0xef3c.b3cc.fd04.d413.370e.5042.3822.89d0.d31f.36a9.08c7.5262.0620.a5f3.c36b.159d.2012.7101]
=/  empty=mst-result:atpro-repo-types  (build:atpro-mst ~)
=/  empty-expected=cid:atpro-repo-types
  :*  36
      0x7b67.47f6.8992.75e2.db6f.2d48.20df.7ad5.7983.b080.3802.e5ca.3dea.76dd.61fe.fe9d.2012.7101
  ==
=/  trivial=mst-result:atpro-repo-types
  (build:atpro-mst ~[['com.example.record/3jqfcqzm3fo2j' value]])
=/  trivial-expected=cid:atpro-repo-types
  [36 0x1d79.82e9.c1d6.5eb3.0007.b2cb.cf86.2da7.b146.e74a.8bec.f677.5e8d.0d82.2de4.e229.2012.7101]
=/  layer-two=mst-result:atpro-repo-types
  (build:atpro-mst ~[['com.example.record/3jqfcqzm3fx2j' value]])
=/  layer-two-expected=cid:atpro-repo-types
  [36 0x27b.6357.616e.6940.0d8e.9e1c.3f19.384d.8a99.f4e5.da34.2047.c1c9.f775.8f48.b1ff.2012.7101]
=/  simple=mst-result:atpro-repo-types
  %-  build:atpro-mst
  :~  ['com.example.record/3jqfcqzm3fp2j' value]
      ['com.example.record/3jqfcqzm3fr2j' value]
      ['com.example.record/3jqfcqzm3fs2j' value]
      ['com.example.record/3jqfcqzm3ft2j' value]
      ['com.example.record/3jqfcqzm4fc2j' value]
  ==
=/  simple-expected=cid:atpro-repo-types
  [36 0xfbd0.0a61.4669.bff5.e9fb.9779.6c86.33fc.f963.f486.675a.7777.69b1.be71.28f1.014c.2012.7101]
[ empty-ok==(root.empty empty-expected)
  trivial-ok==(root.trivial trivial-expected)
  layer-two-ok==(root.layer-two layer-two-expected)
  simple-ok==(root.simple simple-expected)
  empty-blocks=(lent blocks.empty)
  simple-blocks=(lent blocks.simple)
  simple-layer=layer.simple
  simple-leaves=leaves.simple
]
