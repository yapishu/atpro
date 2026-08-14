::  Deterministic repository-commit signing smoke vector.
/-  atpro-repo-types
/+  atpro-commit
:-  %say
|=  *
:-  %noun
:-  ~
=/  key=@  1
=/  data=cid:atpro-repo-types
  [36 0x7b67.47f6.8992.75e2.db6f.2d48.20df.7ad5.7983.b080.3802.e5ca.3dea.76dd.61fe.fe9d.2012.7101]
=/  commit=unsigned-commit:atpro-repo-types
  ['did:plc:atproexample' '3jqfcqzm3fo2j' ~ data]
=/  signed=commit-result:atpro-repo-types  (sign:atpro-commit commit key)
=/  signature-s=@  (rev 3 32 (cut 3 [32 32] q.signature.signed))
=/  order=@  0xffff.ffff.0000.0000.ffff.ffff.ffff.ffff.bce6.faad.a717.9e84.f3b9.cac2.fc63.2551
[ did-key-ok==((did-key:atpro-commit key) 'did:key:zDnaepsL7AXenJkVYdkh5KuKsSU7Ykh7kyXaLLU7auN9FWSiZ')
  root-bytes=p.root.signed
  block-bytes=p.block.signed
  unsigned-bytes=p.unsigned.signed
  signature-bytes=p.signature.signed
  low-s=(lte (mul 2 signature-s) order)
]
