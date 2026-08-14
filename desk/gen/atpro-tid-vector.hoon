::  Fixed AT TID encoding vectors.
/+  atpro-tid
:-  %say
|=  *
:-  %noun
:-  ~
[ zero==((make:atpro-tid 0 0) '2222222222222')
  one==((make:atpro-tid 1 1) '2222222222323')
  fixed=(make:atpro-tid 1.700.000.000.000.000 17)
  monotonic=(next:atpro-tid ~2023.11.14..22.13.20 `1.700.000.000.000.001 17)
]
