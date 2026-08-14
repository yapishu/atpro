::  AT Protocol timestamp identifiers (TIDs).
|%
++  unix-micros
  |=  now=@da
  ^-  @ud
  (div (mul (sub now ~1970.1.1) 1.000.000) (bex 64))
::
++  encode-width
  |=  [value=@ud width=@ud]
  ^-  @t
  =/  alphabet=@t  '234567abcdefghijklmnopqrstuvwxyz'
  =/  chars=tape  ~
  |-
  ?:  =(width 0)
    (crip chars)
  =/  digit=@ud  (mod value 32)
  =/  char=@tD  (cut 3 [digit 1] alphabet)
  $(value (div value 32), width (dec width), chars [char chars])
::
++  make
  |=  [timestamp=@ud clock=@ud]
  ^-  @t
  ?>  (lth timestamp (bex 55))
  ?>  (lth clock 32)
  (rap 3 ~[(encode-width timestamp 11) (encode-width clock 2)])
::
++  next
  |=  [now=@da previous=(unit @ud) clock=@ud]
  ^-  [tid=@t timestamp=@ud]
  =/  wall=@ud  (unix-micros now)
  =/  timestamp=@ud
    ?~  previous  wall
    (max wall +(u.previous))
  [(make timestamp clock) timestamp]
--
