::  End-to-end record -> MST -> signed commit -> CAR fixture.
/-  atpro-repo-types
/+  atpro-repository
:-  %say
|=  *
:-  %noun
:-  ~
=/  record=record-value:atpro-repo-types
  :-  'app.bsky.feed.post/3jqfcqzm3fo2j'
  :*  %map
      :~  ['$type' [%text 'app.bsky.feed.post']]
          ['text' [%text 'hello from urbit']]
          ['createdAt' [%text '2023-11-14T22:13:20.000Z']]
      ==
  ==
=/  repo=repo-snapshot:atpro-repo-types
  (snapshot:atpro-repository 'did:plc:atproexample' '3jqfcqzm3fo2j' ~ ~[record] 1)
[ head-bytes=p.head.repo
  records=(lent records.repo)
  blocks=(lent blocks.repo)
  car-bytes=p.car.repo
  car-root-prefix=(cut 3 [0 4] q.head.repo)
]
