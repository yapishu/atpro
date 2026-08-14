::  Fixed HS256 and password-digest vectors.
/+  atpro-session
:-  %say
|=  *
:-  %noun
:-  ~
=/  key=@  0x1f1e.1d1c.1b1a.1918.1716.1514.1312.1110.0f0e.0d0c.0b0a.0908.0706.0504.0302.0100
=/  jwt=@t
  %-  session-jwt:atpro-session
  :*  'at+jwt'
      'com.atproto.access'
      'did:plc:test'
      'did:web:pds.example.com'
      'session-1'
      1.786.622.400
      1.786.629.600
      key
  ==
[jwt password-digest=(password-digest:atpro-session key 'correct horse battery staple')]
