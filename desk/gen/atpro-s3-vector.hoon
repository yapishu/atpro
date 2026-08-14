::  Fixed AWS Signature V4 request vector.
/+  atpro-s3
:-  %say
|=  *
:-  %noun
:-  ~
=/  credentials=credentials:atpro-s3  ['s3.example.com' 'AKID' 'SECRET']
=/  configuration=configuration:atpro-s3  ['bucket' 'us-east-1']
=/  request=signed-request:atpro-s3
  (sign:atpro-s3 'PUT' 'image/png' [3 0x63.6261] credentials configuration 'atpro/test blob' ~2026.8.14..12.34.56)
=/  deletion=signed-request:atpro-s3
  (sign:atpro-s3 'DELETE' 'application/octet-stream' [0 0] credentials configuration 'atpro/test blob' ~2026.8.14..12.34.56)
[ url=url.request
  delete-url=url.deletion
  date=(need (get-header:http 'x-amz-date' headers.request))
  payload-hash=(need (get-header:http 'x-amz-content-sha256' headers.request))
  authorization=(need (get-header:http 'authorization' headers.request))
  delete-authorization=(need (get-header:http 'authorization' headers.deletion))
  delete-method-signed=!=((need (get-header:http 'authorization' headers.request)) (need (get-header:http 'authorization' headers.deletion)))
]
