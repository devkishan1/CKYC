Using this Nodejs Program We can Fetch Details from CERSAI.

1) Generate a random 256 bit session key.
2) Encrypt PID and timestamp using this session key by AES algorithm.
3) Encode the encrypted PID to Base64 string
4) Encrypt the session key using public key provided by CERSAI using RSA algorithm.
5) Encode the encrypted session key to Base64 string
6) Add this encrypted and encoded session key in request xml.
7) Sign entire request using FI's private key.
