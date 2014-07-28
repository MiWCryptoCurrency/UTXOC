UTXOC
=====

Unspent Transaction Output based Certificates UTXOC ‘you-chi-ock’

Proof of concept cryptocurrency (bitcoin-like) private keys used to generate valid
signed ECDSA with-SHA256 x509 certificates to be used for medium term
authentication within the TLS protocol and other and future applications. These
certificates have additional explicit value by merit that they prove ownership of
decentralised bitcoin-like value. This construction has been formatively titled
Unspent TransaXtion Output Certificate or UTXOC, pronounced ‘you-chi-ock’.

What does this provide in addition to
every-day Trusted CA Certified certificates
we know and love from such trusted
names as Honest Achmed and Diginotar?

By generating an x509 certificate that uses this key, one can
explicitly reference the transaction in which some value was transered to this
address. By ensuring that the transaction is not claimed (spent) for the lifetime
of the certificate, clients have an independently verifiable way of detecting key
compromise; as well as increasing the cost for active attacks against TLS.
Additionally it provides a bearer bond type construction that can be used with
existing x509 infrastructure and devices such as elliptic curve smart cards; and
proof of ownership signatures can be made without the official wallet software.

Paper: https://github.com/MiWCryptoCurrency/UTXOC/blob/master/UTXOCv1.pdf?raw=true


Yours in cryptography && cryptocurrency,
MiWCryptoCurrency
