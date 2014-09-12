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

A traditional x509 trust chain can be created between signer and request with these certificates.
Subject and Issuer values are encoded in standard certificate form and can be added to compliant
Operating System or or Browser trust stores.


Our first UTXOC Root CA Certificate was signed Friday, 25 July 2014 4:07:06 AM and as published at
```
https://github.com/MiWCryptoCurrency/UTXOC/blob/master/UTXOC-CA.crt
The TX referenced in the certificate has0.01 BTC unspent (~$60 USD in July 2014)
and the bond is held for 10 years. (10 year validity, expires 22/07/2024)
```

[Discussion Paper](https://github.com/MiWCryptoCurrency/UTXOC/blob/master/UTXOCv1.pdf?raw=true)

Things you will need:
* openssl (usually with Linux and OSX; Windows binaries from Shining Light Productions)
* python 2.7
* python libraries:
* pycoin
* pyasn1
* qrcode
* binascii
* pycrypto
* binascii
* pkiutils
* hashlib
* pyasn1\_modules
* maybe more?

How to generate a Self-Signed UTXOC (CryptoCurrency Bond) [learning way]:
-----------------------------------------------------------------------------

##Generate Key
first generate your EC (elliptic curve) private key over secp256k1

This is just a very big number between 1 and (almost) 2^256.
Or in decimal:
1 and 115792089237316195423570985008687907852837564279074904382605163141518161494337

This is a 'universe scale' range of numbers.
Guessing a bitcoin private key by chance is less likely than finding one particular atom in the 
neighbouring 8 billion galaxies to our home on Earth.

the curve secp256k1 is defined as y^2 = x^3 + 7 over the finite field Z(p), where p
is 115792089237316195423570985008687907853269984665640564039457584007908834671663.

these curve parameters allow us to define a public key, from which we can create an bitcoin-like address,
ie: bitcoin, litecoin, dogecoin

There are many ways to generate a large number (our EC private key) as randomly (unpredictably) as possible,
but for now we use openssl:
```
openssl ecparam -out myUTXOC.key -name secp256k1 -genkey
```
clean this file so that it only contains the headings and text between 
-----BEGIN EC PRIVATE KEY----- and -----END EC PRIVATE KEY-----
Dont worry! The -----BEGIN EC PARAMETERS----- section is stored implicitly in the EC PRIVATE KEY SECTION.

##Convert key to coin
use the eckey2coin.py script to write this as coin address, and generate a QR code for you.

You may wish to store the line containing the wif, or wallet import format, value somewhere safe.
This code will allow you import this key into any wallet software and spend any balance associated with the address.
It will also let you claim the value after the certificate has expired.
```
python eckey2coin.py -k myUTXOC.key -n BTC -q myUTXOC.png
```
##Load the key with value
Initiate a transaction on the network that spends some value to the address displayed by eckey2coin.py or in the QR code it generated.
That transaction hash will be the included in the certificate signing request.

##Check the transaction has been accepted, and confirmed by the network.
Copy the transaction hash.

##Generate the signing request
```
python utxocsr.py -k myUTXOC.key -f myUTXOC.csr -n BTC -t #################tx-hash-goes-here#############################
```

This will generate you a signing request with the specified subject, and calculate a SubjectAltName to identify the coin address
and transaction.

##Sign the signing request
```
python utxocsign.py -k myUTXOC.key -c myUTXOC.csr -f myUTXOC.crt -d 365 -n BTC
```
This will output the file myUTXOC.crt; which should be a valid UTXOC. You can verify the validity of this, or any other UTXOC encoded
this way with the verifyutxoc.py script.

##Verify the certificate
```
python verifyutxoc.py -f myUTXOC.crt
```
##Share your certificate file as proof of bond
The certificate is considered valid as long as the transaction it references is not claimed until the end of the validity period.
Examples of use:
* TLS Server Authentication, ie: https www server
* TLS Client Authentication, browser client
* Code Signing, ie Operating System or Application binaries on a trusted platform
* File encryption keys, File system encryption keys
* Future applications for public key cryptosystems!

How to generate a Self-Signed UTXOC (CryptoCurrency Bond) [commands only]:
---------------------------------------------------------------------------
```
openssl ecparam -out myUTXOC.key -name secp256k1 -genkey 
{remove ec params section from key file}
python eckey2coin.py -k myUTXOC.key -n BTC -q myUTXOC.png
python utxocsr.py -k myUTXOC.key -f myUTXOC.csr -n BTC -t ##################tx-hash-goes-here#############################
python utxocsign.py -k myUTXOC.key -c myUTXOC.csr -f myUTXOC.crt -d 365 -n BTC
python verifyutxoc.py -f myUTXOC.crt
```



Warning:
If this is your first time playing with raw coin addresses, raw bitcoin or altcoin transactions and private keys, please be careful
with the files you generate. Store them sensibly. Take Backups. Consider your data privacy.
As long as you do not lose your private key (either the secret number, the key file or wif value is sufficent), you should be able to 
recover any funds spent to their addresses.
Start experimenting with small amounts of cryptocurrency in the event you lose your keys or they are somehow compromised.
Dont store the key file, the wif value or the secret number anywhere that others can read it.

Yours in cryptography && cryptocurrency,
MiWCryptoCurrency
