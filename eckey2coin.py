## eckey2coin.py by MiWCryptoCurrency@gmail.com for UTXO based Certificates UTXOC 'you chi ock'
## CC BY-SA 3.0
##
## code snippits from https://bitcointalk.org/index.php?topic=18051.0
## thnkx Martin P. Hellwig
## Read PEM
## https://github.com/geertj/python-asn1/blob/master/examples/dump.py
##
## Choice based ASN1 fix for x509
## https://github.com/Gu1/ndg_httpsclient/commit/50289e2eb0e5dd5fa539a5b7487e30296812a0da
## 
## Background reading:
##
## RFC 5915 EC
##  ECPrivateKey ::= SEQUENCE {
##     version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
##     privateKey     OCTET STRING,
##     parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
##     publicKey  [1] BIT STRING OPTIONAL
##}

# RFC 5480
##ECParameters ::= CHOICE {
##       namedCurve         OBJECT IDENTIFIER
##       -- implicitCurve   NULL
##       -- specifiedCurve  SpecifiedECDomain
##     }
##       -- implicitCurve and specifiedCurve MUST NOT be used in PKIX.
##       -- Details for SpecifiedECDomain can be found in [X9.62].
##       -- Any future additions to this CHOICE should be coordinated
##       -- with ANSI X9.


#
# inspiration from ku tools
# thanks to richard kiss for pycoin, this library is great

import sys
import pycoin
import array
import argparse
from hashlib import sha512
from pyasn1.codec.der import encoder, decoder
from pyasn1.type import univ, namedtype, namedval, constraint, tag
from pycoin.ecdsa import is_public_pair_valid, generator_secp256k1, public_pair_for_x, secp256k1
from pycoin.serialize import b2h, h2b
from pycoin.key import Key
from pycoin.networks import full_network_name_for_netcode, NETWORK_NAMES
from pycoin import encoding
import qrcode

class ECPrivateKey(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', univ.Integer()),
        namedtype.NamedType('privateKey', univ.OctetString()),
        namedtype.NamedType('namedCurve', univ.ObjectIdentifier().subtype(
        explicitTag=tag.Tag(tag.tagClassContext,
            tag.tagFormatSimple, 0))),
        namedtype.NamedType('publicKey', univ.BitString().subtype(
            implicitTag=tag.Tag(tag.tagClassContext,
                tag.tagFormatSimple, 1)))
        )

# http://www.oid-info.com/get/1.2.840.10045.2.1
OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1" 
# http://www.oid-info.com/get/1.3.132.0.10
OID_SECP256K1 = univ.ObjectIdentifier("1.3.132.0.10")



def read_pem(input):
    """Read PEM formatted input."""
    data = []
    state = 0
    for line in input.split('\n'):
        if state == 0:
            if line.startswith('-----BEGIN'):
                state = 1
        elif state == 1:
            if line.startswith('-----END'):
                state = 2
            else:
                data.append(line)
        elif state == 2:
            break
    if state != 2:
        raise ValueError, 'No PEM encoded input found'
    data = ''.join(data)
    data = data.decode('base64')
    return data
   

def isValidECKey(privatekey):
    if not (privatekey[0]==univ.Integer(1)):
        "Version in PEM must be 1"
        return False
    print "Key is %d bits" % (len(privatekey[1]) * 8)
    if (len(privatekey[1]) * 8) < 256:
        print "Key is too small! Must be 256 bit"
        return False
    if not (privatekey[2] == OID_SECP256K1):
        print "Curve is not SECP256K1 (bitcoin, et al.)"
        return False
    return True

def parse_as_number(s):
    try:
        return int(s)
    except ValueError:
        pass
    try:
        return int(s, 16)
    except ValueError:
        pass


def parse_as_secret_exponent(s):
    v = parse_as_number(s)
    if v and v < secp256k1._r:
        return v

def main():
    parser = argparse.ArgumentParser(
        description='ECkey2coin.py by MiWCryptoCurrency@gmail.com for UTXO based Certificates UTXOC.',
        epilog='Known networks codes:\n  ' \
                + ', '.join(['%s (%s)'%(i, full_network_name_for_netcode(i)) for i in NETWORK_NAMES])
    )
    parser.add_argument('-k', '--key', required=False, type=argparse.FileType('r'), help='The EC private key in PEM format')
    parser.add_argument('-q', '--qrfilename', required=False, help='QR code output filename')
    parser.add_argument('-n', "--network", help='specify network (default: BTC = Bitcoin)',
                                default='BTC', choices=NETWORK_NAMES)
    args = parser.parse_args()
    network = args.network
    inputprivatekey = ''
    if args.key:
        keyfile = args.key        
        while True:
            line = keyfile.readline().strip()
            if not line: break
            inputprivatekey += line + '\n'
        print 'Loaded EC Key from %s' % keyfile
    else:    
        print ('Please enter EC KEY in pem format:')
        inputprivatekey  = ''
        while True:
            line = raw_input().strip()
            if not line: break
            inputprivatekey += line + '\n'
    if not args.qrfilename:
        qrfilename = raw_input("Please enter qrcode output filename: ")
    else:
        qrfilename = args.qrfilename
    pkey = decoder.decode(read_pem(inputprivatekey), asn1Spec=ECPrivateKey())
    print 'Key loaded'
    if not isValidECKey(pkey[0]):
        print "EC Key Supplied cannot be used"
        exit
    print "Key Validated OK"
    inputkey = encoding.to_long(256, pycoin.encoding.byte_to_int, pkey[0][1].asOctets())[0]
    if inputkey:
        key = Key(secret_exponent=inputkey, netcode=network)
        btcsecret = key.secret_exponent()
        btcpublic = key.public_pair()
        hash160_c = key.hash160(use_uncompressed=False)
        hash160_u = key.hash160(use_uncompressed=True)
        qrimg = qrcode.QRCode (
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qrimg.add_data(key.address(use_uncompressed=False))
        qrimg.make(fit=True)
        img = qrimg.make_image()
        img.save(qrfilename)
    print"----------------- BEGIN EC PRIVATE KEYS -----------------"
    print "Secret:     %d" % btcsecret
    print "Secret hex: %x" % btcsecret
    print "wif:        %s" % key.wif(use_uncompressed=False)
    print "----------------- END EC PRIVATE KEYS -----------------------------"
    print "----------------- BEGIN PUBLIC KEY -----------------------------"
    print "Public X: %d" % btcpublic[0]
    print "Public Y: %d" % btcpublic[1]
    print "hash160 uncompressed: %s" % b2h(hash160_u)
    print "Sec: (uncompressed): %s" % b2h(key.sec(use_uncompressed=True))
    print "%s address: %s (uncompressed)" % (key._netcode, key.address(use_uncompressed=True))
    print "Public X (hex): %x" % btcpublic[0]
    print "Public Y (hex): %x" % btcpublic[1]
    print "Sec: %s" % b2h(key.sec(use_uncompressed=False))
    print "hash160 compressed: %s" % b2h(hash160_c)
    print "----------------- END PUBLIC KEYS -----------------------------"
    print "------------------ BEGIN %s ADDRESSES -------------------------" % key._netcode
    print "%s address: %s" % (key._netcode, key.address(use_uncompressed=False))
    print "------------------ END %s ADDRESSES -------------------------" % key._netcode
    
    

    
if __name__ == "__main__":
    main()
