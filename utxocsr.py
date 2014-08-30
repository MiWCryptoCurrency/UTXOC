## utxocsr.py py by MiWCryptoCurrency for UTXO based Certificates UTXOC 'you chi ock'
## CC BY-SA 3.0
##
## Uses code from https://github.com/jandd/python-pkiutils/blob/master/pkiutils/__init__.py pure python pkiutils
# http://www.ietf.org/rfc/rfc5480.txt is your friend (EC public key format)
## also RFC3279 http://www.ietf.org/rfc/rfc3279.txt
##
##
##

import sys
import pycoin
import array
import argparse
import hashlib
from hashlib import sha256
from Crypto.Hash import SHA256
from Crypto import Random
from pyasn1.codec.der import encoder, decoder
from pyasn1.type import univ, namedtype, namedval, constraint, tag
from pyasn1_modules import rfc2314
from pycoin.serialize import b2h, h2b
from pycoin.key import Key
from pycoin.key.bip32 import Wallet
from pycoin.networks import full_network_name_for_netcode, NETWORK_NAMES
from pycoin import encoding
import pkiutils
import binascii
# also http://tools.ietf.org/html/rfc5754 RFC 5754 with SHA2
# http://tools.ietf.org/html/rfc5758 RFC 5758 x509 additional identifiers for ECDSA
# https://github.com/coruus/pyasn1-modules/blob/master/pyasn1_modules/rfc2459.py
# x509 objects

OID_SECP256K1 = univ.ObjectIdentifier("1.3.132.0.10")
OID_ecdsaWithSHA256 = univ.ObjectIdentifier("1.2.840.10045.4.3.2")
OID_idEcPublicKey = univ.ObjectIdentifier("1.2.840.10045.2.1")
OID_PKCS9_EXT_REQUEST= univ.ObjectIdentifier('1.2.840.113549.1.9.14')
OID_eku = univ.ObjectIdentifier('2.5.29.37')
##
## AlgorithmIdentifier  ::=  SEQUENCE  {
##        algorithm   OBJECT IDENTIFIER,
##        parameters  ANY DEFINED BY algorithm OPTIONAL
##  }
##
##
##

class AlgorithmIdentifier(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('algorithm', univ.ObjectIdentifier() ),
        namedtype.NamedType('parameters', univ.ObjectIdentifier().subtype(
        explicitTag=tag.Tag(tag.tagClassContext,
            tag.tagFormatSimple, 0)))
        )

##     SubjectPublicKeyInfo  ::=  SEQUENCE  {
##       algorithm         AlgorithmIdentifier,
##       subjectPublicKey  BIT STRING
##     }

class SubjectPublicKeyInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('algorithm', AlgorithmIdentifier()),
        namedtype.NamedType('subjectPublicKey', univ.BitString())
        )


## RFC 3279
## Ecdsa-Sig-Value  ::=  SEQUENCE  {
##           r     INTEGER,
##           s     INTEGER
## }

class ECDSASigValue(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('r', univ.Integer()),
        namedtype.NamedType('s', univ.Integer())
        )

## RFC 5915 EC
##  ECPrivateKey ::= SEQUENCE {
##     version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
##     privateKey     OCTET STRING,
##     parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
##     publicKey  [1] BIT STRING OPTIONAL
##}
    
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

class curve(univ.Sequence):

    componentType = namedtype.NamedTypes(
     namedtype.NamedType('public KeyType',univ.ObjectIdentifier()),
     namedtype.NamedType('curveName',univ.ObjectIdentifier())
    )

class ECPublicKey(univ.Sequence):
    componentType = namedtype.NamedTypes(
    namedtype.NamedType('curve', curve()),
    namedtype.NamedType('publicKeyValue', univ.BitString())
    )
        
    
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

def read_pem(input):
    """Read PEM formatted input."""
    data = []
    state = 0
    for line in input.split('\n'):
        line.split('\n')
        if state == 0:
            if line.startswith('-----BEGIN EC PRIVATE'):
                state = 1
        elif state == 1:
            if line.startswith('-----END EC PRIVATE'):
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

def _build_subject_publickey_info(key):
    pubkeybitstring = key[0].getComponentByPosition(3)
    algorithm = univ.Sequence()
    algorithm.setComponentByPosition(
        0, OID_idEcPublicKey)
    algorithm.setComponentByPosition(
        1, OID_SECP256K1)
    subjectPublicKeyInfo = SubjectPublicKeyInfo()
    subjectPublicKeyInfo.setComponentByName(
        'algorithm', algorithm)
    subjectPublicKeyInfo.setComponentByName(
        'subjectPublicKey', univ.BitString(value=pubkeybitstring))
    # print subjectPublicKeyInfo
    return subjectPublicKeyInfo

def randomsign(generator, secret_exponent, val):
# from https://github.com/richardkiss/pycoin/blob/master/pycoin/ecdsa/ecdsa.py
# but randomized sig. Use k value in the order of the curve
    from math import log
    G = generator
    n = G.order()
    n_bytes = int(log(n)) + 7 // 8
    rndfile = Random.new()
    k = encoding.to_long(256, encoding.byte_to_int, rndfile.read(n_bytes))[0]
    p1 = k * G
    r = p1.x()
    if r == 0: raise RuntimeError("amazingly unlucky random number r")
    s = ( pycoin.ecdsa.numbertheory.inverse_mod( k, n ) * \
          ( val + ( secret_exponent * r ) % n ) ) % n
    if s == 0: raise RuntimeError("amazingly unlucky random number s")
    return (r, s)



def _build_signature(key, certreqinfo, network):
    secret_exponent = encoding.to_long(256, encoding.byte_to_int, key[0][1].asOctets())[0]
    #signer = SigningKey.from_secret_exponent(secret_exponent, curve=ecdsa.curves.SECP256k1, hashfunc=sha256)
    coin  = Key(secret_exponent=secret_exponent, netcode=network)
    print "building signature for %s address" % network
    print coin.address()
    pubkeybitstring = (key[0].getComponentByPosition(2), key[0].getComponentByPosition(3))
    certreqinfoder = encoder.encode(certreqinfo)
    hashvalue = SHA256.new(certreqinfoder)
    hexdgst = hashvalue.hexdigest()
    dgst = hashvalue.digest()
    dgstaslong = encoding.to_long(256, encoding.byte_to_int, dgst)[0]
    order2 = pycoin.ecdsa.generator_secp256k1.order()
    # random sign
    rawsig2 = randomsign(pycoin.ecdsa.generator_secp256k1, secret_exponent, dgstaslong)
    # deterministic sign
    #rawsig2 = pycoin.ecdsa.sign(pycoin.ecdsa.generator_secp256k1, secret_exponent, dgstaslong)
    r2, s2 = rawsig2
    print "signature: r: %x s: %x" % (r2, s2)
    signature = ECDSASigValue()
    signature.setComponentByName('r', r2)
    signature.setComponentByName('s', s2)
    dersig = encoder.encode(signature)
    signaturevalue = "'{0}'H".format(binascii.hexlify(dersig))
    bitstring = univ.BitString( value=signaturevalue )
    return rfc2314.Signature( bitstring )


def _build_dn(dnspec):
    if isinstance(dnspec, dict):
        dndict = dnspec
    else:
        dndict = []
        for pair in dnspec.split('/'):
            if pair.find('=') >= 0:
                key, value = pair.split('=', 1)
                dndict.append((key,value))
    # put components in correct order
    
    dnparts = rfc2314.RDNSequence()
    count = 0
    for key, value in dndict:
        rdn = rfc2314.RelativeDistinguishedName()
        rdn.setComponentByPosition(0, pkiutils._build_dn_component(key, value))
        dnparts.setComponentByPosition(count, rdn)
        count += 1

    dn = rfc2314.Name()
    dn.setComponentByPosition(0, dnparts)
    return dn

def _build_basic_constraints(value):
    retval = rfc2314.BasicConstraints()
    retval.setComponentByName('cA', univ.Boolean(value[0]))
    if value[0]:
        retval.setComponentByName(
            'pathLenConstraint',
            retval.componentType.getTypeByPosition(
                retval.componentType.getPositionByName(
                    'pathLenConstraint')).clone(value[1]))
    return retval

def _build_extension_request(extensions):
    SUPPORTED_EXTENSIONS = {
        'subjectAlternativeName': (
            rfc2314.id_ce_subjectAltName,
            _build_subject_alt_name),
        'x509basicConstraints': (
            rfc2314.id_ce_basicConstraints,
            _build_basic_constraints),
        'x509v3KeyUsage': (
            rfc2314.id_ce_keyUsage,
            _build_key_usage),
        'x509v3ExtendedKeyUsage': (
            rfc2314.id_ce_extKeyUsage,
            _build_extended_key_usage),
    }

    count = 0
    exts = rfc2314.Extensions()
    for key, critical, value in extensions:
        if key in SUPPORTED_EXTENSIONS:
            extoid, builder = SUPPORTED_EXTENSIONS[key]
            extval = builder(value)
            ext = rfc2314.Extension()
            encapsulated = univ.OctetString(encoder.encode(extval))
            ext.setComponentByName('extnID', extoid)
            ext.setComponentByName('critical', univ.Boolean(critical))
            ext.setComponentByName('extnValue', encapsulated)

            exts.setComponentByPosition(count, ext)
            count += 1
    if count > 0:
        retval = univ.SetOf(componentType=rfc2314.AttributeTypeAndValue())
        retval.setComponentByPosition(0, exts)
    return retval
    
def _build_key_usage(value):
    pass


def _build_extended_key_usage(value):
    pass


def _build_subject_alt_name(value):
    if isinstance(value, str) or isinstance(value, unicode):
        value = (value,)
    retval = rfc2314.SubjectAltName()
    count = 0
    for item in value:
        altname = _build_general_name(item)
        if altname:
            retval.setComponentByPosition(count, altname)
            count += 1
    return retval
    
def _build_general_name(generalname):
    rfc2314.GeneralNames()
    retval = rfc2314.GeneralName()
    identifier, value = generalname.split(':', 1)
    if identifier == 'DNS':
        dnspos = retval.componentType.getPositionByName('dNSName')
        dnsval = retval.componentType.getTypeByPosition(dnspos).clone(
            value)
        retval.setComponentByPosition(dnspos, dnsval)
    elif identifier == 'IP':
        ippos = retval.componentType.gtPositionByName('iPAddress')
        ipval = retval.componentType.getTypeByPosition(ippos).clone(
            hexValue=_ip_str_to_octets(value))
        retval.setComponentByPosition(ippos, ipval)
    elif identifier == 'URI':
        dnspos = retval.componentType.getPositionByName('uniformResourceIdentifier')
        dnsval = retval.componentType.getTypeByPosition(dnspos).clone(
            value)
        retval.setComponentByPosition(dnspos, dnsval)
    else:
        print 'unsupported general name %s' % generalname
        return None
    return retval

def _build_attributes(attributes, attrtype):
    if not attributes:
        return attrtype
    attr = attrtype.clone()
    count = 0
    for key, value in list(attributes.items()):
        attritem = _build_attribute(key, value)
        if attritem:
            attr.setComponentByPosition(count, attritem)
            count += 1
    return attr

def _build_attribute(key, value):
    SUPPORTED_ATTRIBUTES = {
        'extensionRequest': (
            OID_PKCS9_EXT_REQUEST, _build_extension_request),
    }
    if key in SUPPORTED_ATTRIBUTES:
        attroid, builder = SUPPORTED_ATTRIBUTES[key]
        attr = rfc2314.Attribute()
        attrval = builder(value)
        if attrval:
            attr.setComponentByName('type', attroid)
            attr.setComponentByName('vals', builder(value))
            #print "attr %s" % attr.prettyPrint()
            return attr
    return None



def create_csr_ec(key, dn, network, csrfilename=None, attributes=None ):
    """ from jandd pkiutils adjusted for EC
    """
    certreqInfo = rfc2314.CertificationRequestInfo()
    certreqInfo.setComponentByName('version', rfc2314.Version(0))
    certreqInfo.setComponentByName('subject', _build_dn(dn))
    certreqInfo.setComponentByName('subjectPublicKeyInfo',
                                   _build_subject_publickey_info(key))
    attrpos = certreqInfo.componentType.getPositionByName('attributes')
    attrtype = certreqInfo.componentType.getTypeByPosition(attrpos)
    attr_asn1 = _build_attributes( attributes, attrtype)
    certreqInfo.setComponentByName('attributes', attr_asn1)
    certreq = rfc2314.CertificationRequest()
    certreq.setComponentByName('certificationRequestInfo', certreqInfo)
    sigAlgIdentifier = rfc2314.SignatureAlgorithmIdentifier()
    sigAlgIdentifier.setComponentByName(
        'algorithm',OID_ecdsaWithSHA256)
    certreq.setComponentByName(
        'signatureAlgorithm',
        sigAlgIdentifier)
    sig = _build_signature(key, certreqInfo, network)
    certreq.setComponentByName(
        'signature', sig)
    output = pkiutils._der_to_pem(encoder.encode(certreq), 'CERTIFICATE REQUEST')

    if csrfilename:
        with open(csrfilename, 'w') as csrfile:
            csrfile.write(output)
    print "generated certification request:\n\n%s"%  output
    return output

def main():
    parser = argparse.ArgumentParser(
        description='utxocsr.py by MiWCryptoCurrency for UTXOC UTXO based certificate signing request generation (CSR).'
    )
    parser.add_argument('-k', '--key', required=True, type=argparse.FileType('r'), help='Private EC Key')
    parser.add_argument('-f', '--filename', required=True, help='Output CSR Filename')
    parser.add_argument('-n', "--network", help='specify network (default: BTC = Bitcoin)',
                               default='BTC', choices=NETWORK_NAMES)
    parser.add_argument('-t', "--transactionid", required=False, help='transaction id (hex)')
    inputkey=""
    args = parser.parse_args()
    out = args.filename
    network = args.network
    while True:
            line = args.key.readline().strip()
            if not line: break
            inputkey += line + '\n'
    parsed_key = decoder.decode(read_pem(inputkey), asn1Spec=ECPrivateKey())
    #print parsed_key
    
    
    secret_exponent = encoding.to_long(256, encoding.byte_to_int, parsed_key[0][1].asOctets())[0]
    coin  = Key(secret_exponent=secret_exponent, netcode=network)
    pubaddr = coin.address(use_uncompressed=False)

    if (network=="BTC"):
        uriname = "bitcoin"
    if (network=="NMC"):
        uriname = "namecoin"
    if (network=="LTC"):
        uriname = "litecoin"

    if not args.transactionid:
        print "Please enter transaction id to reference in certificate. Leave blank to only encode the address."
        transactionid = raw_input()
        if transactionid == "":
            uri = uriname + ":" + pubaddr
        else:
            uri = uriname + ":" + pubaddr + "?" + "transaction=" + transactionid
    else:
        transactionid = args.transactionid
        uri = uriname + ":" + pubaddr + "?" + "transaction=" + transactionid
    dn = ""
    dn_c = raw_input("Please enter Country (eg: US): ")
    if (dn_c == ""):
        dn_c = "US"
    dn_st = raw_input("Please enter State (eg: California): ")
    if (dn_st == ""):
        dn_st = "California"
    dn_l = raw_input("Please enter City (eg: Sunnyvale): ")
    if (dn_l == ""):
        dn_l = "Sunnyvale"
    dn_o = raw_input("Please enter Organization (eg: Widgets Inc.): ")
    if (dn_o == ""):
        dn_o = "Widgets Inc."
    dn_ou = raw_input("Please enter Organization Unit: (eg: Information Security): ")
    if (dn_ou == ""):
        dn_ou = "Information Security"
    dn_cn = raw_input("Please enter Common Name: (eg: My first UTXOC): ")
    if (dn_cn == ""):
        dn_cn = "My first UTXOC"
    san = raw_input("Please enter Subject Alt Name values (DNS name, blank for none, seperate multiple entries with space): ")
    sanentry = []
    if (san == ""):
        sanentry = 'URI:%s' % uri
    else:
        for entry in san.split(" "):
            sanentry.append('DNS:%s' % entry)
        sanentry.append('URI:%s' % uri)
    dn = "/C=" + dn_c + "/ST=" + dn_st + "/L=" + dn_l + "/O=" + dn_o + "/OU=" + dn_ou + "/CN=" + dn_cn

    attributes={
        'extensionRequest': (
            ('x509basicConstraints', True,
             (False,)),
            ('subjectAlternativeName', False,
             sanentry
            ),
        )
    }

    create_csr_ec(parsed_key, dn, csrfilename=out, attributes=attributes, network=network)

if __name__ == "__main__":
    main()
