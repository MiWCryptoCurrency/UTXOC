## utxocsign.py by MiWCryptoCurrency for UTXO based Certificates UTXOC 'you chi ock'
## CC BY-SA 3.0
##
## Uses code from https://github.com/jandd/python-pkiutils/blob/master/pkiutils/__init__.py pure python pkiutils
# http://www.ietf.org/rfc/rfc5480.txt is your friend (EC public key format)
## also RFC3279 http://www.ietf.org/rfc/rfc3279.txt
## also the pyasn1-modules from the very talented Ilya Etingof
## this library tames the asn1 beast
##

import utility
from pyasn1_modules import rfc2314, rfc2459
import argparse
from Crypto.Hash import SHA256, SHA
from Crypto import Random
from pycoin.networks import full_network_name_for_netcode, NETWORK_NAMES
from pyasn1.codec.der import encoder, decoder
from pyasn1.codec.cer import encoder as pemencoder
import pycoin.ecdsa
from pycoin import encoding
from pyasn1.type import univ, namedtype, namedval, constraint, tag, useful, char
from pycoin.key import Key
import datetime
import binascii


class SANValidationException(Exception):
    pass

def _build_ECDSAwithSHA256_signatureAlgorithm():
    sigAlgIdentifier = rfc2314.SignatureAlgorithmIdentifier()
    sigAlgIdentifier.setComponentByName('algorithm', utility.OID_ecdsaWithSHA256)
    return sigAlgIdentifier
    

def _build_key_usage(value):
    ext = rfc2459.Extension()
    extoid = utility.OID_ku
    extval = rfc2459.KeyUsage(value)
    encapsulated = univ.OctetString(encoder.encode(extval))
    ext.setComponentByName('extnID', extoid)
    ext.setComponentByName('extnValue', encapsulated)
    return ext


def _build_extended_key_usage(ekus):
    ext = rfc2459.Extension()
    extoid = utility.OID_eku
    extval = rfc2459.ExtKeyUsageSyntax()
    for i, eku in enumerate(ekus):
        extval.setComponentByPosition(i, eku)
    encapsulated = univ.OctetString(encoder.encode(extval))
    ext.setComponentByName('extnID', extoid)
    ext.setComponentByName('extnValue', encapsulated)
    return ext

def _build_subject_alt_name(value):
    pass

def _find_basic_contraints(extensions):
    for extension in extensions:
        extoid = extension[0]
        if (extoid == utility.OID_basicConstraints):
            return extension
    return None

def _build_extensionFromAttributeExtension(extension):
    extoid = extension[0]
    if len(extension)==3:   
        critical = extension[1]
        value = extension[2]
        extval = value
        ext = rfc2459.Extension()
        encapsulated = extval
        ext.setComponentByName('extnID', extoid)
        ext.setComponentByName('critical', univ.Boolean(critical))
        ext.setComponentByName('extnValue', encapsulated)
        return ext
    elif len(extension)==2:
        value = extension[1]
        extval = value
        ext = rfc2314.Extension()
        encapsulated = extval
        ext.setComponentByName('extnID', extoid)
        ext.setComponentByName('extnValue', encapsulated)
        return ext
    else:
        return None

def _build_extension_netscapeURL(strurl):
    ext = rfc2459.Extension()
    extoid = utility.OID_ns_netscape_base_url
    extval = char.IA5String(strurl)
    encapsulated = univ.OctetString(encoder.encode(extval))
    ext.setComponentByName('extnID', extoid)
    ext.setComponentByName('extnValue', encapsulated)
    return ext

def _validate_san(extension):
    #print extension
    return True

def _build_extensionsForTbs(extensionsfromcsr, akipubkeybitstring=None, skipubkeybitstring=None, nsURL="https://www.github.com/MiwCryptoCurrency/UTXOC"):
    count = 0
    exts = rfc2459.Extensions().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))
    retval = rfc2459.Extensions()
    ## BASIC CONSTRAINTS
    ## we like basic constraints at the top. this is how openssl produces it
    bc_ext = _find_basic_contraints(extensionsfromcsr)
    if (bc_ext):
        ext = _build_extensionFromAttributeExtension(bc_ext)
        exts.setComponentByPosition(count, ext)
        count += 1
    ## SKI
    if skipubkeybitstring:
        ## tricky - SKI is a hash (keyid).
        ## rfc 5280 says use SHA1 of the raw bytes of the pubkey, dont encode as asn1 DER (ie: OctetString())
        ## SKI is stored in an encoded OctetString()
        skider = bytearray(utility.bitStringtoOctetString(skipubkeybitstring))
        #skihashfunction = SHA.new(skider)
        skihashfunction = SHA256.new(skider)
        skidgst = skihashfunction.digest()
        extval = univ.OctetString(skidgst)
        encapsulated = univ.OctetString(encoder.encode(extval))
        extoid = utility.OID_subjectKeyIdentifier
        ext = rfc2314.Extension()
        ext.setComponentByName('extnID', extoid)
        ext.setComponentByName('extnValue', encapsulated)
        exts.setComponentByPosition(count, ext)
        count += 1
    ## AKI
    if akipubkeybitstring:
        ## tricky - AKI can be a DN or a keyid. Use KeyID
        ## rfc 5280 says use SHA1 of the raw bytes of the pubkey, dont encode as asn1 DER (ie: OctetString())
        ## AKI is stored in a SEQ
        akider = bytearray(utility.bitStringtoOctetString(akipubkeybitstring))
        #akihashfunction = SHA.new(akider)
        akihashfunction = SHA256.new(akider)
        akidgst = akihashfunction.digest()
        extval = rfc2459.AuthorityKeyIdentifier()
        extval.setComponentByPosition(0, akidgst)
        encapsulated = univ.OctetString(encoder.encode(extval))
        extoid = utility.OID_authorityKeyIdentifier
        ext = rfc2314.Extension()
        ext.setComponentByName('extnID', extoid)
        ext.setComponentByName('extnValue', encapsulated)
        exts.setComponentByPosition(count, ext)
        count += 1
    
    ## put a few more in, so it looks all proper-like
    ## KEY USAGE
    ## a bitstring of:
    ## (1,1,1,1,1,1,1,1)= flags:
    ## Digital Signature, Non Repudiation, Key Encipherment, Data Encipherment, Key Agreement,
    ## Certificate Sign, CRL Sign, Encipher Only
    ## (1,1,1,0,0,1,1) = Digital Signature, Non Repudiation, Key Encipherment, Certificate Sign, CRL Sign
    ku_bitstring = (1,1,1,0,0,1,1)
    ext_ku = _build_key_usage(ku_bitstring)


    ## EXTENDED (or ENHANCED) KEY USAGE
    ## Sequence of OIDs encoded as an OctetString
    req_ekus = (
            utility.OID_eku_serverAuth,
            utility.OID_eku_clientAuth,
            utility.OID_eku_codeSigning,
            utility.OID_eku_individualCodeSigning,
            utility.OID_eku_certTrustListSigning,
            utility.OID_eku_serverGatedCrypto,
            utility.OID_eku_encryptedFileSystem,
            utility.OID_eku_serverGatedCrypto
            )
    ext_eku = _build_extended_key_usage(req_ekus)
    ext_nsurl = _build_extension_netscapeURL(nsURL)
    
    if (ext_ku):
        exts.setComponentByPosition(count, ext_ku)
        count += 1
    if (ext_eku):
        exts.setComponentByPosition(count, ext_eku)
        count += 1
    if (ext_nsurl):
        exts.setComponentByPosition(count, ext_nsurl)
        count += 1

    ## cycle through the rest of the requested extensions
    ## copy them as is, ignoring BC which we grabbed earlier
    ## also skip the supplied ku and eku and subst our own
    for extension in extensionsfromcsr:
        extoid = extension[0]
        if (extoid == utility.OID_basicConstraints):
            continue
        if (extoid == utility.OID_eku):
            continue
        if (extoid == utility.OID_ku):
            continue
        if (extoid == utility.OID_san):
            if not _validate_san(extension):
                raise SANValidationException("Invalid SAN: does not contain valid address or UTXO") 
        ext = _build_extensionFromAttributeExtension(extension)
        exts.setComponentByPosition(count, ext)
        count += 1
    return exts

def _build_tbs(csr, days, network):
    cri = csr.getComponentByName('certificationRequestInfo')
    subject = cri.getComponentByName('subject')
    subjectPublicKeyInfo = cri.getComponentByName('subjectPublicKeyInfo')
    dt_now = datetime.datetime.utcnow()
    later = datetime.timedelta(days=days)
    dt_now_str = dt_now.strftime("%y%m%d%H%M%S") + "Z"
    later_str = (dt_now + later).strftime("%y%m%d%H%M%S") + "Z"
    notbefore = useful.UTCTime(dt_now_str)
    notafter = useful.UTCTime(later_str)
    validity = rfc2459.Validity()
    validity.setComponentByName('notBefore', notbefore)
    validity.setComponentByName('notAfter', notafter)
    tbs = rfc2459.TBSCertificate()
    tbs.setComponentByName('version', rfc2459.Version('v3').subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)))
    rndfile = Random.new()
    serial = encoding.to_long(256, encoding.byte_to_int, rndfile.read(32))[0]
    tbs.setComponentByName('serialNumber', rfc2459.CertificateSerialNumber(univ.Integer(serial)))
    tbs.setComponentByName('signature', csr.getComponentByName('signatureAlgorithm'))
    tbs.setComponentByName('issuer', subject)
    tbs.setComponentByName('validity', validity)
    tbs.setComponentByName('subject', subject)
    tbs.setComponentByName('subjectPublicKeyInfo', subjectPublicKeyInfo)
    extensionstoadd = ""
    attributes = cri.getComponentByName('attributes')
    for attribute in attributes:
        if (attribute.getComponentByName('type') == utility.OID_PKCShash9ExtensionRequest):
            value = attribute[1]
            ## careful with decoder, it returns an implicit type in a tuple
            extensionstoadd = decoder.decode(value[0])[0]
    spk = subjectPublicKeyInfo.getComponentByName('subjectPublicKey')
    ## self siiiigned
    extensions = _build_extensionsForTbs(extensionstoadd, akipubkeybitstring=spk, skipubkeybitstring=spk)
    if extensions:
        tbs.setComponentByName('extensions', extensions)
    return tbs




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


def _build_signature(key, tbs, network):
    ''' Takes a utility.ECPrivateKey() as key, tbs as rfc2459.TBSCertificate, and network as pycoin.NETWORK_NAMES
    '''
    secret_exponent = encoding.to_long(256, encoding.byte_to_int, key[0][1].asOctets())[0]
    coin  = Key(secret_exponent=secret_exponent, netcode=network)
    public_pair = coin.public_pair()
    coin_address = coin.address()
    print "building signature for %s address %s" % (network, coin_address)
    pubkeybitstring = (key[0].getComponentByPosition(2), key[0].getComponentByPosition(3))
    tbsder = encoder.encode(tbs)
    hashvalue = SHA256.new(tbsder)
    dgst = hashvalue.digest()
    dgstaslong = encoding.to_long(256, encoding.byte_to_int, dgst)[0]
    order2 = pycoin.ecdsa.generator_secp256k1.order()
    ## random sign
    generator = pycoin.ecdsa.generator_secp256k1
    rawsig2 = randomsign(generator, secret_exponent, dgstaslong)
    # deterministic sign
    ##rawsig2 = pycoin.ecdsa.sign(pycoin.ecdsa.generator_secp256k1, secret_exponent, dgstaslong)
    r2, s2 = rawsig2
    print "signature: r: %x s: %x" % (r2, s2)
    if not pycoin.ecdsa.verify(generator, coin.public_pair(), dgstaslong, rawsig2):
        raise SignatureVerifyException("Generated signature r: %x s: %x does not verify against public key %s" % (r2, s2, public_pair))
    signature = utility.ECDSASigValue()
    signature.setComponentByName('r', r2)
    signature.setComponentByName('s', s2)
    dersig = encoder.encode(signature)
    signaturevalue = "'{0}'H".format(binascii.hexlify(dersig))
    bitstring = univ.BitString( value=signaturevalue )
    return rfc2314.Signature( bitstring )

def main():
    parser = argparse.ArgumentParser(
        description='utxocsr.py by MiWCryptoCurrency for UTXOC UTXO based certificate signing (to produce PEM encoded).'
    )
    parser.add_argument('-k', '--key', required=True, type=argparse.FileType('r'), help='Private EC Key')
    parser.add_argument('-c', '--csrfilename', required=True, type=argparse.FileType('r'), help='Input CSR Filename')
    parser.add_argument('-f', '--certfilename', required=True, type=argparse.FileType('w'), help='Output UTXOC Filename')
    parser.add_argument('-n', "--network", help='specify network (default: BTC = Bitcoin)',
                               default='BTC', choices=NETWORK_NAMES)
    parser.add_argument('-r', "--redemption", required=False, help='redemption address (to claim after expiry)')
    
    parser.add_argument('-d', "--days", required=False, help='number of days to hold Bond (certificate validity period). Suggested >365')
    inputkey=""
    inputcsr=""
    args = parser.parse_args()
    network = args.network
    days = 365
    if args.days:
        days = args.days
    csrfilename = args.csrfilename
    while True:
            line = args.key.readline().strip()
            if not line: break
            inputkey+= line + '\n'
    parsed_key = decoder.decode(utility.read_ec_private_pem(inputkey), asn1Spec=utility.ECPrivateKey())
    secret_exponent = encoding.to_long(256, encoding.byte_to_int, parsed_key[0][1].asOctets())[0]
    #coin  = Key(secret_exponent=secret_exponent, netcode=network)
    #pubaddr = coin.address(use_uncompressed=False)
    while True:
            line = args.csrfilename.readline().strip()
            if not line: break
            inputcsr+= line + '\n'
    parsed_csr = decoder.decode(utility.read_csr_pem(inputcsr), asn1Spec=rfc2314.CertificationRequest())
    tbs = _build_tbs(parsed_csr[0], days, network)
    certificate = rfc2459.Certificate()
    certificate.setComponentByName('tbsCertificate', tbs)
    certificate.setComponentByName('signatureAlgorithm', _build_ECDSAwithSHA256_signatureAlgorithm())
    certificate.setComponentByName('signatureValue', _build_signature(parsed_key, tbs, network))
    certder = encoder.encode(certificate)
    certpem = utility.generate_certificate_pem(certder)
    args.certfilename.write(certpem)
    print certpem
    return


if __name__ == "__main__":
    main()
