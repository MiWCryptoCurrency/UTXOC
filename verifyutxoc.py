## verifyutxoc.py py by MiWCryptoCurrency for UTXO based Certificates UTXOC 'you chi ock'
## CC BY-SA 3.0
##
## Use this script to verify that a UTXOC is valid against a 3rd party blockchain provider
##
## Uses code from https://github.com/jandd/python-pkiutils/blob/master/pkiutils/__init__.py pure python pkiutils
## http://www.ietf.org/rfc/rfc5480.txt is your friend (EC public key format)
## also RFC3279 http://www.ietf.org/rfc/rfc3279.txt
##
## Master RFC for RFC http://tools.ietf.org/html/rfc5912
## RFC 2459 - x509 certificates (RSA/DSA)
## RFC 5280 - x509 certificates (ECDSA)
## 
## also Standards in Efficent Cryptography SEC 1: Elliptic Curve Cryptography has useful bits on bitstring to octetstring in 2.3.3


import utility
import sys
import pycoin
import datetime
import time
import calendar
import argparse
from pyasn1.codec.der import encoder, decoder
from pyasn1.type import univ, namedtype, namedval, constraint, tag, useful
from Crypto.Hash import SHA256
from pycoin.serialize import b2h, h2b
from pycoin.key import Key
from pycoin.networks import full_network_name_for_netcode, NETWORK_NAMES
from pycoin.ecdsa.secp256k1 import generator_secp256k1
from pycoin.encoding import from_long, from_bytes_32, byte_to_int
import binascii
from bitstring import BitArray, BitStream
from pycoin import encoding
from math import ceil, log
from pyasn1_modules import rfc2459
import requests
import json


#globals!
trusted_signer_list = {}

## fun with oids
OID_SECP256K1 = univ.ObjectIdentifier("1.3.132.0.10")
OID_ecdsaWithSHA256 = univ.ObjectIdentifier("1.2.840.10045.4.3.2")
OID_idEcPublicKey = univ.ObjectIdentifier("1.2.840.10045.2.1")
OID_PKCS9_EXT_REQUEST= univ.ObjectIdentifier('1.2.840.113549.1.9.14')
OID_eku = univ.ObjectIdentifier('2.5.29.37')
OID_san = univ.ObjectIdentifier('2.5.29.17')

OID_x520_DN_commonName = univ.ObjectIdentifier('2.5.4.3')
OID_x520_DN_surName = univ.ObjectIdentifier('2.5.4.4')
OID_x520_DN_deviceSerialNumber = univ.ObjectIdentifier('2.5.4.5')
OID_x520_DN_countryName = univ.ObjectIdentifier('2.5.4.6')
OID_x520_DN_localityName= univ.ObjectIdentifier('2.5.4.7')
OID_x520_DN_stateOrProvinceName= univ.ObjectIdentifier('2.5.4.8')
OID_x520_DN_streetAddress = univ.ObjectIdentifier('2.5.4.9')
OID_x520_DN_organizationName = univ.ObjectIdentifier('2.5.4.10')
OID_x520_DN_organizationalUnitName = univ.ObjectIdentifier('2.5.4.11')
OID_x520_DN_title = univ.ObjectIdentifier('2.5.4.12')
OID_x520_DN_givenName = univ.ObjectIdentifier('2.5.4.42')
OID_x520_DN_initials = univ.ObjectIdentifier('2.5.4.42')


def read_pem(input):
    """Read PEM formatted input."""
    data = []
    state = 0
    for line in input.split('\n'):
        line.split('\n')
        if state == 0:
            if line.startswith('-----BEGIN CERTIFICATE'):
                state = 1
        elif state == 1:
            if line.startswith('-----END CERTIFICATE'):
                state = 2
            else:
                data.append(line)
        elif state == 2:
            break
    if state != 2:
        raise ValueError, 'No PEM encoded certificate input found'
    data = ''.join(data)
    data = data.decode('base64')
    return data


## Validity ::= SEQUENCE {
##        notBefore      Time,
##        notAfter       Time }
##
##   Time ::= CHOICE {
##        utcTime        UTCTime,
##        generalTime    GeneralizedTime }
##   

##   CertificateSerialNumber  ::=  INTEGER
##    Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }

## AlgorithmIdentifier  ::=  SEQUENCE  {
##        algorithm   OBJECT IDENTIFIER,
##        parameters  ANY DEFINED BY algorithm OPTIONAL
##  }
##
##
##    



class AlgorithmIdentifier(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('algorithm', univ.ObjectIdentifier()),
        namedtype.OptionalNamedType('parameters', univ.Any())
        )



class SubjectPublicKeyInfo(univ.Sequence):
     componentType = namedtype.NamedTypes(
         namedtype.NamedType('algorithm', AlgorithmIdentifier()),
         namedtype.NamedType('subjectPublicKey', univ.BitString())
     )

##   TBSCertificate  ::=  SEQUENCE  {
##        version         [0]  EXPLICIT Version DEFAULT v1,
##        serialNumber         CertificateSerialNumber,
##        signature            AlgorithmIdentifier,
##        issuer               Name,
##        validity             Validity,
##        subject              Name,
##        subjectPublicKeyInfo SubjectPublicKeyInfo,
##        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
##                             -- If present, version MUST be v2 or v3
##        subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
##                             -- If present, version MUST be v2 or v3
##        extensions      [3]  EXPLICIT Extensions OPTIONAL
##                             -- If present, version MUST be v3
##        }
##

##
##
## http://pydoc.net/Python/pyasn1-modules/0.0.2/pyasn1_modules.rfc2459/

class TBSCertificate(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.DefaultedNamedType('version', rfc2459.Version('v1', tagSet=rfc2459.Version.tagSet.tagExplicitly(tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)))),
        namedtype.NamedType('serialNumber', rfc2459.CertificateSerialNumber()),
        namedtype.NamedType('signature', AlgorithmIdentifier()),
        namedtype.NamedType('issuer', rfc2459.Name()),
        namedtype.NamedType('validity', rfc2459.Validity()),
        namedtype.NamedType('subject', rfc2459.Name()),
        namedtype.NamedType('subjectPublicKeyInfo', SubjectPublicKeyInfo()),
        namedtype.OptionalNamedType('issuerUniqueID', rfc2459.UniqueIdentifier().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
        namedtype.OptionalNamedType('subjectUniqueID', rfc2459.UniqueIdentifier().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))),
        namedtype.OptionalNamedType('extensions', rfc2459.Extensions().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)))
        )
    
#
# Certificate  ::=  SEQUENCE  {
#        tbsCertificate       TBSCertificate,
#        signatureAlgorithm   AlgorithmIdentifier,
#        signatureValue       BIT STRING  }

class ECCertificate(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('tbsCertificate', TBSCertificate()),
        namedtype.NamedType('signatureAlgorithm', AlgorithmIdentifier()),
        namedtype.NamedType('signatureValue', univ.BitString())
        )


# SEC1 2.3.1
def bitStringtoOctetString(binstring):
    # input a bitstring of length blen bits
    # output an octet string M of length mlen=[blen/8] octets
    blen = len(binstring)
    mlen = blen/8
    m = []
    # Step One
    for i in range(0, mlen):
        m_i = []
        for j in range(8, 0, -1):
            mround = binstring[blen-j-8*(mlen-1-i)]
            m_i.append(mround)
        m.append(m_i)
    # step 2
    m0ff = 8*mlen-blen
    for i in range(0, m0ff):
        m[0][i] = 0
    m0ff = 8-(8*mlen-blen)
    for i in range(m0ff, 0, -1):
        m[0][i-1] = binstring[i-1]
    # step 3
    # output as octet array
    for i in range(0, len(m)):
        m[i] = BitArray(m[i]).bytes
    return m

# SEC1 2.3.4
def octetStringtoEllipticCurvePoint(generator, octetstring):
    ## returns a curve point P = (x,y) either P = O, P = (x0,y0) or (None, None)
    ## currently does not support compressed curve points, todo
    q = generator.curve().p()
    o_mlen = len(octetstring)
    o_csize = int(ceil(log(q, 2)/8) + 1)
    o_usize = int(2 * ceil(log(q, 2)/8) + 1)
    if (octetstring == '\x00'):
        return (0,0)
    if (o_mlen == o_usize):
        coord_size = int(ceil(log(q, 2)/8))
        w = octetstring[0]
        x = octetstring[1:coord_size+1]
        y = octetstring[coord_size+1:]
        if not (w=='\x04'):
            print "invalid Octet String for Elliptic Curve Point"
            return None
        pair = (octetStringtoInteger(x), octetStringtoInteger(y))
        if (generator.curve().contains_point(pair[0], pair[1])):
            return pair
    return (None, None)


## should use EC 2.3.8
def octetStringtoInteger(octetstring):
    ## use pycoin.encoding to translate for now
    return from_bytes_32(octetstring)



def checkCurveSecp256k1(subjectpublickeyinfo):
    certalgo = subjectpublickeyinfo.getComponentByName("algorithm")
    if (certalgo[0] != OID_idEcPublicKey):
        print "Certificate does not contain an EC public key! :-("
        return False
    certcurve = decoder.decode(certalgo[1].asOctets())[0]
    if (certcurve != OID_SECP256K1):
        print "Certificate does not contain a public key over secp256k1; cannot be a UTXO Certificate! :-("
        return False
    else:
        return True
    

def subjectPublicKeyInfoToPublicPair(subjectpublickeyinfo):
    ## returns a long tuple containing public pair
    
    certpublickey = subjectpublickeyinfo.getComponentByName("subjectPublicKey")
    if not checkCurveSecp256k1(subjectpublickeyinfo):
        return None
    
    pubkey = utility.bitStringtoOctetString(certpublickey)
    hstr = ""
    for hchar in pubkey:
        hstr+=binascii.hexlify(hchar)
    if (pubkey[0]== '\x02') | (pubkey[0]== '\x03') :
        print "Compressed Public Key not supported right now, sorry! :-("
        return None
    elif (pubkey[0]=='\x04'):
        return octetStringtoEllipticCurvePoint(generator_secp256k1, pubkey)
    else:
        print "Unknown PublicKey format. :-("
        return None

def subjectDnToString(dn):
    returnstring = ""
    for rdnseq in dn[0]:
        for rdn in rdnseq:
            componenttype = rdn.getComponentByName('type')
            componentvalue = rdn.getComponentByName('value')
            value = decoder.decode(componentvalue)[0]
            returnstring+= "/"
            if componenttype == OID_x520_DN_commonName:
                returnstring+="CN=%s" % value
            elif componenttype == OID_x520_DN_surName:
                returnstring+="S=%s" % value
            elif componenttype == OID_x520_DN_countryName:
                returnstring+="C=%s" % value
            elif componenttype == OID_x520_DN_localityName:
                returnstring+="L=%s" % value
            elif componenttype == OID_x520_DN_stateOrProvinceName:
                returnstring+="ST=%s" % value
            elif componenttype == OID_x520_DN_streetAddress:
                returnstring+="STREET=%s" % value
            elif componenttype == OID_x520_DN_organizationName:
                returnstring+="O=%s" % value
            elif componenttype == OID_x520_DN_organizationalUnitName:
                returnstring+="OU=%s" % value
            elif componenttype == OID_x520_DN_title:
                returnstring+="T=%s" % value
            elif componenttype == OID_x520_DN_givenName:
                returnstring+="GN=%s" % value
            elif componenttype == OID_x520_DN_initials:
                returnstring+="I=%s" % value    
    return returnstring


def build_trusted_signer_list():
    ## generate trusted signer list from teh local database
    ## the shiny one. the list that everyone wants to be on.
    ## more exclusive than a mensa club 33 member with a black amex
    with open("UTXOC.signer.list") as openfileobject:
        signer_cert = ""
        for line in openfileobject:
            if "BEGIN CERTIFICATE" in line:
                signer_cert = line
            else:
                signer_cert += line
            if "END CERTIFICATE" in line:
                signer_cert = decoder.decode(read_pem(signer_cert), ECCertificate() )[0]
                signer_subject = signer_cert.getComponentByName("tbsCertificate").getComponentByName('subject')
                signer_public_pair = subjectPublicKeyInfoToPublicPair(signer_cert.getComponentByName("tbsCertificate").getComponentByName('subjectPublicKeyInfo'))
                trusted_signer_list[subjectDnToString(signer_subject)] = signer_public_pair
                signer_cert = ""



def checkChainSoUTXO(netcode, coinaddress, txid):
    ## use chain.so for lookup
        ## the get_tx_unspent simply returns unspent transactions for our address
        ## if one of them is the txid hash in our cert, it must be unspent!
        found_chainso_utxo = False
        value = 0
        r = requests.get('https://chain.so/api/v2/get_tx_unspent/%s/%s' % (netcode, coinaddress))
        if (r.status_code == 500):
            print r.text
            return
        if (r.status_code == 200):
            get_tx_unspent_json = r.json()
            txjson = get_tx_unspent_json['data']['txs']
            for tx in txjson:
                chainso_txid = tx['txid']
                chainso_time = tx['time']
                chainso_value = tx['value']
                ## check the txhash matches the cert
                if (chainso_txid == txid):
                    found_chainso_utxo = True
                    print "TX %s worth %s from %s remains unspent" % (chainso_txid, chainso_value, chainso_time)
                    break
        return found_chainso_utxo


def checkBlockchainInfoUTXO(coinaddress, txid):
    r = requests.get('https://blockchain.info/rawtx/%s' % txid)
    if (r.status_code == 500):
        print r.text
        if (r.text == "Transaction not found"):
            print "Certificate transaction not found in the blockchain"
        return False
    elif (r.status_code == 200):
        txjson = r.json()
        tx_index = txjson["tx_index"]
        txhash = txjson["hash"]
        txtime = txjson["time"]
        txout = txjson["out"]
        txblock = txjson["block_height"]
        ## check the txhash matches the cert
        ## (this is validating the json data more than anything, 
        if not (txhash == txid):
            print "hash in json data does not match hash in certificate!"
            return False
        ## check the outputs
        for txo in txout:
            ## check out output is for the address in the SAN
            if not (txo['addr'] == coinaddress):
                continue
            ## is it unspent? blockchain.info "spent" == false means unspent
            if (txo['spent'] == True):
                print "TX is spent! Certificate invalid!"
                return False
            else:
                print "TX %s from block %s from %s remains unspent. " % (txid, txblock, txtime)
                return True
    # we didnt find the tx in the returned data
    return False

def main():
    parser = argparse.ArgumentParser(
        description='verifyutxoc.py by MiWCryptoCurrency for UTXOC UTXO based certificate verify'
    )
    parser.add_argument('-f', '--filename', required=True, type=argparse.FileType('r'), help='Input UTXOC Filename')
    parser.add_argument('-n', "--network", help='specify network (default: BTC = Bitcoin)',
                               default='BTC', choices=NETWORK_NAMES)
    args = parser.parse_args()
    network = args.network
    inputcert = ""
    while True:
            line = args.filename.readline()
            if not line: break
            inputcert += line
    parsedcert = None
    try:
        parsedcert = decoder.decode(read_pem(inputcert), ECCertificate() )[0]
    except:
        print "Problem parsing certificate. Is input x509 Elliptic Curve certificate?"
        return
    
    ###############################
    ## Check 1 - Is the current date and time within the validity period of the certificate?
    print "-- Check 1: Date validity--"
    tbs = parsedcert.getComponentByName("tbsCertificate")
    validity = tbs.getComponentByName("validity")
    validityperiod = (validity.getComponentByName("notBefore")[0], validity.getComponentByName("notAfter")[0])
    dt_now = datetime.datetime.utcnow()
    notbefore = str(validityperiod[0][:12])
    notafter =  str(validityperiod[1][:12])
    ## this should work for UTCtime, GeneralTime is YYYY so fix this near the year 2050
    dt_notbefore = datetime.datetime(2000 + int(notbefore[0:2]), int(notbefore[2:4]), int(notbefore[4:6]), int(notbefore[6:8]), int(notbefore[8:10]), int(notbefore[10:12]))
    dt_notafter = datetime.datetime(2000 + int(notafter[0:2]), int(notafter[2:4]), int(notafter[4:6]), int(notafter[6:8]), int(notafter[8:10]), int(notafter[10:12]))
    timetoexpire = dt_notafter - dt_now
    if ( dt_now < dt_notbefore ):
        print "This certificate is not yet valid. Please wait until validity period has started in %s" % timetoexpire
        return
    elif ( dt_now > dt_notafter ):
        print "This certificate has expired %s ago. Please claim any unspent transactions and migrate value to another address" % timetoexpire
        return
    print "Certificate will expire on: %s, which is in %s" % (dt_notafter, timetoexpire)
    print "The date notBefore and notAfter validity checks passed. OK!" 

    
    
    ###############################
    ## Check 2 -- is the public key valid to be used in cryptocurrency? does it match the coin address generated from the public key?
    print "-- Check 2: Public Key --"
    print "--- Check 2.1 : Public Key over secp256k1  ---"
    subjectpublickeyinfo = tbs.getComponentByName("subjectPublicKeyInfo")
    if checkCurveSecp256k1(subjectpublickeyinfo):
        print "Certificate contains EC public key over curve secp256k1 OK!"
    else:
        return
    public_pair = subjectPublicKeyInfoToPublicPair(subjectpublickeyinfo)
    if not public_pair:
        print "Problem with getting public pair from certificate :-("
        return
    print "Public Key is point (%d %d) on curve secp256k1" % public_pair
    print "--- Check 2.2 Comparing coin address in SAN to public key in cert ----"
    extentions = tbs.getComponentByName('extensions')
    ## the tx should be in the extensions somewhere.
    ## we also work out the netcode for pycoin here
    ## currently the last SAN with a coin address will win
    ## as multiple URI for cointype is not supported at this stage
    txid = None
    netcode = None
    for extension in extentions:
        oid = extension.getComponentByName('extnID')
        if (oid != OID_san):
            continue
        value = decoder.decode(extension.getComponentByName('extnValue'), asn1Spec=univ.OctetString())[0]
        sans = decoder.decode(value, asn1Spec=rfc2459.SubjectAltName())[0]
        for san in sans:
            santype = san.getName()
            if santype == 'dNSName':
                print "Cert is for DNS name: %s" % san.getComponent()
            elif santype == 'uniformResourceIdentifier':
                sanuri = san.getComponent().asOctets()
                if sanuri.startswith('bitcoin:'):
                    netcode = 'BTC'
                    coinuri = sanuri[8:].split('?')
                    coinaddress = coinuri[0]
                    coinparams = coinuri[1].split('&')
                    for coinparam in coinparams:
                        if coinparam.startswith("transaction="):
                            txid = coinparam.split('=')[1]
                elif sanuri.startswith('dogecoin:'):
                    netcode = 'DOGE'
                    coinuri = sanuri[9:].split('?')
                    coinaddress = coinuri[0]
                    coinparams = coinuri[1].split('&')
                    for coinparam in coinparams:
                        if coinparam.startswith("transaction="):
                            txid = coinparam.split('=')[1]
                elif sanuri.startswith('litecoin:'):
                    netcode = 'LTC'
                    coinuri = sanuri[9:].split('?')
                    coinaddress = coinuri[0]
                    coinparams = coinuri[1].split('&')
                    for coinparam in coinparams:
                        if coinparam.startswith("transaction="):
                            txid = coinparam.split('=')[1]
                elif sanuri.startswith('blackcoin:'):
                    netcode = 'BLK'
                    coinuri = sanuri[10:].split('?')
                    coinaddress = coinuri[0]
                    coinparams = coinuri[1].split('&')
                    for coinparam in coinparams:
                        if coinparam.startswith("transaction="):
                            txid = coinparam.split('=')[1]
    if not txid:
        print "No Coin address or TX found in SubjectAltName. Cannot be a UTXOC :-("
        return
    print "Found Coin Address: %s and Transaction: %s" % (coinaddress, txid)
    pycoin_key = pycoin.key.Key(public_pair=public_pair, netcode=netcode)
    if not (coinaddress == pycoin_key.address() ):
        print "Coin address does not match public key on certificate! :-("
        return
    print "Address matches subject public key. OK!"

    ###############################
    ## Is our transaction unspent? Using blockchain.info API and chain.so data API to validate Unspent.
    ## TODO should use multiple sources or wallet client, additional coins
    print "-- Check 3: Is the transaction unspent? --"
    utxo_valid = False
    ## dont forget to check the txid just in case its something malicious smuggled in through the cert and passed to requests
    ## its a SHA-256 hash so its 64 chracters
    if not (len(txid) == 64):
        print "TXID wrong size, is not a SHA-256 Hash"
        return
    ## try convert from hex, catches bad characters
    try:
        int(txid, 16)
    except:
        print "illegal characters, cannot be a SHA-256 Hash"
        return
    ## use blockchain.info for BTC
    ## use chain.so for DOGE
    ## use ??? for BLK
    ## use ??? for NMC
    if (netcode=='BTC'):
        utxo_valid = checkBlockchainInfoUTXO(coinaddress, txid)
        utxo_valid = checkChainSoUTXO(netcode, coinaddress, txid)
    elif (netcode=='DOGE') or (netcode=='LTC'):
        utxo_valid = checkChainSoUTXO(netcode, coinaddress, txid)
    else:
        print "Unsupported coin %s for 3rd party chain lookup" % netcode
        return
    # did we get a valid utxo confirmed by 3rd party?
    if utxo_valid:
        print "UTXO valid! OK!"
    else:
        print "UTXO invalid! :-("
        return

    ###############################
    ## Check 4 - Signature: If self-signed or issuer signed? Check that signature against trusted signer list
    print "-- Check 4: Signature --"
    ## check the issuer attrib
    certissuer = tbs.getComponentByName('issuer')
    print "UTXOC is Signed by: %s" % subjectDnToString(certissuer)
    certsubject = tbs.getComponentByName('subject')
    if (certissuer == certsubject):
        print "Self Signed Cert: CA or 'bond' style UTXOC"
        signer_public_pair = public_pair
    else:
        build_trusted_signer_list()
        signer_public_pair = trusted_signer_list[subjectDnToString(certissuer)]
        if not signer_public_pair:
            print "Signing Cert not found in trusted signer store"
            return
    certsigalgo = parsedcert.getComponentByName('signatureAlgorithm')
    certsigvalue = parsedcert.getComponentByName('signatureValue')
    rawsig = bitStringtoOctetString(certsigvalue)
    sigder = ""
    for hchar in rawsig:
        sigder+=hchar
    sig_pair = decoder.decode(sigder)[0]
    if not (certsigalgo[0] == OID_ecdsaWithSHA256):
        print "Certificate not signed with ecdsa-SHA256"
        return
    r = long(sig_pair[0])
    s = long(sig_pair[1])
    # generate digest of the tbs
    tbsder = encoder.encode(tbs)
    hashvalue = SHA256.new(tbsder)
    hexdgst = hashvalue.hexdigest()
    dgst = hashvalue.digest()
    dgstaslong = encoding.to_long(256, encoding.byte_to_int, dgst)[0]
    # 
    if pycoin.ecdsa.verify(generator_secp256k1, signer_public_pair, dgstaslong, (r,s)):
        print "Signature validated. OK!"
    else:
        print "Signature validation failed!"
        return
    print "------------------------------  ALL TESTS PASSED  ------------------------------"
    return
        
if __name__ == "__main__":
    main()
