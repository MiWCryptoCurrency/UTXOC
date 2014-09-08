## utility methods for utxocsr and utxocsign

from pyasn1.type import univ, namedtype, namedval, constraint, tag
from bitstring import BitArray, BitStream

OID_SECP256K1 = univ.ObjectIdentifier('1.3.132.0.10')
OID_ecdsaWithSHA256 = univ.ObjectIdentifier('1.2.840.10045.4.3.2')
OID_idEcPublicKey = univ.ObjectIdentifier("1.2.840.10045.2.1")
OID_PKCS9_EXT_REQUEST= univ.ObjectIdentifier('1.2.840.113549.1.9.14')
OID_PKCShash9ExtensionRequest = univ.ObjectIdentifier('1.2.840.113549.1.9.14')


# id-ce == 2.5.29 OIDS
OID_subjectKeyIdentifier = univ.ObjectIdentifier('2.5.29.14')
OID_ku = univ.ObjectIdentifier('2.5.29.15')
OID_san = univ.ObjectIdentifier('2.5.29.17')
OID_basicConstraints = univ.ObjectIdentifier('2.5.29.19')
OID_cRLDistributionPoints = univ.ObjectIdentifier('2.5.29.31')
OID_authorityKeyIdentifier = univ.ObjectIdentifier('2.5.29.35')
OID_eku = univ.ObjectIdentifier('2.5.29.37')
OID_certificatePolicies = univ.ObjectIdentifier('2.5.29.32')


# ekus
OID_eku_serverAuth = univ.ObjectIdentifier("1.3.6.1.5.5.7.3.1")
OID_eku_clientAuth = univ.ObjectIdentifier("1.3.6.1.5.5.7.3.2")
OID_eku_codeSigning = univ.ObjectIdentifier("1.3.6.1.5.5.7.3.3")
OID_eku_individualCodeSigning = univ.ObjectIdentifier("1.3.6.1.4.1.311.2.1.21")
OID_eku_certTrustListSigning = univ.ObjectIdentifier("1.3.6.1.4.1.311.10.3.1")
OID_eku_serverGatedCrypto = univ.ObjectIdentifier("1.3.6.1.4.1.311.10.3.3")
OID_eku_encryptedFileSystem = univ.ObjectIdentifier("1.3.6.1.4.1.311.10.3.4")
OID_eku_serverGatedCrypto = univ.ObjectIdentifier("2.16.840.1.113730.4.1")


# netscape oids == 2 16 840 1113730 1 2
OID_ns_netscape_base_url = univ.ObjectIdentifier('2.16.840.1.113730.1.2')

def generate_certificate_pem(inputder):
    ''' takes binary der data and turns it PEM
    '''
    data = ""
    data+=('-----BEGIN CERTIFICATE-----\n')
    data+=inputder.encode('base64')
    data+=('-----END CERTIFICATE-----\n')
    return data

def read_ec_private_pem(inputpem):
    """Read PEM formatted input."""
    data = []
    state = 0
    for line in inputpem.split('\n'):
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

def read_csr_pem(input):
    """Read PEM formatted input."""
    data = []
    state = 0
    for line in input.split('\n'):
        line.split('\n')
        if state == 0:
            if line.startswith('-----BEGIN CERTIFICATE REQUEST'):
                state = 1
        elif state == 1:
            if line.startswith('-----END CERTIFICATE REQUEST'):
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
