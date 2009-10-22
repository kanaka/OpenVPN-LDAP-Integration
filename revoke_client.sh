#!/bin/bash

# Revoke a client certificate/key.
#
# Written by Joel Martin <joel_martin@sil.org>
#
# Requirements:
#   - openvpn package: revoke-full and openssl.cnf ('easy-rsa/2.0' dir)
#   - root certificate authority files (ca.crt, ca.key) in keys dir

VERBOSE=${VERBOSE:-}

# Utility routines
die() { echo >&2 -e "$*"; exit 1; }
vecho() { [ "${VERBOSE}" ] && echo "$*"; }
usage() {
    echo >&2 "$*"
    echo >&2
    echo >&2 "Usage: ${NAME} [-v] [-D SCP_Dest] first_last"
    echo >&2 "  -v          verbose output"
    echo >&2 "  -D SCP_Dest scp crl file to this location"
    echo >&2 "  first_last  name to revoke"
    die
}

# returns 0 for 'yes' or 1 for 'no'
yesno() {
    local answer=
    [ "${NOASK}" ] && echo "$* y" && return 0
    while read -p "$*" answer; do
        case ${answer} in
            y|yes|Y|Yes|YES) return 0 ;;
            n|no|N|No|NO) return 1 ;;
            *) echo "Eh?"; answer= ;;
        esac
    done
}


# Derive some settings
top=$(readlink -f $(dirname ${0}))
findssl=$(ls -d /usr/share/doc/openvpn*/{,*/}easy-rsa/2.0/ 2>/dev/null |tail -n1)
REVOKETOOL=${REVOKETOOL:-${findssl}/revoke-full}
SSL_CONF=${SSL_CONF:-${findssl}/openssl.cnf}
SCP_DEST=${SCP_DEST:-jonesrb@172.21.1.19:/etc/openvpn/Dallas_OpenVPN_CA.crl}

# Process command line parameters
params="$*"
while [ "$*" ]; do
    param=$1; shift; OPTARG=$1
    case $param in
    -v|--verbose) VERBOSE="-v" ;;
    -D)           SCP_DEST="${OPTARG}"; shift ;;
    -*)           die "Unknown paramter $param" ;;
    *)            [ "${name}" ] && usage || name=${param} ;;
    esac
done


# Sanity checks
[ "${REVOKETOOL}" ] || die "Could not find revoke-full"
[ "${SSL_CONF}" ] || die "Could not find openssl.cnf"
[ -d "${top}" ] || die "Could not find ${top}"
[ "${name}" ] || usage "You must specify a client name"
#[ "${name/_/}" != "${name}" ] || usage "Name must be 'first_last'"


# Export variables needed by the pkitool program. These would
# traditionally be set by first sourcing the 'easy-rsa/vars' file.
export KEY_DIR="${KEY_DIR:-${top}/keys/}"
export KEY_CONFIG="${SSL_CONF}"
export KEY_SIZE=1024
export KEY_EXPIRE=730  # 2 years
export KEY_CITY="DALLAS"
export KEY_PROVINCE="TX"
export KEY_COUNTRY="US"
export KEY_ORG="SIL"
export KEY_EMAIL="${name}@example.com"
export OPENSSL=${OPENSSL:-openssl}
export PKCS11_MODULE_PATH=   # Not used, but openssl wants it set
export PKCS11_PIN=           # Not used, but openssl wants it set

# Output settings if verbose output requested
vecho "top:          ${top}"
vecho "name:         ${name}"
vecho "REVOKETOOL:   ${REVOKETOOL}"
vecho "SSL_CONF:     ${SSL_CONF}"
vecho "SCP_DEST:     ${SCP_DEST}"
vecho "KEY_DIR:      ${KEY_DIR}"
vecho "KEY_CONFIG:   ${KEY_CONFIG}"
vecho "KEY_SIZE:     ${KEY_SIZE}"
vecho "KEY_EXPIRE:   ${KEY_EXPIRE}"
vecho "KEY_CITY:     ${KEY_CITY}"
vecho "KEY_PROVINCE: ${KEY_PROVINCE}"
vecho "KEY_COUNTRY:  ${KEY_COUNTRY}"
vecho "KEY_ORG:      ${KEY_ORG}"
vecho "KEY_EMAIL:    ${KEY_EMAIL}"
vecho "OPENSSL:      ${OPENSSL}"

echo "*** Add to CRL:  ${name}"
echo "*** Copy CRL to: ${SCP_DEST}"
yesno "Continue (y/n)? " || die

# Make sure the key directory is sane
[ -d "${KEY_DIR}" ] || die "Keys directory '${KEY_DIR}' does not exist"
chmod -R go-rwx "${KEY_DIR}" || die "Failed to fix permissions on ${KEY_DIR}"
[ -e ${KEY_DIR}/index.txt ] || die "${KEY_DIR}/index.txt must exist"
#if [ ! -e ${KEY_DIR}/serial ]; then
#    echo "01" > ${KEY_DIR}/serial || die "Failed to create ${KEY_DIR}/serial"
#fi


# Update the certificate revocation list file with the key/cert for
# the named user.

echo -e "\n>>> Updating revoke list with ${name}"
vecho "${REVOKETOOL} ${name}"
if [ "${VERBOSE}" ]; then
    ${REVOKETOOL} ${name} || die "${REVOKETOOL} failed"
else
    ${REVOKETOOL} ${name} &>/dev/null || die "${REVOKETOOL} failed"
fi

# TODO: copy the revoke key to the server
echo scp ${KEY_DIR}/crl.pem ${SCP_DEST}
scp ${KEY_DIR}/crl.pem ${SCP_DEST}
