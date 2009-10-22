#!/bin/bash

# Generate a client certificate/key and then build an installable
# Windows OpenVPN client package using that client cert/key.
#
# Written by Joel Martin <joel_martin@sil.org>
#
# Requirements:
#   - openvpn package: pkitool and openssl.cnf ('easy-rsa/2.0' dir)
#   - nsis package: makensis program
#   - root certificate authority files (ca.crt, ca.key) in keys dir

VERBOSE=${VERBOSE:-}

# Utility routines
die() { echo >&2 -e "$*"; exit 1; }
vecho() { [ "${VERBOSE}" ] && echo "$*"; }
usage() {
    echo >&2 "$*"
    echo
    echo >&2 "Usage: $(basename ${0}) [-v] first_last"
    echo >&2 "  -v          verbose output"
    echo >&2 "  first_last  create cert/key and NSIS package for first_last"
    die
}

# Derive some settings
top=$(readlink -f $(dirname ${0}))
findssl=$(ls -d /usr/share/doc/openvpn*/{,*/}easy-rsa/2.0/ 2>/dev/null |tail -n1)
PKITOOL=${PKITOOL:-${findssl}/pkitool}
SSL_CONF=${SSL_CONF:-${findssl}/openssl.cnf}
MAKENSIS=${MAKENSIS:-makensis}
findpkg=$(dirname ${top}/*/openvpn-gui.nsi | tail -n1)
NSIS_DIR=${NSIS_DIR:-${findpkg}}
NSIS_FILE=${NSIS_DIR}/openvpn-gui.nsi

# Process command line parameters
params="$*"
while [ "$*" ]; do
    param=$1; shift; OPTARG=$1
    case $param in
    -v|--verbose) VERBOSE="-v" ;;
    -*)           die "Unknown paramter $param" ;;
    *)            [ "${name}" ] && usage || name=${param} ;;
    esac
done

lastname=${name#*_}


# Sanity checks
[ "${PKITOOL}" ] || die "Could not find pkitool"
[ "${SSL_CONF}" ] || die "Could not find openssl.cnf"
which ${MAKENSIS} &>/dev/null || die "Could not run ${MAKENSIS}"
[ -d "${top}" ] || die "Could not find ${top}"
[ -d "${NSIS_DIR}" ] || die "Could not find openvpn NSIS directory"
[ -e "${NSIS_FILE}" ] || die "Could not find openvpn-gui.nsi"
[ "${name}" ] || usage "You must specify a client name"
[ "${name/_/}" != "${name}" ] || usage "Name must be 'first_last'"


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

# Output settings if verbose output requested
vecho "top:          ${top}"
vecho "name:         ${name}"
vecho "PKITOOL:      ${PKITOOL}"
vecho "NSIS_DIR:     ${NSIS_DIR}"
vecho "NSIS_FILE:    ${NSIS_FILE}"
vecho "KEY_DIR:      ${KEY_DIR}"
vecho "KEY_CONFIG:   ${KEY_CONFIG}"
vecho "KEY_SIZE:     ${KEY_SIZE}"
vecho "KEY_EXPIRE:   ${KEY_EXPIRE}"
vecho "KEY_CITY:     ${KEY_CITY}"
vecho "KEY_PROVINCE: ${KEY_PROVINCE}"
vecho "KEY_COUNTRY:  ${KEY_COUNTRY}"
vecho "KEY_ORG:      ${KEY_ORG}"
vecho "KEY_EMAIL:    ${KEY_EMAIL}"


# Make sure the key directory is sane
[ -d "${KEY_DIR}" ] || die "Keys directory '${KEY_DIR}' does not exist"
chmod -R go-rwx "${KEY_DIR}" || die "Failed to fix permissions on ${KEY_DIR}"
touch ${KEY_DIR}/index.txt || die "Failed to create ${KEY_DIR}/index.txt"
if [ ! -e ${KEY_DIR}/serial ]; then
    echo "01" > ${KEY_DIR}/serial || die "Failed to create ${KEY_DIR}/serial"
fi


# Make a certificate/private key pair using a locally generated
# root certificate and convert it to a PKCS #12 file including the
# the CA certificate as well.

echo -e "\n>>> Generating pkgcs12 key"
vecho "${PKITOOL} --pkcs12 ${name}"
if [ "${VERBOSE}" ]; then
    ${PKITOOL} --pkcs12 ${name} || die "PKITOOL failed"
else
    ${PKITOOL} --pkcs12 ${name} &>/dev/null || die "PKITOOL failed"
fi

[ -s "${KEY_DIR}/${name}.p12" ] \
    || die "Failed pkcs12: ${KEY_DIR}/${name}.p12 is zero size"


# Copy the pkcs12 cert/key just generated into the NSIS config
cp ${KEY_DIR}/${name}.p12 ${NSIS_DIR}/openvpn/config/client.p12 \
    || die "Could not copy pkgcs12 client cert to NSIS config"


# Now build the Windows package using that key
echo -e "\n>>> Creating NSIS OpenVPN package"
vecho "makensis ${NSIS_FILE} \"-XOutFile ${top}/openvpn-${name}-install.exe\""
if [ "${VERBOSE}" ]; then
    makensis ${NSIS_FILE} "-XOutFile ${top}/openvpn-${name}-install.exe" \
        || die "Failed to create nsis package"
else
    makensis ${NSIS_FILE} "-XOutFile ${top}/openvpn-${name}-install.exe" \
        >/dev/null || die "Failed to create nsis package"
fi


# Zip it so that email programs will allow it through
echo -e "\n>>> Zipping NSIS OpenVPN package"
cd ${top} || die "Failed to cd to ${top} for zip"
rm -f openvpn-${name}-install.zip
zip openvpn-${name}-install.{zip,exe} || die "failed to zip"
