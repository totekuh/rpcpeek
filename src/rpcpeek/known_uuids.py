class UUIDDatabase:
    _ENTRIES = {
        # AD / SMB named-pipe interfaces
        "12345778-1234-ABCD-EF00-0123456789AC": ("SAMR", "MS-SAMR Security Account Manager Remote Protocol"),
        "12345778-1234-ABCD-EF00-0123456789AB": ("LSARPC", "MS-LSAD/MS-LSAT Local Security Authority Remote Protocol"),
        "3919286A-B10C-11D0-9BA8-00C04FD92EF5": ("LSA-DSSETUP", "LSA Directory Services Setup interface"),
        "12345678-1234-ABCD-EF00-01234567CFFB": ("NETLOGON", "MS-NRPC Netlogon Remote Protocol"),
        "4B324FC8-1670-01D3-1278-5A47BF6EE188": ("SRVSVC", "MS-SRVS Server Service Remote Protocol"),
        "6BFFD098-A112-3610-9833-46C3F87E345A": ("WKSSVC", "MS-WKST Workstation Service Remote Protocol"),
        "367ABB81-9844-35F1-AD32-98F038001003": ("SVCCTL", "MS-SCMR Service Control Manager Remote Protocol"),
        "338CD001-2244-31F1-AAAA-900038001003": ("WINREG", "MS-RRP Windows Remote Registry Protocol"),
        "E3514235-4B06-11D1-AB04-00C04FC2DCD2": ("DRSUAPI", "MS-DRSR Directory Replication Service (DCSync)"),

        # Print
        "12345678-1234-ABCD-EF00-0123456789AB": ("RPRN", "MS-RPRN Print System Remote Protocol"),
        "76F03F96-CDFD-44FC-A22C-64950A001209": ("MS-PAR", "Print System Asynchronous Remote Protocol"),

        # Coercion targets
        "C681D488-D850-11D0-8C52-00C04FD90F7E": ("EFSRPC", "MS-EFSR Encrypting File System Remote Protocol (PetitPotam, lsarpc pipe)"),
        "DF1941C5-FE89-4E79-BF10-463657ACF44D": ("EFSRPC", "MS-EFSR Encrypting File System Remote Protocol (efsrpc pipe)"),
        "4FC742E0-4A10-11CF-8273-00AA004AE673": ("DFSNM", "MS-DFSNM DFS Namespace Management (DFSCoerce)"),
        "A8E0653C-2744-4389-A61D-7373DF8B2292": ("FSRVP", "MS-FSRVP File Server Remote VSS Protocol (ShadowCoerce)"),

        # Event log
        "82273FDC-E32A-18C3-3F78-827929DC23EA": ("EVENTLOG", "MS-EVEN EventLog Remoting Protocol (legacy)"),
        "F6BEAFF7-1E19-4FBB-9F8F-B89E2018337C": ("MS-EVEN6", "EventLog Remoting Protocol Version 6.0"),

        # Task scheduler
        "1FF70682-0A51-30E8-076D-740BE8CEE98B": ("ATSVC", "AT Scheduler interface (legacy)"),
        "86D35949-83C9-4044-B424-DB363231FD0C": ("ITaskSchedulerService", "MS-TSCH Task Scheduler Service"),

        # WMI
        "F309AD18-D86A-11D0-A075-00C04FB68820": ("IWbemLevel1Login", "MS-WMI Remote Login interface"),

        # Certificate services
        "91AE6020-9E3C-11CF-8D7C-00AA00C091BE": ("ICertPassage", "MS-ICPR Certificate enrollment"),
        "D99E6E70-FC88-11D0-B498-00A0C90312F3": ("ICertRequestD", "MS-WCCE Certificate Enrollment Protocol"),
        "5422FD3A-D4B8-4CEF-A12E-E87D4CA22E90": ("ICertRequestD2", "MS-WCCE Certificate Enrollment Protocol v2"),
        "D99E6E71-FC88-11D0-B498-00A0C90312F3": ("ICertAdminD", "MS-CSRA Certificate Services Remote Administration"),
        "7FE0D935-DDA6-443F-85D0-1CFB58FE41DD": ("ICertAdminD2", "MS-CSRA Certificate Services Remote Administration v2"),

        # Exchange
        "F5CC5A18-4264-101A-8C59-08002B2F8426": ("NSPI", "Exchange Name Service Provider Interface"),

        # DCOM / OXID
        "E1AF8308-5D1F-11C9-91A4-08002B14A0FA": ("EPMAPPER", "RPC Endpoint Mapper"),
        "99FCFEC4-5260-101B-BBCB-00AA0021347A": ("IObjectExporter", "MS-DCOM OXID Resolver"),
        "000001A0-0000-0000-C000-000000000046": ("IRemoteSCMActivator", "MS-DCOM Remote Activation"),
        "4D9F4AB8-7D1C-11CF-861E-0020AF6E7C57": ("IActivation", "MS-DCOM Legacy Remote Activation"),
        "00000131-0000-0000-C000-000000000046": ("IRemUnknown", "MS-DCOM Reference Counting"),
        "00000143-0000-0000-C000-000000000046": ("IRemUnknown2", "MS-DCOM Reference Counting v2"),
        "00000000-0000-0000-C000-000000000046": ("IUnknown", "Base DCOM Interface"),

        # DNS
        "50ABC2A4-574D-40B3-9D66-EE4FD5FBA076": ("DnsServer", "MS-DNSP DNS Server Management"),

        # Terminal services
        "5CA4A760-EBB1-11CF-8611-00A0245420ED": ("TermSrv", "Terminal Services winstation_rpc"),
        "3D267954-EEB7-11D1-B94E-00C04FA321A1": ("LicenseServer", "Terminal Server Licensing"),

        # WebDAV
        "C8CB7687-E6D3-11D2-A958-00C04F682E16": ("WebClient", "WebDAV Client Service"),

        # Shutdown
        "894DE0C0-0D55-11D3-A322-00C04FA321A1": ("InitShutdown", "Remote Shutdown interface"),

        # Crypto
        "8D0FFE72-D252-11D0-BF8F-00C04FD9126B": ("IKeySvc", "Cryptographic Services"),
        "0D72A7D4-6148-11D1-B4AA-00C04FB66EA0": ("ICertProtect", "CryptSvc Certificate Protection"),

        # Locator
        "D6D70EF0-0E3B-11CB-ACC3-08002B1D29C4": ("NsiS", "RPC Locator Service"),

        # Licensing
        "342CFD40-3C6C-11CE-A893-08002B2E9C6D": ("LLSRPC", "Licensing Logging Service"),

        # Messenger
        "5A7B91F8-FF00-11D0-A9B2-00C04FB6E6FC": ("MsgSvcSend", "Messenger Service"),

        # NetDDE
        "2F5F3220-C126-1076-B549-074D078619DA": ("NDDEAPI", "NetDDE Service"),

        # Plug and Play
        "8D9F4E40-A03D-11CE-8F69-08003E30051B": ("PlugPlay", "Plug and Play Service"),

        # IPSec
        "D335B8F6-CB31-11D0-B0F9-006097BA4E54": ("PolicyAgent", "IPSec Policy Agent"),

        # Protected Storage
        "C9378FF1-16F7-11D0-A0B2-00AA0061426A": ("IPStoreProv", "Protected Storage"),

        # RRAS
        "8F09F000-B7ED-11CE-BBD2-00001A181CAD": ("RRASM", "MS-RRASM Routing and Remote Access Management"),
        "20610036-FA22-11CF-9823-00A0C911E5DF": ("RASRPC", "Remote Access Service RPC"),

        # Security config
        "93149CA2-973B-11D1-8C39-00C04FB984F9": ("SceSvc", "Security Configuration Editor"),

        # Secondary logon
        "12B81E99-F207-4A4C-85D3-77B42F76FD14": ("ISeclogon", "Secondary Logon Service"),

        # Windows File Protection
        "83DA7C00-E84F-11D2-9807-00C04F8EC850": ("SfcApi", "Windows File Protection"),

        # SSDP
        "4B112204-0E19-11D3-B42B-0000F81FEB9F": ("SSDPSRV", "SSDP Discovery Service"),

        # Telephony
        "2F5F6520-CA46-1067-B319-00DD010662DA": ("TapSrv", "Telephony Service"),

        # Link tracking
        "300F3532-38CC-11D0-A3F0-0020AF6B0ADD": ("TrkWks", "Distributed Link Tracking Client"),

        # Time
        "8FB6D884-2388-11D0-8C35-00C04FDA2795": ("W32Time", "Windows Time Service"),

        # Audio
        "3FAF4738-3A21-4307-B46C-FDDA9BB8C0D5": ("AudioSrv", "Windows Audio Service"),

        # Browser
        "6BFFD098-A112-3610-9833-012892020162": ("Browser", "Computer Browser Service"),

        # WINS
        "45F52C28-7F9F-101A-B52B-08002B2EFABE": ("WINSIF", "WINS Service"),

        # Winlogon
        "369CE4F0-0FDC-11D3-BDE8-00C04F8EEE78": ("PMapApi", "Winlogon interface"),
        "A002B3A0-C9B7-11D1-AE88-0080C75E4EC1": ("GetUserToken", "Winlogon GetUserToken"),
    }

    def __init__(self):
        self._by_uuid = {k.upper(): v for k, v in self._ENTRIES.items()}

    def lookup(self, uuid: str) -> tuple:
        result = self._by_uuid.get(uuid.upper())
        if result:
            return result
        return (None, None)

    def name(self, uuid: str) -> str | None:
        return self.lookup(uuid)[0]

    def __len__(self):
        return len(self._by_uuid)

    def __contains__(self, uuid: str):
        return uuid.upper() in self._by_uuid


DB = UUIDDatabase()
