$script:service_policy_key = "HKLM\SYSTEM\CurrentControlSet\Services\"
$script:service_policy_item = "start"
$script:SERVICE_POLICY_AUTOMATIC = 2
$script:SERVICE_POLICY_MANUAL = 3
$script:SERVICE_POLICY_DISABLED = 4

$script:HEAD_NODE = 0
$script:IF_NODE = 1
$script:THEN_NODE = 2
$script:ELSE_NODE = 3

$script:MIN_PASS_LEN = 0
$script:MAX_PASS_AGE = 1
$script:MIN_PASS_AGE = 2
$script:FORCE_LOGOFF = 3
$script:PASS_HIST_LEN = 4
$script:PASS_COMPLEX = 5
$script:REV_ENCRYPT = 6

$script:LOCKOUT_DURATION = 0
$script:LOCKOUT_OBSV_WIN = 1
$script:LOCKOUT_THRESHOLD = 2

$script:ADMIN_ACCOUNT = 1
$script:GUEST_ACCOUNT = 2

$script:UF_ACCOUNTDISABLE = 2

$script:FILE = 0
$script:REGISTRY = 1


#Some declarations are from pinvoke.net
Add-Type @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using System.Security.AccessControl;
using System.Text;

namespace ACLSecurity {

    enum ACL_INFORMATION_CLASS : int {
        AclRevisionInformation = 1,
        AclSizeInformation
    }

    enum SE_OBJECT_TYPE {
        SE_UNKNOWN_OBJECT_TYPE,
        SE_FILE_OBJECT,
        SE_SERVICE,
        SE_PRINTER,
        SE_REGISTRY_KEY
    }

    enum SECURITY_INFORMATION {
        OWNER_SECURITY_INFORMATION = 1,
        GROUP_SECURITY_INFORMATION = 2,
        DACL_SECURITY_INFORMATION = 4,
        SACL_SECURITY_INFORMATION = 8
    }


    [StructLayout(LayoutKind.Sequential)]
    struct ACE_SIZE_INFORMATION {
        internal int AceCount;
        internal int AclBytesInUse;
        internal int AclBytesFree;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct ACE_HEADER {
        internal byte AceType;
        internal byte AceFlags;
        internal ushort AceSize;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct ACCESS_ACE {
        internal ACE_HEADER Header;
        internal uint Mask;
        internal int sidStart;
    }

    sealed class WinACL {
        [DllImport("advapi32.dll", CallingConvention= CallingConvention.StdCall)]
        internal static extern uint GetNamedSecurityInfo(
            string pObjectName,
            SE_OBJECT_TYPE objectType,
            SECURITY_INFORMATION securityInformation,
            out IntPtr ppsidOwner,
            out IntPtr ppsidGroup,
            out IntPtr ppDacl,
            out IntPtr ppSacl,
            out IntPtr ppSecuirtyDescriptor
        );

        [DllImport("advapi32.dll", SetLastError=true)]
        internal static extern bool GetAclInformation(
            IntPtr pAcl,
            out ACE_SIZE_INFORMATION pAclInformation,
            int nAclInformationLength,
            ACL_INFORMATION_CLASS dwAclInformationClass
        );

        [DllImport("advapi32.dll", SetLastError=true)]
        internal static extern bool GetAce(
            IntPtr pAcl,
            int dwAceIndex,
            out IntPtr pAce
        );

        [DllImport("advapi32.dll", CharSet=CharSet.Ansi, SetLastError=true)]
        internal static extern bool LookupAccountSid(
            string lpSystemName,
            IntPtr sid,
            StringBuilder lpName,
            ref uint cchName,
            StringBuilder ReferencedDomainName,
            ref uint cchReferenceDomainName,
            out int peUse  
        );
    }

    public class ACLWrapper : IDisposable {
        public ACLWrapper() {}
        ~ACLWrapper() { Dispose(); }
        public void Dispose() {
            GC.SuppressFinalize(this);
        }
        /*Compares ACL values. Currently Not is use*/
        public uint CompareACL(string path, int type, string name, uint allowDeny, uint accessRights, int inherit, int apply) {
            uint UNKNOWN_ERR = 0x2;
            uint SUCCESS = 0;
            uint NOT_FOUND_ERR = 0x1;
            uint retStatus = UNKNOWN_ERR;
            uint CallStatus = 0;
            IntPtr ownerSid;
            IntPtr groupSid;
            IntPtr dacl;
            IntPtr sacl;
            IntPtr securityDescriptor = IntPtr.Zero;
            IntPtr ace;
            ACE_SIZE_INFORMATION aceSzInfo;

            SE_OBJECT_TYPE SeType = SE_OBJECT_TYPE.SE_FILE_OBJECT;
            if (type == 1) {
                SeType = SE_OBJECT_TYPE.SE_REGISTRY_KEY;
            }

           retStatus = WinACL.GetNamedSecurityInfo(path, SeType, SECURITY_INFORMATION.DACL_SECURITY_INFORMATION,
                            out ownerSid, out groupSid, out dacl, out sacl, out securityDescriptor);
           if (CallStatus != 0) {
                return retStatus;
           }
           retStatus = UNKNOWN_ERR;
           bool ACLStatus = WinACL.GetAclInformation(dacl, out aceSzInfo, Marshal.SizeOf(typeof(ACE_SIZE_INFORMATION)), ACL_INFORMATION_CLASS.AclSizeInformation);
           if (ACLStatus) {
                retStatus = NOT_FOUND_ERR;
                for (int i = 0; i < aceSzInfo.AceCount; ++i) {
                    ACLStatus = WinACL.GetAce(dacl, i, out ace);
                    if (ACLStatus) {
                        ACE_HEADER aceHeader = (ACE_HEADER)Marshal.PtrToStructure(ace, typeof(ACE_HEADER));
                        if (aceHeader.AceType == 0 || aceHeader.AceType == 1) {
                            StringBuilder username;
                            uint cchUserName = 20;
                            StringBuilder domainName;
                            uint cchDomainName = 20;
                            int sidUse;
                            int LastError = 0;

                            ACCESS_ACE aclACE = (ACCESS_ACE)Marshal.PtrToStructure(ace, typeof(ACCESS_ACE));
                            IntPtr sid = (IntPtr)((long)ace + (long)Marshal.OffsetOf(typeof(ACCESS_ACE), "sidStart"));
                            int times = 0;
                            do {
                                username = new StringBuilder((int)cchDomainName);
                                domainName = new StringBuilder((int)cchDomainName);
                                bool lookupErr = WinACL.LookupAccountSid(null, sid, username, ref cchUserName, domainName, ref cchDomainName, out sidUse);
                                LastError = Marshal.GetLastWin32Error();
                                if (times > 10) { //Preventing Infinite loop
                                    return (uint)LastError;
                                }
                                times++;
                            } while (LastError == 0x7a); //INSUFFICIENT SIZE ERROR
                            
                            if ((String.Compare(username.ToString(), name, true) == 0) && (allowDeny == aceHeader.AceType)
                                    && ((aclACE.Mask & accessRights) == accessRights) && ((aclACE.Header.AceFlags & 0x000000F0) == inherit) && ((aclACE.Header.AceFlags & 0x0000000F) == apply)) {
                                retStatus = SUCCESS;
                                break;
                            }
                        }
                    }
                }  //end for  
           }//end if
           return retStatus;
        } //end func
    } //end class
} //end of ACLSecurity




/*
Handles User policy information 
*/
namespace NetSecurity {
    [StructLayout(LayoutKind.Sequential)]
    struct USER_MODALS_INFO_0 {
        internal int usrmod0_min_passwd_len;
        internal int usrmod0_max_passwd_age;
        internal int usrmod0_min_passwd_age;
        internal int usrmod0_force_logoff;
        internal int usrmod0_password_hist_len;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct USER_MODALS_INFO_3 {
        internal int usrmod3_lockout_duration;
        internal int usrmod3_lockout_observation_window;
        internal int usrmod3_lockout_threshold;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct USER_INFO_1
    {
        [MarshalAs(UnmanagedType.LPWStr)]
        internal string name;
        [MarshalAs(UnmanagedType.LPWStr)]
        internal string password;
        internal int passwd_age;
        internal int priv;
        [MarshalAs(UnmanagedType.LPWStr)]
        internal string home_dir;
        [MarshalAs(UnmanagedType.LPWStr)]
        internal string comments;
        internal int flags;
        [MarshalAs(UnmanagedType.LPWStr)]
        internal string script_path;
    }
    
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct SecurityProfileInfo {
        internal int unk0;
        internal int minPasswdAge;
        internal int maxPasswdAge;
        internal int minpasswdLen;
        internal int passwdComplexity;
        internal int passwdHistSz;
        internal int LockoutCount;
        internal int resetLockoutCount;
        internal int lockoutDuration;
        internal int reqLogonChangePasswd; 
        internal int forceLogoff;
        internal string adminName;
        internal string guestName;
        internal int unk2;
        internal int clearTextPasswd;
        internal int allowAnonymousSID;
        //More stuff here?
    }

    sealed class WinSceCli {
        [DllImport("scecli.dll", CallingConvention = CallingConvention.StdCall)]
        internal static extern uint SceGetSecurityProfileInfo(
            int arg1,
            int arg2,
            int arg3,
            out IntPtr buffer,
            out IntPtr optBuf
        );

        [DllImport("scecli.dll")]
        internal static extern int SceFreeProfileMemory(IntPtr Buffer);
    }

    sealed class WinNet32Sec {
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall)]
        internal static extern uint NetUserModalsGet(
            string server,
            int level,
            out IntPtr BufPtr
        );
        
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall)]
        internal static extern uint NetUserGetInfo(
            [MarshalAs(UnmanagedType.LPWStr)]
            string servername,
            [MarshalAs(UnmanagedType.LPWStr)]
            string username,
            int level,
            out IntPtr bufptr
        );

        [DllImport("netapi32.dll")]
        internal static extern int NetApiBufferFree(IntPtr Buffer);
    }

    public class NetWrapper : IDisposable {
        enum AccountType : int {
            ADMIN = 1,
            GUEST = 2
        }

        const uint ERROR_ACCESS_DENIED = 0x5;
        const uint ERROR_BAD_NETPATH = 0x35;
        const uint ERROR_INVALID_LEVEL = 0x7C;
        const uint ERROR_INVALID_NAME = 0x7B;
        const uint ERROR_WRONG_TARGET_NAME = 0x574;
        const uint NERR_InvalidComputer = 2351;
        const uint NERR_Success = 0;

        public NetWrapper() {}
        ~NetWrapper() {Dispose();}
        public void Dispose() {
            GC.SuppressFinalize(this);
        }

        /*Checks if local Password complexity is active*/
        public bool hasComplexity() {
            IntPtr buffer;
            IntPtr buffer2;
            bool hasPassComplexity = false;
            uint ret = WinSceCli.SceGetSecurityProfileInfo(0, 300, -1, out buffer, out buffer2);
            SecurityProfileInfo spi = (SecurityProfileInfo)Marshal.PtrToStructure(buffer, typeof(SecurityProfileInfo));
            if (spi.passwdComplexity == 1) {
                hasPassComplexity = true;
            } 
            WinSceCli.SceFreeProfileMemory(buffer);
            return hasPassComplexity;
        }

        /*Checks if local revisible encryption for password is active*/
        public bool hasRevEncryption() {
            IntPtr buffer;
            IntPtr buffer2;
            bool hasEncryption = false;
            uint ret = WinSceCli.SceGetSecurityProfileInfo(0, 300, -1, out buffer, out buffer2);
            SecurityProfileInfo spi = (SecurityProfileInfo)Marshal.PtrToStructure(buffer, typeof(SecurityProfileInfo));
            if (spi.clearTextPasswd == 1) {
                hasEncryption = true;
            } 
            WinSceCli.SceFreeProfileMemory(buffer);
            return hasEncryption;
        }
        
        /*
            Returns the name of the specified account.
            accType: (1 = ADMIN), (2 = GUEST)
        */
        public string LSAGetAccountName(int accType)
        {
            IntPtr buffer;
            IntPtr buffer2;
            string name;
            uint ret = WinSceCli.SceGetSecurityProfileInfo(0, 300, -1, out buffer, out buffer2);
            if (ret != 0) {
                return null;
            }
            SecurityProfileInfo spi = (SecurityProfileInfo)Marshal.PtrToStructure(buffer, typeof(SecurityProfileInfo));
            if (accType == (int)AccountType.ADMIN)
            {
                name = spi.adminName;
            } else {
                name = spi.guestName;
            }
            
            WinSceCli.SceFreeProfileMemory(buffer);
            return name;
        }

        /*Checks if 'Anonymous SID Allowed' is active*/
        public bool isAnonymousSIDAllowed() {
            IntPtr buffer;
            IntPtr buffer2;
            bool allowAnonymous = false;
            uint ret = WinSceCli.SceGetSecurityProfileInfo(0, 300, -1, out buffer, out buffer2);
            SecurityProfileInfo spi = (SecurityProfileInfo)Marshal.PtrToStructure(buffer, typeof(SecurityProfileInfo));
            if (spi.allowAnonymousSID == 1) {
                allowAnonymous = true;
            }
            WinSceCli.SceFreeProfileMemory(buffer);
            return allowAnonymous;
        }

        /*Get user's information as an int (flag).
          username: the account to get information flags
        */
        public int GetFlags(string username)
        {
            IntPtr buffer;
            uint ret =  WinNet32Sec.NetUserGetInfo("", username,1, out buffer);
            if (ret != NERR_Success)
            {
                return -1;
            } 
            USER_INFO_1 uf1 = (USER_INFO_1)Marshal.PtrToStructure(buffer, typeof(USER_INFO_1));
            return uf1.flags;

        }


        /*
        Get local password/lockout policy information
        level: (1 = password policy), (3 = lockout policy)
        returns an array of all possible policy values in specified level
        */
        public int[] NetUserModalsGet(int level) {
            IntPtr buffer;
            int[] UsrInfo = null;
            uint ret = WinNet32Sec.NetUserModalsGet(null, level, out buffer);
           
            if (ret != NERR_Success) {
                return null; //ERROR
            }

            if (level == 0) {
                UsrInfo = new int[5];
                USER_MODALS_INFO_0 umi0 = (USER_MODALS_INFO_0)Marshal.PtrToStructure(
                        buffer,
                        typeof(USER_MODALS_INFO_0));
                
                UsrInfo[0] = umi0.usrmod0_min_passwd_len;
                if (umi0.usrmod0_max_passwd_age > 0) { //convert seconds to day
                    UsrInfo[1] = (((umi0.usrmod0_max_passwd_age / 60) / 60) / 24);
                } else {
                    UsrInfo[1] = umi0.usrmod0_max_passwd_age;
                }
                if (umi0.usrmod0_min_passwd_age > 0) {
                    UsrInfo[2] = (((umi0.usrmod0_min_passwd_age / 60) / 60) / 24);
                } else {
                    UsrInfo[2] = umi0.usrmod0_min_passwd_age;
                }
                if (umi0.usrmod0_force_logoff == -1) {
                    UsrInfo[3] = 0;
                } else {
                    UsrInfo[3] = 1;
                }
               // UsrInfo[3] = umi0.usrmod0_force_logoff;
                UsrInfo[4] = umi0.usrmod0_password_hist_len;
            } else if (level == 3) {
                UsrInfo = new int[3];
                USER_MODALS_INFO_3 umi3 = (USER_MODALS_INFO_3)Marshal.PtrToStructure(
                        buffer,
                        typeof(USER_MODALS_INFO_3));
                UsrInfo[0] = (umi3.usrmod3_lockout_duration / 60);
                UsrInfo[1] = (umi3.usrmod3_lockout_observation_window/ 60 );
                UsrInfo[2] = umi3.usrmod3_lockout_threshold;

            } else {
               return null;
            }
            WinNet32Sec.NetApiBufferFree(buffer);
            return UsrInfo;
        }

    } //NetWrapper Class End



} //NetSecurity NameSpace End

/*
*/
namespace LSASecurity {
    using LSA_HANDLE = IntPtr;
    using PSID       = IntPtr;

    [StructLayout(LayoutKind.Sequential)]
    struct LSA_OBJECT_ATTRIBUTES {
        internal int Length;
        internal IntPtr RootDirectory;
        internal IntPtr ObjectName;
        internal int Attributes;
        internal IntPtr SecurityDescriptor;
        internal IntPtr SecurityQualityOfService;
    }    

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct LSA_UNICODE_STRING {
        internal ushort Length;
        internal ushort MaximumLength;
        [MarshalAs(UnmanagedType.LPWStr)]
        internal string Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct LSA_ENUMERATION_INFORMATION {
        internal IntPtr PSid;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct POLICY_ACCOUNT_DOMAIN_INFO {
        internal LSA_UNICODE_STRING DomainName;
        internal IntPtr DomainSid;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct LSA_TRANSLATED_NAME {
        internal int Use;
        internal LSA_UNICODE_STRING Name;
        internal long DomainIndex;
    }

    sealed class Win32Sec {
        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true), SuppressUnmanagedCodeSecurityAttribute]
        internal static extern uint LsaOpenPolicy(
            LSA_UNICODE_STRING[] SystemName,
            ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
            int AccessMask,
            out IntPtr PolicyHandle
        );

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true), SuppressUnmanagedCodeSecurityAttribute]
        internal static extern uint LsaEnumerateAccountsWithUserRight(
            LSA_HANDLE PolicyHandle,
            LSA_UNICODE_STRING[] UserRights,
            out IntPtr EnumrationBuffer,
            out int CountReturned
        );

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true), SuppressUnmanagedCodeSecurityAttribute]
        internal static extern uint LsaQueryInformationPolicy(
            LSA_HANDLE PolicyHandle,
            int InformationClass,
            out IntPtr Buffer
        );

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true), SuppressUnmanagedCodeSecurityAttribute]
        internal static extern uint LsaLookupSids(
            LSA_HANDLE PolicyHandle,
            ulong Count,
            IntPtr Sids,
            out IntPtr ReferencedDomains,
            ref IntPtr Names
        );


        [DllImport("advapi32")]
        internal static extern int LsaNtStatusToWinError(int NTSTATUS);

        [DllImport("advapi32")]
        internal static extern int LsaClose(IntPtr PolicyHandle);

        [DllImport("advapi32")]
        internal static extern int LsaFreeMemory(IntPtr Buffer);
    }

    public class LsaWrapper : IDisposable {

        enum Access : int {
            POLICY_READ = 0x200006,
            POLICY_ALL_ACCESS = 0x00F0FFF,
            POLICY_EXECUTE = 0x20801,
            POLICY_WRITE = 0x207F8
        }
        const uint STATUS_ACCESS_DENIED          = 0xc0000022;
        const uint STATUS_INSUFFICIENT_RESOURCES = 0xc000009a;
        const uint STATUS_NO_MEMORY              = 0xc0000017;
        const uint STATUS_NO_MORE_ENTRIES        = 0xc000001A;

        IntPtr lsaHandle;

        public LsaWrapper() : this(null) {}

        public LsaWrapper(string SystemName) {
            LSA_OBJECT_ATTRIBUTES lsaAttr;
            lsaAttr.RootDirectory = IntPtr.Zero; 
            lsaAttr.ObjectName = IntPtr.Zero;
            lsaAttr.Attributes = 0;
            lsaAttr.SecurityDescriptor = IntPtr.Zero;
            lsaAttr.SecurityQualityOfService = IntPtr.Zero;
            lsaAttr.Length = Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES));
            lsaHandle = IntPtr.Zero;
            LSA_UNICODE_STRING[] system = null;
            if (SystemName != null) {
                system = new LSA_UNICODE_STRING[1];
                system[0] = InitLsaString(SystemName);
            }
            
            uint ret = Win32Sec.LsaOpenPolicy(system, ref lsaAttr, (int)Access.POLICY_ALL_ACCESS, out lsaHandle);
            if (ret == 0) {
                return;
            }
            if (ret == STATUS_ACCESS_DENIED) {
                throw new UnauthorizedAccessException();
            }
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY)) {
                throw new OutOfMemoryException();
            }
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }

        /*
        Gets all users allowed for specified privilege right
        privilege: the rights to search for  
        return all users that contain that privilege
        */
        public string[] LSAEnurmerateAccountsWithUserRight(string privilege) {
            LSA_UNICODE_STRING[] privileges = new LSA_UNICODE_STRING[1];
            privileges[0] = InitLsaString(privilege);
            IntPtr buffer;
            int count = 0;
            uint ret = Win32Sec.LsaEnumerateAccountsWithUserRight(lsaHandle, privileges, out buffer, out count);
            string[] accounts = null;
            if (ret == 0) {
               accounts = new string[count];
               for (int i = 0; i < count; ++i) {
                    LSA_ENUMERATION_INFORMATION LsaInfo = (LSA_ENUMERATION_INFORMATION)Marshal.PtrToStructure(
                        IntPtr.Add(buffer, i * Marshal.SizeOf(typeof(LSA_ENUMERATION_INFORMATION))),
                        typeof(LSA_ENUMERATION_INFORMATION));
                    try {
                        accounts[i] = (new SecurityIdentifier(LsaInfo.PSid)).Translate(typeof(NTAccount)).ToString();
                    } catch (System.Security.Principal.IdentityNotMappedException) {
                        accounts[i] = (new SecurityIdentifier(LsaInfo.PSid)).ToString();
                    }
               }
               Win32Sec.LsaFreeMemory(buffer);
               return accounts;
            }
            if (ret == STATUS_NO_MORE_ENTRIES) {
                return null;
            }
            if (ret == STATUS_ACCESS_DENIED) {
                throw new UnauthorizedAccessException();
            }
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY)) {
                throw new OutOfMemoryException();
            }
            return null;
            //throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        } 

        public void Dispose() {
            if (lsaHandle != IntPtr.Zero) {
                Win32Sec.LsaClose(lsaHandle);
                lsaHandle = IntPtr.Zero;
            }
            GC.SuppressFinalize(this);
        }

       
        ~LsaWrapper() {
            Dispose();
        }

        /*Instantiates a LSA_UNICODE_STRING*/
        static LSA_UNICODE_STRING InitLsaString(string s) {
            if (s.Length > 0x7ffe) {
                throw new ArgumentException("String too Long");
             }  
                LSA_UNICODE_STRING lus = new LSA_UNICODE_STRING();
                lus.Buffer = s;
                lus.Length = (ushort)(s.Length * sizeof(char));
                lus.MaximumLength = (ushort)(lus.Length + sizeof(char));
                return lus;
        }
    } // End LsaWrapper Class
}//End Namespace
'@



function checkTEXT {
    <#
    .SYNOPSIS
    Compares two string values based on conditions in valueData

    .DESCRIPTION
    Takes in two values to compare. checks if valueData and valToCheck matches.  

    .PARAMETER funcName
    (optional) function name that called this function. Used to display origin for debug prints

    .PARAMETER valueData
     Set of data to be checked with valToCheck. valueData may contain the or (||) conditional statement to be checked with mulitple values

    .PARAMETER valToCheck
    Value to be checked from valueData

    .EXAMPLE
    checkText -funcName "Test" -valueData "x || y" -valToCheck "y"
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [String]$funcName, 
        [String]$valueData, 
        [String]$valToCheck,
        [ValidateSet('CHECK_EQUAL', 'CHECK_NOT_EQUAL', '')][String]$checkType
    )
    if ($valueData.Contains("&&")) {
        $found = $true
        [array]$data = $valueData.Split("&&", [System.StringSplitOptions]::RemoveEmptyEntries);
        foreach ($value in $data) {
            if ($valToCheck.Trim().Trim(0) -notlike $value.Trim().Trim(0)){
                $found = $false
                break
            }
        }
    } else {
        [array]$data = $valueData.Split("||", [System.StringSplitOptions]::RemoveEmptyEntries);
        foreach ($value in $data) {
            if ($valToCheck.Trim().Trim(0) -like $value.Trim().Trim(0)) {
                $found = $true
                break
            }
        }
    }

    if ($checkType -like 'CHECK_NOT_EQUAL' -and $found) {
        Write-Verbose "[$funcName] Violated CHECK_NOT_EQUAL Policy <$valueData> : <$valToCheck>"
        return $false
    } elseif (($checkType -like "CHECK_EQUAL" -or $checkType.Length -eq 0) -and !$found) {
        Write-Verbose "[$funcName] Do Not match <$valueData> : <$valToCheck>"
        return $false
    } else {
        return $true
    }
}


function checkDWORD {
    <#
    .SYNOPSIS
    Compares two Integer values based on conditions in valueData

    .DESCRIPTION
    Takes in two values to compare. checks if valueData and valToCheck matches. 

    .PARAMETER funcName
    (optional) function name that called this function. Used to display origin for debug prints

    .PARAMETER valueData
     Set of data to be checked with valToCheck. valueData may contain the or (||) conditional statement to be checked with mulitple values.
     Can contain brackets [] to compare range (Cannot be combined with or conditional statement), format as [1..3].

    .PARAMETER valToCheck
    (optional) Value to be checked from valueData

    .PARAMETER checkType
    (optional) If valueData should meet the following criteria based on valToCheck. Cannot be used with range brackets []
    CHECK_EQUAL (default)
    CHECK_NOT_EQUAL
    CHECK_GREATER_THAN_OR_EQUAL
    CHECK_GREATER_THAN
    CHECK_LESS_THAN_OR_EQUAL
    CHECK_LESS_THAN

    .EXAMPLE
    checkDWORD -funcName "Test" -valueData "1 || 2 || 3" -valToCheck 2
    checkDWORD -funcName "Test" -valueData "[1..5]" -valToCheck 3
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [String]$funcName, 
        [String]$valueData, 
        [Int]$valToCheck,
        [ValidateSet('CHECK_EQUAL', 'CHECK_NOT_EQUAL', 'CHECK_GREATER_THAN_OR_EQUAL','CHECK_GREATER_THAN' , 'CHECK_LESS_THAN_OR_EQUAL','CHECK_LESS_THAN','',IgnoreCase=$false)][String]$checkType=""
    )
    if ($checkType.CompareTo("") -ne 0) {
        if (($checkType.CompareTo("CHECK_GREATER_THAN_OR_EQUAL") -eq 0 -and $valToCheck -ge $valueData) `
            -or ($checkType.CompareTo("CHECK_GREATER_THAN") -eq 0 -and $valToCheck -gt $valueData) `
            -or ($checkType.CompareTo("CHECK_LESS_THAN") -eq 0 -and $valToCheck -lt $valueData) `
            -or ($checkType.CompareTo("CHECK_LESS_THAN_OR_EQUAL") -eq 0 -and $valToCheck -le $valueData) `
            -or (($checkType.CompareTo("CHECK_EQUAL") -eq 0 -or $checkType.CompareTo("") -eq 0) -and (checkTEXT $funcName $valueData $valToCheck "CHECK_EQUAL") )`
            -or ($checkType.CompareTo("CHECK_NOT_EQUAL") -eq 0 -and (checkTEXT $funcName $valueData $valToCheck "CHECK_NOT_EQUAL")) 
            ) 
        {
            return $true
        } else {
            Write-Verbose "[$funcName] value_data did not meet criteria: <$valToCheck> $checkType <$valueData>"
            return $false
        }
    } else {
        if ($valueData.Contains("||")) {
            return (checkTEXT $funcName $valueData $valToCheck)
        } else {
            [array]$data = $valueData.TrimStart("[").TrimEnd("]").Split("..", [System.StringSplitOptions]::RemoveEmptyEntries)
            if ($data.Length -eq 2) {  #range
                if ($valToCheck -ge [convert]::ToInt32($data[0], 10) -and $valToCheck -le [convert]::ToInt32($data[1], 10)) {
                    return $true
                } else {
                    Write-Verbose "[$funcName] $valToCheck Not within range"
                    return $false
                }
            } else { #single dword
                if ([convert]::ToInt32($valueData, 10) -eq $valToCheck) {
                    return $true
                } else {
                    Write-Verbose "[$funcName] Expected <$valueData>: Received <$valToCheck>"
                    return $false
                }
            }
        }
    }
}

function checkPolicySet {
    <#
    .SYNOPSIS
    Checks if the data is enabled or disabled

    .DESCRIPTION
    (Helper Function) Takes in two values to compare boolean values. Translates "Enabled" and "Disabled" into boolean values and compares with valToCheck

    .PARAMETER funcName
    (optional) function name that called this function. Used to display origin for debug prints

    .PARAMETER valueData
    String value of setting status. Can be of the following values:
    Enabled
    Disabled

    .PARAMETER valToCheck
    (optional) Value to be checked from valueData

    .PARAMETER checkType
    (optional) If valueData should meet the following criteria based on valToCheck.
    CHECK_EQUAL (default)
    CHECK_NOT_EQUAL

    .EXAMPLE
    checkPolicySet -funcName "Test" -valueData 'Enabled' -valToCheck $true -checkType 'CHECK_EQUAL'
    checkPolicySet -funcName "Test" -valueData 'Disabled' -valToCheck $true -checkType 'CHECK_NOT_EQUAL'

    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [String]$funcName, 
        [ValidateSet('Enabled', 'Disabled')][String]$valueData, 
        [bool]$valToCheck,
        [ValidateSet('CHECK_EQUAL', 'CHECK_NOT_EQUAL', '')][String]$checkType
    )

        $setting = $(switch -Regex ($valueData) {
            "Enabled" {$true; break;}
            "Disabled" {$false; break;}
        })

        $status =  (!($setting -xor $valToCheck))
        if (!$status) {
            if ($checkType -like "CHECK_NOT_EQUAL") {
                $status = $true
            } else {
                Write-Verbose "[$funcName] Settings do not match. Expect <$valueData>. Received <$valToCheck>"
            }
        }
        return $status

}


function translateRegRoot {
    <#
    .SYNOPSIS
    Converts Audit file's Registry path to Powershell path format

    .DESCRIPTION
    (Helper Function) Takes in registry path and converts the root (HKLM, HKCU, etc) to Powershell format.
    Not all root paths are defaulted as an alias like HKLM -> HKEY_LOCAL_MACHINE. This method ensures we get to the root path
    using the Registry::ROOT_PATH format

    .PARAMETER regKey
    Registry path in the format of ROOT\... where ROOT can be:
    HKLM
    HKCU
    HKU
    HKCR

    .EXAMPLE
    translateRegRoot 'HKLM\Software'
        -> 'Registry::HKEY_LOCAL_MACHINE\Software'

    #>
    [OutputType([String])]
    param([String]$regKey)

    $idx = $regKey.IndexOf("\")
    if ($idx -eq -1) {
        $root = $regKey
    } else {
        $root = $regKey.Substring(0, $idx)
    }
    $newRoot = $(switch ($root) {
        "HKLM" {"Registry::HKEY_LOCAL_MACHINE"; break;}
        "HKCU" {"Registry::HKEY_CURRENT_USER"; break;}
        "HKU"  {"Registry::HKEY_USERS"; break;}
        "HKCR" {"Registry::HKEY_CLASSES_ROOT"; break;}
        default {$root; break;}
    })

    if ($idx -eq -1) {
        return $newRoot
    } else {
        return ($newRoot + $regKey.Substring($idx))
    }

}

function AuditPowershell {
    <#
    .SYNOPSIS
    Run Powershell command and check compliance result

    .DESCRIPTION
    Parses AUDIT_POWERSHELL item in audit files. Runs Powershell command and based on check_type, it will either pass or fail
 
    .PARAMETER valueType
    (optional) Data type representation of valueData
    POLICY_TEXT = String

    .PARAMETER valueData
    (optional) Data to be checked with result from Powershell output

    .PARAMETER PsArgs
    Powershell command. Use single quotes (') for anything string data. If base64 Encoded, set ps_encoded_args to 'YES'

    .PARAMETER Only_Show_CMD
    (optional) YES or NO input to display PsArgs results on screen

    .PARAMETER ps_encoded_args
    (optional) Indicates if PsArgs are base64 Encoded. Default: NO
    YES: PsArgs is Base64 encoded
    NO: PsArgs is not Base64 encoded

    .PARAMETER checkType
    (optional) Method to check PsArgs Results to valueData. Currently supports
    CHECK_EQUAL: checks if PsArgs returns an output (valueData is empty)
    CHECK_REGEX: checks if PsArgs contain a certain string (valueData contain regex)

    .EXAMPLE
    AuditPowerShell -valueType "POLICY_TEXT" -valueData ".*\.audit" -PsArgs "ls" -Only_Show_CMD "YES" -checkType "CHECK_REGEX"
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [ValidateSet('POLICY_TEXT', '', IgnoreCase=$false)][String]$valueType, 
        [String]$valueData, 
        [Parameter(Mandatory=$true, HelpMessage='Powershell command')]
        [ValidateNotNullOrEmpty()]
        [String]$PsArgs,
        [ValidateSet('YES','NO', '', IgnoreCase=$false)][String]$Only_Show_CMD, 
        [ValidateSet('YES','NO', '', IgnoreCase=$false)][String]$ps_encoded_args, 
        [ValidateSet('CHECK_EQUAL', 'CHECK_NOT_EQUAL', 'CHECK_REGEX', '', IgnoreCase=$false)][String]$checkType)
    if ($ps_encoded_args -like "YES") {
        $PsArgs = $PsArgs.Trim("'")
        $PsArgs = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($PsArgs))
    }
    Try {
        $result = iex $PsArgs
    } Catch {
        $errMsg = $_.Exception.Message
        Write-Verbose "Powershell command failed: $errMsg"
        return $false
    }
    #if ($Only_Show_CMD -Like "YES") {
    #    Write-Host "$result"
    #}

    if ($checkType -Like "CHECK_REGEX") {
        if ($result -match $valueData) {
            return $true
        } else {
            Write-Verbose "[AuditPowershell] Regex result did not match <$result> with <$valueData>"
            return $false
        }
    } else {
        return (checkTEXT "AuditPowershell" $valueData $result $checkType )
    }

    Write-Verbose "[AuditPowershell] Unknown error"
    return $false
}


function RegCheck {
    <#
    .SYNOPSIS
    Checks if the registry key (or item) exists.

    .DESCRIPTION
    Parses REG_CHECK audit item. Checks if Registry exist and if registry item exist (optional)

    .PARAMETER valueType
    (optional) Data type representation of valueData
    POLICY_TEXT: String

    .PARAMETER valueData
    The Path to Registry. 

    .PARAMETER regOption
    (optional) Strict Registry Path Option. Default is 'MUST_EXIST'
    MUST_EXIST: Registry path must exist
    MUST_NOT_EXIST: Registry path should not exist

    .PARAMETER checkType
    (optional) Strict Data type of result
    POLICY_TEXT: String

    .PARAMETER keyItem
    (optional) Checks if Registry Item exist (or not) based on regOption

    .EXAMPLE
    RegCheck -valueType 'POLICY_TEXT' -valueData 'HKLM\Software\Policies\Google\Chrome\' -regOption 'MUST_EXIST' -checkType 'POLICY_TEXT' -keyItem 'HomepageLocation'

    .EXAMPLE
    RegCheck -valueData 'HKLM\Software\Policies\Google\Chrome\'
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [ValidateSet('POLICY_TEXT', '', IgnoreCase=$false)][String]$valueType, 
        [Parameter(Mandatory=$true, HelpMessage='Registry Path')][ValidateScript({$_.Contains("\")})][ValidateNotNullOrEmpty()][String]$valueData, 
        [ValidateSet('MUST_EXIST', 'MUST_NOT_EXIST', '', IgnoreCase=$false)][String]$regOption, 
        [ValidateSet('POLICY_TEXT', 'POLICY_DWORD', '', IgnoreCase=$false)][String]$checkType = "", 
        [String]$keyItem = "")

        $valueData = translateRegRoot $valueData      
        if (Test-Path $valueData) {                       
            if ($keyItem.Length -ne 0) {           
                $val = Get-Item -LiteralPath $valueData    
                if ($val.GetValue($keyItem, $null) -ne $null) {
                    if ($regOption.CompareTo("MUST_NOT_EXIST") -eq 0) {
                        Write-Verbose "[REG_CHECK] Registry Path and item exist, but registry option policy specifies MUST_NOT_EXIST"   
                        return $false
                    }
                    return $true
                } else {
                    if ($regOption.CompareTo("MUST_NOT_EXIST") -eq 0) {
                        return $true
                    }
                    Write-Verbose "[REG_CHECK] Unknown Key: $keyItem"     
                    return $false
                }
            }
            return $true
        } else {
            if ($regOption.CompareTo("MUST_NOT_EXIST") -eq 0) {
                return $true
            }
            Write-Verbose "[REG_CHECK] Unknown Path: $valueData"       
            return $false
        }
    Write-Host "[REG_CHECK] Unhandled"
    return $false
}


function checkRegSetting {
    <#
    .SYNOPSIS
    Compares Registry Key/Item with valueData. Helper function for RegistrySetting

    .DESCRIPTION
    Helper Function for RegistrySetting. See @RegistrySetting
    This function ASSUMES that the registry path exists and validated 

    .PARAMETER path
    The Path to Registry. Use Audit file registry path syntax
    Example: HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings

    .PARAMETER key
    Registry Key/Item to check

    .PARAMETER valueType
    Data type of valueData
    POLICY_SET: If policy is Enabled or Disabled
    POLICY_DWORD: A DWORD number or range (range is written as '[#..#]' ie: '[1..1000]'
    POLICY_TEXT: String (can be regex and used with or-operator (||))
    POLICY_MULTI_TEXT: Multiple text that it should contain, seperated by and-operator (&&)

    .PARAMETER valueData
    Data to compare with registry key/item (if it exists)

    .PARAMETER regOption
    If path and key item can exist or not
    CAN_BE_NULL: path/item does not need to exist
    CAN_NOT_BE_NULL: Path/item must exist (default)
    c
    .PARAMETER checkType
    (optional) Strict data type of registry key/item
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory=$true)][String]$path, 
        [Parameter(Mandatory=$true)][String]$key, 
        [Parameter(Mandatory=$true)][ValidateSet('POLICY_SET','POLICY_DWORD','POLICY_TEXT','POLICY_MULTI_TEXT', 'SMARTCARD_SET', 'LOCALACCOUNT_SET', IgnoreCase=$false)][String]$valueType, 
        [Parameter(Mandatory=$true)][AllowEmptyString()][String]$valueData, 
        [ValidateSet('CAN_BE_NULL','CAN_NOT_BE_NULL', '', IgnoreCase=$false)][String]$regOption="", 
        [String]$checkType="")

    $regItem = Get-Item -LiteralPath $path                
    $keyData = ""
    if ($regItem.GetValue($key, $null) -ne $null) {       
        $keyData = (Get-ItemProperty -Path $path -Name $key).$key 
    } else {                                               
        if ($regOption.CompareTo("CAN_BE_NULL") -eq 0) {  
            return $true
        } else {
            Write-Verbose "[Check-RegSettings] Unable to find key: $key"  
            return $false
        }
    }
    
    #Checking RegData with valueData passed in
    if ($valueType.CompareTo("POLICY_SET") -eq 0) {     
        $keyData = if ($keyData -eq 1) {$true} else {$false}
        return (checkPolicySet "Check-RegSetting" $valueData $keyData)
    } elseif ($valueType.CompareTo("POLICY_DWORD") -eq 0) {     
        return (checkDWORD "Check-RegSettings" $valueData $keyData $checkType)
    } elseif (($valueType.CompareTo("POLICY_TEXT") -eq 0) -or ($valueType.CompareTo("POLICY_MULTI_TEXT") -eq 0)) {
        return (checkTEXT "Check-RegSettings" $valueData $keyData $checkType)
    } elseif (($valueType.CompareTo("SMARTCARD_SET") -eq 0) -or ($valueType.CompareTo("LOCALACCOUNT_SET") -eq 0)) {
         [array]$data = $valueData.Split("||", [System.StringSplitOptions]::RemoveEmptyEntries)
         foreach ($value in $data) {
             $translatedVal = $(switch ($value.Trim()) {
                    "No action"          {0x0; break;}
                    "Lock workstation"   {0x1; break;}
                    "Force logoff"       {0x2; break;}
                    "Disconnect if a remote terminal services session" {0x3; break;}
                    "Classic - local users authenticate as themselves" {0x0; break;}
                    "Guest only - local users authenticate as guest"   {0x1; break;}
                    default {-1; break;}
                })
            if ($translatedVal -eq -1) {
                Write-Verbose "[Check-RegSettings] <$valueData> input is invalid."
                return $false
            }
            if ($translatedVal -eq $keyData) {
                if ($checkType -like "CHECK_NOT_EQUAL") {
                    Write-Verbose "[Check-RegSettings] Found match <$valueData> : <$keyData> per compliance to <$checkType>"
                    return $false
                }
                return $true
            }
         }
         Write-Verbose "[Check-RegSettings] <$keyData> not in <$valueData>"
         return $false

    } 
    Write-Verbose "[Check-RegSettings] <$valueType> Unhandled"
    return $false
}

function RegistrySetting {
    <#
    .SYNOPSIS
    Check the value of the registry key.

    .DESCRIPTION
    Parses REGISTRY_SETTINGS for compliance check and compares value with registry key

    .PARAMETER valueType
    Data type of valueData
    POLICY_SET: If policy is 'Enabled' or 'Disabled'
    POLICY_DWORD: A DWORD number or range (range is written as '[#..#]' ie: '[1..1000]'
    POLICY_TEXT: String (can be regex and used with or-operator ex: ' *.exe || *.dll ')
    POLICY_MULTI_TEXT: Multiple text that it should contain, seperated by and-operator (&&)

    .PARAMETER valueData
    Data to compare with registry key/item (if it exists)

    .PARAMETER regKey
    The Path to Registry. sUse Audit file registry path syntax
    Example: HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings

    .PARAMETER keyItem
    Registry Key/Item to check

    .PARAMETER checkType
    (optional) Strict data type of registry keyItem

    .PARAMETER regOption
    (optional) If path and key item can exist or not
    CAN_BE_NULL: path/item does not need to exist
    CAN_NOT_BE_NULL: Path/item must exist

    .PARAMETER regEnum
    (optional) Enumerate the registry key and check subkeys
    ENUM_SUBKEYS: enumerate subkeys

    .EXAMPLE
    RegistrySetting -valueType 'POLICY_TEXT' -valueData '*.mil || *.net' -regKey 'HKLM\Software\Policies\Google\Chrome\' -regItem 'EnterpriseWebStoreURL'
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory=$true)][ValidateSet('POLICY_SET','POLICY_DWORD','POLICY_TEXT','POLICY_MULTI_TEXT', 'SMARTCARD_SET', 'LOCALACCOUNT_SET', IgnoreCase=$false)][String]$valueType, 
        [Parameter(Mandatory=$true)][AllowEmptyString()][String]$valueData, 
        [Parameter(Mandatory=$true)][String]$regKey, 
        [Parameter(Mandatory=$true)][String]$regItem, 
        [String]$checkType="", 
        [ValidateSet('CAN_BE_NULL', 'CAN_NOT_BE_NULL','', IgnoreCase=$false)][String]$regOption="",
        [ValidateSet('ENUM_SUBKEYS', '', IgnoreCase=$false)][String]$regEnum="")

    $regKey = translateRegRoot $regKey   
    if (Test-Path $regKey) {
        if ($regEnum.CompareTo("ENUM_SUBKEYS") -eq 0) {
            #enumerate subkeys
            $subkeys = Get-ChildItem $regKey
            $passed = $false
            foreach ($subpath in $subkeys) {
                $passed = $passed -or (checkRegSetting $subpath.PSPath $regItem $valueType $valueData $regOption $checkType)
            }
            return $passed
        } else {
            return checkRegSetting $regKey $regItem $valueType $valueData $regOption $checkType
        }
    } else {
        if ($regOption.CompareTo("CAN_BE_NULL") -eq 0) {  
            return $true
        } else {
            Write-Verbose "[RegistrySetting] Path does not exist $regKey"
            return $false
        }
    }
}

function FileCheck {
    <#
    .SYNOPSIS
    Check if whether the file exists or not.

    .DESCRIPTION
    Parses FILE_CHECK for compliance check and determines if file exists or not

    .PARAMETER valueType
    (optional) Data type of valueData
    POLICY_TEXT: String

    .PARAMETER valueData
    Full path to file

    .PARAMETER fileOption
    Whether the file should exist or not
    MUST_EXIST: file should exist
    MUST_NOT_EXIST: file should not exist

    .EXAMPLE
    FileCheck -valueType 'POLICY_TEXT' -valueData '%programfiles% (x86)\Google\Chrome\Application\chrome.exe' -fileOption 'MUST_EXIST'
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [ValidateSet('POLICY_TEXT', '', IgnoreCase=$false)][String]$valueType, 
        [Parameter(Mandatory=$true)][String]$valueData, 
        [ValidateSet('MUST_EXIST', 'MUST_NOT_EXIST', IgnoreCase=$false)][Parameter(Mandatory=$true)][String]$fileOption)

    $fileExist = $false
    $valueData = [System.Environment]::ExpandEnvironmentVariables($valueData)
    if (Test-Path $valueData) {                        
        $fileExist = $true
    } else {
        $fileExist = $false
    }
    if ($fileOption.CompareTo("MUST_EXIST") -eq 0 -and $fileExist) {     
        return $true
    } elseif($fileOption.CompareTo("MUST_NOT_EXIST") -eq 0 -and -not $fileExist) {
        return $true
    } else {
        Write-Verbose "[FileCheck] Expected <$fileOption> : Received [exists: $fileExist]"
        return $false
    }

}


function ServicePolicy {
    <#
    .SYNOPSIS
    Check for startup values defined in 'System Services' Registry

    .DESCRIPTION
    Parses SERVICE_POLICY for compliance audit check and compares startup values. Looks inside 'HKLM\SYSTEM\CurrentControlSet\Services\' registry

    .PARAMETER valueType
    (optional) Data type of valueData
    SERVICE_SET: String (see valueData)

    .PARAMETER valueData
    Check if startup value is the following type
    Automatic
    Manual
    Disable

    .PARAMETER serviceName
    Name of the service

    .EXAMPLE
    ServicePolicy -valueType 'SERVICE_SET' -valueData 'Automatic' -serviceName 'gupdate'
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [ValidateSet('SERVICE_SET','', IgnoreCase=$false)][String]$valueType, 
        [Parameter(Mandatory=$true)][ValidateSet('Automatic', 'Manual','Disable', IgnoreCase=$false)][String]$valueData, 
        [Parameter(Mandatory=$true)][String]$serviceName)

    $key_path = $script:service_policy_key + $serviceName
   
    if (RegCheck "POLICY_TEXT" $key_path "MUST_EXIST" "POLICY_DWORD" $script:service_policy_item) {
        $idx = $key_path.IndexOf("\")
        $key_path = $key_path.Insert($idx, ":") 
        $policyData = (Get-ItemProperty -Path $key_path -Name $script:service_policy_item).$script:service_policy_item
        if (($valueData.CompareTo("Automatic") -eq 0 -and $policyData -eq $script:SERVICE_POLICY_AUTOMATIC) `
            -or ($valueData.CompareTo("Manual") -eq 0 -and $policyData -eq $script:SERVICE_POLICY_MANUAL) `
            -or ($valueData.CompareTo("Disable") -eq 0 -and $policyData -eq $script:SERVICE_POLICY_DISABLE)
        ) {
           return $true
        } else {
            Write-Verbose "[ServicePolicy] Policy not correct, received < $policyData >"
            return $false
        }
    } else {
        Write-Verbose "[ServicePolicy] Unable to get Registry Item"
        return $false
    }
    
}


function FileVersion {
    <#
    .SYNOPSIS
    Check if the version of the file specified by the file field 

    .DESCRIPTION
    Parses FILE_VERSION audit item to check the file version

    .PARAMETER valueType
    (optional) Data type of valueData
    POLICY_FILE_VERSION: Version String (ie: #.###.##) (ex: 11.0.123.3)

    .PARAMETER valueData
    File Version string (see valueType)

    .PARAMETER file
    Full path to the file to be checked

    .PARAMETER fileOption
    (optional) Whether the file should exist or not
    MUST_EXIST: File should exist (default)
    MUST_NOT_EXIST: File should not exist

    .PARAMETER checkType
    (optional) If file version should meet the following criteria based on valueData
    CHECK_EQUAL (default)
    CHECK_NOT_EQUAL
    CHECK_GREATER_THAN_OR_EQUAL
    CHECK_GREATER_THAN
    CHECK_LESS_THAN_OR_EQUAL
    CHECK_LESS_THAN

    .EXAMPLE
    FileVersion -valueType 'POLICY_FILE_VERSION' -valueData '15.9' -file 'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe' -fileOption 'MUST_EXIST' -checkType 'CHECK_GREATER_THAN_OR_EQUAL'
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('POLICY_FILE_VERSION', '', IgnoreCase=$false)][String]$valueType, 
        [Parameter(Mandatory=$true)][System.Version]$valueData, 
        [Parameter(Mandatory=$true)][String]$file, 
        [ValidateSet('MUST_EXIST', 'MUST_NOT_EXIST', '', IgnoreCase=$false)][String]$fileOption, 
        [ValidateSet('CHECK_EQUAL', 'CHECK_NOT_EQUAL', 'CHECK_GREATER_THAN_OR_EQUAL','CHECK_GREATER_THAN' , 'CHECK_LESS_THAN_OR_EQUAL','CHECK_LESS_THAN','',IgnoreCase=$false)][String]$checkType="")
    $file = [System.Environment]::ExpandEnvironmentVariables($file)
    if ((fileCheck "POLICY_TEXT" $file "MUST_EXIST") -and ($fileOption.CompareTo("MUST_EXIST") -eq 0 -or $fileOption.CompareTo("") -eq 0)) { 
       [System.Version]$fv = (Get-Item -Path $file).VersionInfo.ProductVersion
        if (($checkType.CompareTo("CHECK_GREATER_THAN_OR_EQUAL") -eq 0 -and $fv -ge $valueData) `
            -or ($checkType.CompareTo("CHECK_GREATER_THAN") -eq 0 -and $fv -gt $valueData) `
            -or ($checkType.CompareTo("CHECK_LESS_THAN") -eq 0 -and $fv -lt $valueData) `
            -or ($checkType.CompareTo("CHECK_LESS_THAN_OR_EQUAL") -eq 0 -and $fv -le $valueData) `
            -or (($checkType.CompareTo("CHECK_EQUAL") -eq 0 -or $checkType.CompareTo("") -eq 0) -and $fv -eq $valueData) `
            -or ($checkType.CompareTo("CHECK_NOT_EQUAL") -eq 0 -and $fv -ne $valueData) 
            ) 
        {
            return $true
        } else { 
            Write-Verbose "[FileVersion] Version did not meet criteria: $fv $checkType $valueData"
            return $false
        }
        
    } elseif ((fileCheck "POLICY_TEXT" $file "MUST_NOT_EXIST") -and $fileOption.CompareTo("MUST_NOT_EXIST") -eq 0) {
        return $true
    } else {
        Write-Verbose "[FileVersion] does not meet file_option criteria"
        return $false
    }
}


function LockoutPolicy {
    <#
    .SYNOPSIS
    Check Local Lockout Policy under "Security Settings -> Account Policies -> Account Lockout Policy" 
    
    .DESCRIPTION
    Parses LOCKOUT_POLICY audit item to check the lockout policy is up to standard. Uses Windows Function NetUserModalsGet. Must be running as Administrator

    .PARAMETER valueType
    Data type of valueData
    POLICY_DWORD: valueData is a regular Integer
    TIME_MINUTE: valueData is represented in minutes

    .PARAMETER valueData
    Value to be compared with a certain lockout policy

    .PARAMETER lockoutPolicy
    The lockout policy to be checked
    LOCKOUT_DURATION
    LOCKOUT_THRESHOLD
    LOCKOUT_RESET

    .PARAMETER checkType
    (optional) If lockout policy should meet the following criteria based on valueData
    CHECK_EQUAL (default)
    CHECK_NOT_EQUAL
    CHECK_GREATER_THAN_OR_EQUAL
    CHECK_GREATER_THAN
    CHECK_LESS_THAN_OR_EQUAL
    CHECK_LESS_THAN

    .EXAMPLE
    LockoutPolicy -valueType 'TIME_MINITE' -valueData '10' -lockoutPolicy LOCKOUT_DURATION -checkType 'CHECK_GREATER_THAN_OR_EQUAL'
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [ValidateSet('POLICY_DWORD', 'TIME_MINUTE',IgnoreCase=$false)][String]$valueType, 
        [Parameter(Mandatory=$true)][String]$valueData, 
        [Parameter(Mandatory=$true)][ValidateSet('LOCKOUT_DURATION', 'LOCKOUT_THRESHOLD', 'LOCKOUT_RESET', IgnoreCase=$false)][String]$lockoutPolicy, 
        [ValidateSet('CHECK_EQUAL', 'CHECK_NOT_EQUAL', 'CHECK_GREATER_THAN_OR_EQUAL','CHECK_GREATER_THAN' , 'CHECK_LESS_THAN_OR_EQUAL','CHECK_LESS_THAN','',IgnoreCase=$false)][String]$checkType=""
    )

    process {
        $net = New-Object NetSecurity.NetWrapper
        $policy = $(switch -Regex ($lockoutPolicy) {
            "LOCKOUT_DURATION" { $script:LOCKOUT_DURATION; break;}
            "LOCKOUT_THRESHOLD" {$script:LOCKOUT_THRESHOLD; break;}
            "LOCKOUT_RESET" {$script:LOCKOUT_OBSV_WIN; break;}
        })

        $policyItems = $net.NetUserModalsGet(3)
        if ($policyItems -eq $null) {
            Write-Verbose "[LOCKOUT_POLICY] Unable to get Net User Modals. Make sure running as administrator"
            return $false
        }

        return (checkDWORD "LOCKOUT_POLICY" $valueData $policyItems[$policy] $checkType)
    }


}

function PasswordPolicy {
    <#
    .SYNOPSIS
    Check Local Password Policy under "Windows Settings -> Security Settings -> Account Policies -> Password Policy"

    .DESCRIPTION
    Parses PASSWORD_POLICY audit item to check the password policy is up to standard. Uses Windows Function NetUserModalsGet. Must be running as Administrator

    .PARAMETER valueType
    Data type of valueData
    POLICY_DWORD: valueData is a regular Integer
    TIME_DAY: valueData is represented in number of days
    POLICY_SET: check if policy is Enabled or Disabled

    .PARAMETER valueData
    Value to be compared with a certain lockout policy

    .PARAMETER passwordPolicy
    The password policy to be checked
    ENFORCE_PASSWORD_HISTORY
    MAXIMUM_PASSWORD_AGE
    MINIMUM_PASSWORD_AGE
    MINIUM_PASSWORD_LENGTH
    COMPLEXITY_REQUIREMENTS
    REVERSIBLE_ENCRYPTION
    FORCE_LOGOFF

    .PARAMETER checkType
    (optional) If password policy should meet the following criteria based on valueData
    CHECK_EQUAL (default)
    CHECK_NOT_EQUAL
    CHECK_GREATER_THAN_OR_EQUAL
    CHECK_GREATER_THAN
    CHECK_LESS_THAN_OR_EQUAL
    CHECK_LESS_THAN

    .EXAMPLE
    PasswordPolicy -value_type 'POLICY_SET' -valueData 'Enabled' -passwordPolicy REVERSIBLE_ENCRYPTION
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [ValidateSet('POLICY_DWORD', 'TIME_DAY', 'POLICY_SET',IgnoreCase=$false)][String]$valueType, 
        [Parameter(Mandatory=$true)][String]$valueData, 
        [Parameter(Mandatory=$true)][ValidateSet('ENFORCE_PASSWORD_HISTORY', 'MAXIMUM_PASSWORD_AGE', 'MINIMUM_PASSWORD_AGE', 'MINIMUM_PASSWORD_LENGTH', 'COMPLEXITY_REQUIREMENTS',
            'REVERSIBLE_ENCRYPTION','FORCE_LOGOFF', IgnoreCase=$false)][String]$passwordPolicy, 
        [ValidateSet('CHECK_EQUAL', 'CHECK_NOT_EQUAL', 'CHECK_GREATER_THAN_OR_EQUAL','CHECK_GREATER_THAN' , 'CHECK_LESS_THAN_OR_EQUAL','CHECK_LESS_THAN','',IgnoreCase=$false)][String]$checkType=""
    )

    process {
        $net = New-Object NetSecurity.NetWrapper
        $policy = $(switch -Regex ($passwordPolicy) {
                "ENFORCE_PASSWORD_HISTORY" { $script:PASS_HIST_LEN; break;} #LEVEL 0 
                "MAXIMUM_PASSWORD_AGE" {$script:MAX_PASS_AGE; break;} #LEVEL 0 - seconds (-1 means forever)
                "MINIMUM_PASSWORD_AGE" {$script:MIN_PASS_AGE; break;} #LEVEL 0 - seconds
                "MINIMUM_PASSWORD_LENGTH" {$script:MIN_PASS_LEN; break;} #LEVEL 0 
                "COMPLEXITY_REQUIREMENTS" {$script:PASS_COMPLEX; break;} #LEVEL 
                "REVERSIBLE_ENCRYPTION" {$script:REV_ENCRYPT; break;} #LEVEL 
                "FORCE_LOGOFF" {$script:FORCE_LOGOFF; break;} #LEVEL 0 - seconds (-1 means forever)
        })
        $policyItems = $net.NetUserModalsGet(0);
        if ($policyItems -eq $null) {
                Write-Verbose "[PasswordPolicy] Unable to get Net User Modals. Make sure running as Administrator"
                return $false
        }
        if (!($valueType -like "POLICY_SET")) {
            return (checkDWORD "PasswordPolicy" $valueData $policyItems[$policy] $checkType)
        } else {
            if ($policy -eq $script:REV_ENCRYPT) {
                return (checkPolicySet "PasswordPolicy" $valueData $net.hasRevEncryption())
            } elseif ($policy -eq $script:PASS_COMPLEX) {
                 return (checkPolicySet "PasswordPolicy" $valueData $net.hasComplexity())
            } elseif ($policy -eq $script:FORCE_LOGOFF) {
               $value = if ($policyItems[$policy] -eq 1) {$true} else {$false} 
                return (checkPolicySet "PasswordPolicy" $valueData $value)
            }

        }
    }
}

function AuditPolicySubCategory {
    <#
    .SYNOPSIS
    Check Local Policy Subcategories for users

    .DESCRIPTION
    Parses AUDIT_POLICY_SUBCATEGORY audit item to check the user policy subcategory. Uses Windows auditpol.exe. Must be running as Administrator

    .PARAMETER valueType
    Data type of valueData
    AUDIT_SET: "Success", "Failure", "Success, Failure", "No Auditing"

    .PARAMETER valueData
    Value to be compared with a certain subcategory
    Values can be "Success", "Failure", "Success, Failure", "No Auditing"

    .PARAMETER audit_policy_subcategory
    A user policy subcategory

    .EXAMPLE
    AuditPolicySubCategory -valueType AUDIT_SET -valueData "Success, Failure" -audit_policy_subcategory "IPsec Main Mode"
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [ValidateSet('AUDIT_SET', IgnoreCase=$false)][String]$valueType, 
        [Parameter(Mandatory=$true)][String]$valueData, 
        [Parameter(Mandatory=$true)][String]$audit_policy_subcategory,
        [String]$checkType=""
    )

    $policyInfo = auditpol.exe /get /category:* | Select-String $audit_policy_subcategory | Where-Object {$_ -match ("^[ ]*"+$audit_policy_subcategory + "[ ]+")} | Select-Object -First 1
    if ($policyInfo -eq $null) {
        Write-Verbose "[AuditPolicySubCategroy] SubCategory <$audit_policy_subcategory> not found"
        return $false
    }
    $policyValue = ($policyInfo -replace $audit_policy_subcategory,"").Trim()

    [array]$data = $valueData.Split("||", [System.StringSplitOptions]::RemoveEmptyEntries);
    $found = $false
    foreach ($setting in $data) {
        if ($setting.Trim() -like ("Success, Failure")) {
            $setting = "Success and Failure"
        }
        if ($policyValue -like $setting.Trim()) {
            $found = $true
            break
        }
    }
    if ($found) {
        return $true
    } else {
        Write-Verbose "[AuditPolicySubCategory] Settings do not match. Expect <$valueData>, Received <$policyValue>"
        return $false
    }
}


function CheckAccount {
   <#
    .SYNOPSIS
    Check Admin and Guest Account Names and enabled status

    .DESCRIPTION
    Parses CHECK_ACCOUNT audit item to check the Admin and Guest values. Uses Windows SceGetSecurityProfileInfo. Must be running as Administrator

    .PARAMETER valueType
    Data type of valueData
    POLICY_SET: 'Enabled' or 'Disabled'
    POLICY_TEXT: Name of Admin or Guest Name

    .PARAMETER valueData
    Value to be compared with a certain Account value
    Look at valueType for valid input

    .PARAMETER accountType
    Guest or Admin account
    ADMINISTRATOR_ACCOUNT
    GUEST_ACCOUNT

    .PARAMETER checkType
    (optional) Not Used

    .EXAMPLE
    CheckAccount -valueType POLICY_TEXT -valueData "Admin Acc Name" -accountType ADMINISTRATOR_ACCOUNT
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [ValidateSet('POLICY_SET','POLICY_TEXT', IgnoreCase=$false)][String]$valueType, 
        [Parameter(Mandatory=$true)][String]$valueData, 
        [Parameter(Mandatory=$true)][ValidateSet('ADMINISTRATOR_ACCOUNT', 'GUEST_ACCOUNT',IgnoreCase=$false)][String]$accountType, 
        [String]$checkType=""
    )
    process {
        $net = New-Object NetSecurity.NetWrapper
        $accName = ""
        if ($accountType -like "ADMINISTRATOR_ACCOUNT") {
            $accName = $net.LSAGetAccountName($script:ADMIN_ACCOUNT)
        } else {
            $accName = $net.LSAGetAccountName($script:GUEST_ACCOUNT)
        }

        if ($accName -eq $null) {
            Write-Verbose "[CheckAccount] Unable to get Account Name. Make sure running as Administrator"
            return $false
        }

        if ($valueType -like "POLICY_TEXT") {
            return (checkTEXT "CheckAccount" $valueData $accName $checkType)
        } else {
            $flags = $net.GetFlags($accName)
            $accEnabled  = !(($flags -band $script:UF_ACCOUNTDISABLE) -eq  $script:UF_ACCOUNTDISABLE)

            return (checkPolicySet "CheckAccount" $valueData $accEnabled $checkType)
        }
    }
}

function UserRightsPolicy {
   <#
    .SYNOPSIS
    Check User Rights under "Security Settings -> Local Policies -> User Rights Assignment"

    .DESCRIPTION
    Parses USER_RIGHTS_POLICY audit item to validate user rights. Uses Windows LsaEnumerateAccountsWithUserRight. Must be running as Administrator

    .PARAMETER valueType
    Data type of valueData
    USER_RIGHT

    .PARAMETER valueData
    Account that uses this right policy
    Can contain and (&&) conditional statements to include mulitple accounts

    .PARAMETER rightType
    The rights policy

    .PARAMETER checkType
    (optional) 
    CHECK_SUBSET    Accounts must be a subset of all accounts allowed 
    CHECK_SUPERSET  Accounts must be the only item in the list

    .EXAMPLE
    UserRightsPolicy -valueType USER_RIGHT -valueData "Administrator" -rightType SeNetworkLogonRight
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [ValidateSet('USER_RIGHT', IgnoreCase=$false)][String]$valueType, 
        [Parameter(Mandatory=$true)][AllowEmptyString()][String]$valueData, 
        [Parameter(Mandatory=$true)][String]$rightType, 
        [String]$checkType=""
    )
    Process {
        $lsa = New-Object LSASecurity.LsaWrapper("")
        $output = $lsa.LSAEnurmerateAccountsWithUserRight($rightType)
        if ($output -eq $null -and $valueData.Length -eq 0) {
            return $true
        }
        if ($output -eq $null) {
            Write-Verbose "[UserRightsPolicy] Computer does not contain <$rightType>"
            return $false
        }
        $accounts = $valueData.Split("&&", [System.StringSplitOptions]::RemoveEmptyEntries)
        foreach ($acc in $accounts) {
            $acc = $acc.Trim()
            if (-not ($output -match ($acc + "$"))) {
                Write-Verbose "[UserRightsPolicy] <$rightType> does not contain account(s) <$acc>. Current Rights: <$output>"
                return $false
            }
        }
        if ($checkType -like "CHECK_SUPERSET" -and ($accounts.Count -ne $output.Count)) {
            Write-Verbose "[UserRightsPolicy] <$accounts> is not a <$checkType> of <$output>."
            return $false
        }

        return $true
    }

}

function AnonymousSidSetting {
     <#
    .SYNOPSIS
    Checks for the value defined in "Security Settings -> Local Policies -> Security Options -> Network access: Allow anonymous SID/Name translation"

    .DESCRIPTION
    Uses SceGetSecurityProfileInfo from scecli.dll to query Anonymous SID field and check if policy is checked

    .PARAMETER valueType
    Define the type of valueData

    .PARAMETER valueData
    Checks whether anonymous SID is 'Enabled' or 'Disabled'
    
    .PARAMETER checkType
    (optional) Not Used

    .EXAMPLE
    AnonymousSidSetting POLICY_SET 'Enabled'
    #>
    [OutputType([bool])]
    param(
        [ValidateSet('POLICY_SET', IgnoreCase=$false)][String]$valueType, 
        [Parameter(Mandatory=$true)][ValidateSet("Enabled", "Disabled", IgnoreCase=$true)][String]$valueData, 
        [String]$checkType=""
    )
    process {
        $net = New-Object NetSecurity.NetWrapper
        return (checkPolicySet "AnonymousSidSetting" $valueData $net.isAnonymousSIDAllowed() $checkType)
    }
}

function CompareACL {
    <#
    .SYNOPSIS
    Compares ACL Flags to Audit file ACL Values

    .DESCRIPTION
    (Helper Function) Takes the System's ACL values (Rights, InheritanceFlags, and PropagationFlags)
     and compares then to audit file ACL values 

    .PARAMETER access
    [System.Security.AccessControl] Object that contains access properties of a ACL

    .PARAMETER aclStr
    String version of ACL from NESSUS' Audit file to be compared with the access parameter 

    .PARAMETER type
    Whether the access is a FILE ACL or a REGISTRY ACL. Type can be either:
    $script:FILE = 0
    $script:REGISTRY = 1

    #>
    [OutputType([bool])]
    param(
        $access,
        [string]$aclStr,
        [int]$type
    )
    
    $rightsArr = $aclStr.Split("|", [System.StringSplitOptions]::RemoveEmptyEntries)
    $containVal = $true; 
    foreach ($rights in $rightsArr) {
        if ($type -eq $script:FILE) { #for file_acl
            $isVal = $(switch ($rights.Trim()) {
                "change permissions"                {($access.FileSystemRights.value__ -band 0x00040000) -eq 0x00040000; break;}
                "create files / write data"         {($access.FileSystemRights.value__ -band 0x00000002) -eq 0x00000002; break;}
                "create folders / append data"      {($access.FileSystemRights.value__ -band 0x00000004) -eq 0x00000004; break;}
                "delete"                            {($access.FileSystemRights.value__ -band 0x00010000) -eq 0x00010000; break;}
                "delete subfolders and files"       {($access.FileSystemRights.value__ -band 0x00000040) -eq 0x00000040; break;}
                "full control"                      {((($access.FileSystemRights.value__ -band 0x000F01FF) -eq 0x000F01FF) -or ($access.FileSystemRights.value__ -eq 268435456)); break;}
                "inherited"                         {($access.IsInherited -eq 0x00000001); break;}
                "list folder contents"              {($access.FileSystemRights.value__ -band 0x000200a9) -eq 0x000200a9; break;}
                "list folder / read data"           {($access.FileSystemRights.value__ -band 0x00000001) -eq 0x00000001; break;}
                "modify"                            {(($access.FileSystemRights.value__ -band 0x000301bf) -eq 0x000301bf) -or (($access.FileSystemRights.value__ -band -536805376) -eq -536805376); break;}                   
                "not inherited"                     {($access.IsInherited -eq 0x00000000); break;}
                "not used"                          {($true); break;}               
                "read"                              {($access.FileSystemRights.value__ -band 0x00020089) -eq 0x00020089; break;}
                "read attributes"                   {($access.FileSystemRights.value__ -band 0x00000080) -eq 0x00000080; break;}
                "read extended attributes"          {($access.FileSystemRights.value__ -band 0x00000008) -eq 0x00000008; break;}            
                "read & execute"                    {((($access.FileSystemRights.value__ -band 0x000200a9) -eq 0x000200a9) -or ($access.FileSystemRights.value__ -eq -1610612736)); break;}
                "read permissions"                  {($access.FileSystemRights.value__ -band 0x00040000) -eq 0x00040000; break;}            
                "take ownership"                    {($access.FileSystemRights.value__ -band 0x00080000) -eq 0x00080000; break;}           
                "this folder only"                  {(($access.InheritanceFlags.value__ -eq [System.Security.AccessControl.InheritanceFlags]::None.value__) -and ($access.PropagationFlags.value__ -eq [System.Security.AccessControl.PropagationFlags]::None.value__)); break;}
                # "this object only"                  {"Unknown"; break;}
                "this folder and files"             {(($access.InheritanceFlags.value__ -eq [System.Security.AccessControl.InheritanceFlags]::ObjectInherit.value__) -and ($access.PropagationFlags.value__ -eq [System.Security.AccessControl.PropagationFlags]::None.value__)); break;}
                "this folder and subfolders"        {(($access.InheritanceFlags.value__ -eq [System.Security.AccessControl.InheritanceFlags]::ContainerInherit.value__) -and ($access.PropagationFlags.value__ -eq [System.Security.AccessControl.PropagationFlags]::None.value__)); break;}
                "this folder, subfolders and files" {(($access.InheritanceFlags.value__ -eq ([System.Security.AccessControl.InheritanceFlags]::ObjectInherit.value__ -bor [System.Security.AccessControl.InheritanceFlags]::ContainerInherit.value__)) -and ($access.PropagationFlags.value__ -eq [System.Security.AccessControl.PropagationFlags]::None.value__)); break;}
                "files only"                        {(($access.InheritanceFlags.value__ -eq [System.Security.AccessControl.InheritanceFlags]::ObjectInherit.value__) -and ($access.PropagationFlags.value__ -eq [System.Security.AccessControl.PropagationFlags]::InheritOnly.value__)); break;}
                "subfolders only"                   {(($access.InheritanceFlags.value__ -eq [System.Security.AccessControl.InheritanceFlags]::ContainerInherit.value__) -and ($access.PropagationFlags.value__ -eq [System.Security.AccessControl.PropagationFlags]::InheritOnly.value__)); break;}
                "subfolders and files only"         {(($access.InheritanceFlags.value__ -eq ([System.Security.AccessControl.InheritanceFlags]::ObjectInherit.value__ -bor [System.Security.AccessControl.InheritanceFlags]::ContainerInherit.value__)) -and ($access.PropagationFlags.value__ -eq [System.Security.AccessControl.PropagationFlags]::InheritOnly.value__)); break;}
                "traverse folder / execute file"    {($access.FileSystemRights.value__ -band 0x00000020) -eq 0x00000020; break;}
                "write"                             {($access.FileSystemRights.value__ -band 0x00000116) -eq 0x00000116; break;}
                "write attributes"                  {($access.FileSystemRights.value__ -band 0x00000100) -eq 0x00000100; break;}
                "write extended attributes"         {($access.FileSystemRights.value__ -band 0x00000010) -eq 0x00000010; break;}
                default                             {$false;break;} 
            });
        } else {
            $isVal = $(switch ($rights.Trim()) {
                "full control"                      {($access.RegistryRights -band 0x000f003f) -eq 0x000f003f; break;}
                "create link"                       {($access.RegistryRights -band 0x00000020) -eq 0x00000020; break;}
                "create subkey"                     {($access.RegistryRights -band 0x00000004) -eq 0x00000004; break;}
                "delete"                            {($access.RegistryRights -band 0x00010000) -eq 0x00010000; break;}
                "enumerate subkeys"                 {($access.RegistryRights -band 0x00000008) -eq 0x00000008; break;}
                "inherited"                         {$access.IsInherited -eq 0x00000001; break;}
                "not inherited"                     {$access.IsInherited -eq 0x00000000; break;}
                "not used"                          {$true; break;}
                "notify"                            {($access.RegistryRights -band 0x00000010) -eq 0x00000010; break;}
                "query value"                       {($access.RegistryRights -band 0x00000001) -eq 0x00000001; break;}
                "read"                              {($access.RegistryRights -band 0x00020019) -eq 0x00020019; break;}
                "Read Control"                      {($access.RegistryRights -band 0x00060000) -eq 0x00060000; break;}
                "set value"                         {($access.RegistryRights -band 0x00000002) -eq 0x00000002; break;}
                "subkeys only"                      {(($access.InheritanceFlags.value__ -eq ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit)) -or ($access.InheritanceFlags.value__ -eq [System.Security.AccessControl.InheritanceFlags]::ContainerInherit)) -and ($access.PropagationFlags.value__ -eq [System.Security.AccessControl.PropagationFlags]::InheritOnly); break;}
                "this key only"                     {(($access.InheritanceFlags.value__ -eq ([System.Security.AccessControl.InheritanceFlags]::None -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit)) -or ($access.InheritanceFlags.value__ -eq [System.Security.AccessControl.InheritanceFlags]::None)) -and ($access.PropagationFlags.value__ -eq [System.Security.AccessControl.PropagationFlags]::None); break;}
                "this key and subkeys"              {(($access.InheritanceFlags.value__ -eq ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit)) -or ($access.InheritanceFlags.value__ -eq [System.Security.AccessControl.InheritanceFlags]::ContainerInherit)) -and ($access.PropagationFlags.value__ -eq [System.Security.AccessControl.PropagationFlags]::None); break;}
                "write dac"                         {($access.RegistryRights -band 0x00040000) -eq 0x00040000; break;}
                "write owner"                       {($access.RegistryRights -band 0x00080000) -eq 0x00080000; break;}
                default                             {$false;break;}
            });
        }
        $containVal = $containVal -and $isVal
    }
    return $containVal
}

function CombineACLDuplicate {
    <#
    .SYNOPSIS
    Takes an Array of [System.Security.AccessControl] Objects, combine similar ACL and returns a new list of HashTables with the new ACLs

    .DESCRIPTION
    (Helper Function) Takes an array of ACL objects and combine similar ACLs. Similar ACLs means that they have the same Rights (FileSystemRights or RegistryRights),
    IsInherited flag, IdentityReference, and AccessControlType. This function takes those similar ACLs and combine the InheritanceFlags and PropagationFlags to get the
    correct value of the Inheritance Hierachy. This also translate some FileSystemRights special privilages to a more readable format (ie: Full Control, Modify, etc)

    .PARAMETER accessList
    Array of[System.Security.AccessControl] Object that contains access properties of a ACL

    .PARAMETER type
    Whether the access is a FILE ACL or a REGISTRY ACL. Type can be either:
    $script:FILE = 0
    $script:REGISTRY = 1

    #>
    param(
        $accessList,
        [int]$type
    )
    if ($accessList -eq $null) {
        return @()
    }
    $i = 0; $access = @(1..$accessList.Length)
    $aclTable = @{}
    $accessList | foreach {$_.psobject.properties; $i++; $aclTable=@{};} | foreach {$aclTable[$_.Name] = $_.Value; $access[$i] = $aclTable}

    if ($type -eq $script:FILE) {
        foreach ($acl in $access) {
            $acl.FileSystemRights = $(switch ($acl.FileSystemRights.value__) {
                268435456 {[System.Security.AccessControl.FileSystemRights]::FullControl}
                -536805376 {[System.Security.AccessControl.FileSystemRights]::Modify -bor [System.Security.AccessControl.FileSystemRights]::Synchronize}
                -1610612736 {[System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [System.Security.AccessControl.FileSystemRights]::Synchronize}
                default {$acl.FileSystemRights}
            })
        }
        $rightsType = 'FileSystemRights'
    } else {
        $rightsType = 'RegistryRights'
    }
    $dupRights = $access | group {$_.IsInherited},{ $_.$rightsType}
    foreach ($dupAcl in $dupRights) {
        if ($dupAcl.Count -gt 1) {
            $inheritanceFlag = $dupAcl.Group[0].InheritanceFlags
            $propagationFlags = $dupAcl.Group[0].PropagationFlags
            $rights = $dupAcl.Group[0].$rightsType
            $user = $dupAcl.Group[0].IdentityReference
            $isInherited = $dupAcl.Group[0].IsInherited
            $AccessControlType = $dupAcl.Group[0].AccessControlType
            for ($i = 1; $i -lt $dupAcl.Count; $i++) {
                $inheritanceFlag = $inheritanceFlag -bor $dupAcl.Group[$i].InheritanceFlags
                $propagationFlags = $propagationFlags -band $dupAcl.Group[$i].PropagationFlags
            }
            $objACE = @{
                "InheritanceFlags"=$inheritanceFlag
                "PropagationFlags"=$propagationFlags
                "IsInherited"=$isInherited
                "AccessControlType"=$AccessControlType
                $rightsType=$rights
                "IdentityReference"=$user}
            $access += $objACE
        }
    }
    return $access
}

function FilePermissions {
     <#
    .SYNOPSIS
    Checks file and directory ACL based on Audit file configurations 

    .DESCRIPTION
    Uses Get-ACL to grab ACL information to compare with audit file ACL specifications

    .PARAMETER valueType
    Define the type of valueData. Must be of type FILE_ACL

    .PARAMETER valueData
    The name of the Global ACL defined in the Audit file (will not be used in this function. @See aclUserList) 
    
    .PARAMETER path
    String path of the file or directory

    .PARAMETER aclUserList
    The list of ACLs to search and compare. Must be in the following format:
    ACL_ITEM:
        [{user:string, acl_inheritance:string, acl_apply:string, acl_allow:string, acl_deny:string},
        {user:string, acl_inheritance:string, acl_apply:string, acl_allow:string, acl_deny:string},
        ...]

    .PARAMETER aclOption
    (optional) Whether the path can exist or not. Values can be:
    CAN_BE_NULL
    CANNOT_BE_NULL

    .PARAMETER checkType
    (not used)

    .EXAMPLE
    FilePermissions FILE_ACL 'ACL_NAME' 'C:\' $aclUserListStruct CANNOT_BE_NULL
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [ValidateSet('FILE_ACL', IgnoreCase=$false)][String]$valueType, 
        [Parameter(Mandatory=$true)][String]$valueData,
        [Parameter(Mandatory=$true)][String]$path,
        [Parameter(Mandatory=$true)]$aclUserList,
        [ValidateSet('CAN_BE_NULL', 'CANNOT_BE_NULL', '')][AllowEmptyString()][String]$aclOption, 
        [String]$checkType=""
    )

    $path = [System.Environment]::ExpandEnvironmentVariables($path)

    if (!(Test-Path $path) -and $aclOption -like 'CAN_BE_NULL') {
        return $true
    }

    foreach ($aclitem in $aclUserList) {
        if ($aclitem.contains("acl_allow")) {
            $passed = $false
            $accessList = Get-Acl $path | Select-Object -ExpandProperty Access | where {($_.IdentityReference -match ("^"+$aclitem["user"]+"|\\+"+$aclitem["user"])) -and ($_.AccessControlType -match "Allow")} 
            $access = CombineACLDuplicate $accessList $script:FILE
            foreach ($acl in $access) {
                if ((CompareACL $acl $aclitem["acl_allow"] $script:FILE) -and (CompareACL $acl $aclitem["acl_apply"] $script:FILE)) {
                    $passed = $true
                    break
                }
            }     
            if (!$passed) {
                Write-Verbose "[FilePermissions] Unable to find matching ACL in <$path>"
                Write-Verbose ($aclitem | Out-String)
                return $false
            }       
        }
        if ($aclitem.contains("acl_deny")) {
            $passed = $false
            $accessList = Get-Acl $path | Select-Object -ExpandProperty Access | where {($_.IdentityReference -match ("^"+$aclitem["user"]+"|\\+"+$aclitem["user"])) -and ($_.AccessControlType -match "Deny")} 
            $access = CombineACLDuplicate $accessList $script:FILE
            foreach ($acl in $access) {
                       
                if ((CompareACL $acl $aclitem["acl_deny"] $script:FILE) -and (CompareACL $acl $aclitem["acl_apply"] $script:FILE)) {
                    $passed =  $true
                    break
                }
            }
            if (!$passed) {
                Write-Verbose "[FilePermissions] Unable to find matching ACL in <$path>"
                Write-Verbose ($aclitem | Out-String)
                return $false
            }    
        }


    }
    return $true
}

function RegistryPermissions {
     <#
    .SYNOPSIS
    Checks REgistry ACL based on Audit file configurations 

    .DESCRIPTION
    Uses Get-ACL to grab ACL information to compare with audit file ACL specifications

    .PARAMETER valueType
    Define the type of valueData. Must be of type REG_ACL

    .PARAMETER valueData
    The name of the Global ACL defined in the Audit file (will not be used in this function. @See aclUserList) 
    
    .PARAMETER regKey
    String path of the registry

    .PARAMETER aclUserList
    The list of ACLs to search and compare. Must be in the following format:
    ACL_ITEM:
        [{user:string, acl_inheritance:string, acl_apply:string, acl_allow:string, acl_deny:string},
        {user:string, acl_inheritance:string, acl_apply:string, acl_allow:string, acl_deny:string},
        ...]

    .PARAMETER aclOption
    (optional) Whether the path can exist or not. Values can be:
    CAN_BE_NULL
    CANNOT_BE_NULL

    .PARAMETER checkType
    (not used)

    .EXAMPLE
    RegistryPermissions REG_ACL 'ACL_NAME' 'HKLM\SOFTWARE' $aclUserListStruct CANNOT_BE_NULL
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [ValidateSet('REG_ACL', IgnoreCase=$false)][String]$valueType, 
        [Parameter(Mandatory=$true)][String]$valueData,
        [Parameter(Mandatory=$true)][String]$regKey,
        [Parameter(Mandatory=$true)]$aclUserList,
        [ValidateSet('CAN_BE_NULL', 'CANNOT_BE_NULL', '')][AllowEmptyString()][String]$aclOption, 
        [String]$checkType=""
    )
    $regKey = translateRegRoot $regKey

    if (!(Test-Path $regKey) -and $aclOption -like 'CAN_BE_NULL') {
        return $true
    }

    foreach ($aclitem in $aclUserList) {
        if ($aclitem.contains("acl_allow")) {
            $passed = $false
            $accessList = Get-Acl $regKey | Select-Object -ExpandProperty Access | where {($_.IdentityReference -match ("^"+$aclitem["user"]+"|\\+"+$aclitem["user"])) -and ($_.AccessControlType -match "Allow")} 
            $access = CombineACLDuplicate $accessList $script:REGISTRY
            foreach ($acl in $access) {
                if ((CompareACL $acl $aclitem["acl_allow"] $script:REGISTRY) -and (CompareACL $acl $aclitem["acl_apply"] $script:REGISTRY)) {
                    $passed = $true
                    break
                }
            }     
            if (!$passed) {
                Write-Verbose "[RegistryPermissions] Unable to find matching ACL in <$regKey>"
                Write-Verbose ($aclitem | Out-String)
                return $false
            }       
        }
        if ($aclitem.contains("acl_deny")) {
            $passed = $false
            $accessList = Get-Acl $regKey | Select-Object -ExpandProperty Access | where {($_.IdentityReference -match ("^"+$aclitem["user"]+"|\\+"+$aclitem["user"])) -and ($_.AccessControlType -match "Deny")} 
            $access = CombineACLDuplicate $accessList $script:REGISTRY
            foreach ($acl in $access) {
                       
                if ((CompareACL $acl $aclitem["acl_deny"] $script:REGISTRY) -and (CompareACL $acl $aclitem["acl_apply"] $script:REGISTRY)) {
                    $passed =  $true
                    break
                }
            }
            if (!$passed) {
                Write-Verbose "[RegistryPermissions] Unable to find matching ACL in <$regKey>"
                Write-Verbose ($aclitem | Out-String)
                return $false
            }    
        }
    }
    return $true
}

function Report {
     <#
    .SYNOPSIS
    Determine if Report Audit is PASSED or FAILED (helper function)

    .DESCRIPTION
    Determine if Report Audit is PASSED or FAILED (helper function)

    .PARAMETER status
    String either 'PASSED' or 'FAILED'

    .EXAMPLE
    Report 'PASSED'
    #>
    [OutputType([bool])]
    param([String]$status)
    if ($status -match "FAILED") {
        return $false
    } else {
        return $true
    }
}

function ProcessAudit {
     <#
    .SYNOPSIS
    Parses Audit file using grammar tree built from Test-Compliance

    .DESCRIPTION
    Recursive function that traverses Grammar Tree executing custom_items and reports and determine conditions
    of if statements. Continue until coniditions do not meet or all necessary leaves have been reached

    .PARAMETER node
    Head node of Grammer Tree

    .PARAMETER FileAclList
    HashTable of Arrays containing File Access Control List

    .PARAMETER RegAclList
    HashTable of Arrays containing Registry Access Control List

    .PARAMETER PassThru
    Writes test objects to pipeline.

    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][psobject]$node,
        [psobject]$FileAclList,
        [psobject]$RegAclList,
        [switch]$PassThru
    )
    [array]$conditionList = @()
    foreach ($customItem in $node.items) {
        $passed = $(switch -Regex ($customItem["type"]) { #Append your own custom audit item here
            "ANONYMOUS_SID_SETTING" {AnonymousSidSetting $customItem["value_type"] $customItem["value_data"] $customItem["check_type"]; break;}
            "AUDIT_POLICY_SUBCATEGORY" {AuditPolicySubCategory $customItem["value_type"] $customItem["value_data"] $customItem["audit_policy_subcategory"] $customItem["check_type"];break;}
            "AUDIT_POWERSHELL" {AuditPowershell $customItem["value_type"] $customItem["value_data"] $customItem["powershell_args"] $customItem["only_show_cmd_output"] $customItem["ps_encoded_args"] $customItem["check_type"];break}
            "CHECK_ACCOUNT" {CheckAccount $customItem["value_type"] $customItem["value_data"] $customItem["account_type"] $customItem["check_type"];break;}
            "FILE_CHECK" {  FileCheck $customItem["value_type"] $customItem["value_data"] $customItem["file_option"]; break }
            "FILE_PERMISSIONS" {FilePermissions $customItem["value_type"] $customItem["value_data"] $customItem["file"] $FileAclList[$customItem["value_data"]] $customItem["acl_option"]}
            "FILE_VERSION" {FileVersion $customItem["value_type"] $customItem["value_data"] $customItem["file"] $customItem["file_option"] $customItem["check_type"]; break}
            "LOCKOUT_POLICY" {LockoutPolicy $customItem["value_type"] $customItem["value_data"] $customItem["lockout_policy"] $customItem["check_type"]; break;}
            "PASSWORD_POLICY" {PasswordPolicy $customItem["value_type"] $customItem["value_data"] $customItem["password_policy"] $customItem["check_type"]; break;}
            "REG_CHECK" {RegCheck $customItem["value_type"] $customItem["value_data"] $customItem["reg_option"] -keyItem $customItem["key_item"]; break}
            "REGISTRY_PERMISSIONS" {RegistryPermissions $customItem["value_type"] $customItem["value_data"] $customItem["reg_key"] $RegAclList[$customItem["value_data"]] $customItem["acl_option"] $customItem["check_type"]}
            "REGISTRY_SETTING" { RegistrySetting $customItem["value_type"] $customItem["value_data"] $customItem["reg_key"] $customItem["reg_item"] $customItem["check_type"] $customItem["reg_option"] $customItem["reg_enum"];break}
            "REPORT" {Report $customItem["status"]; break}
            "SERVICE_POLICY" {ServicePolicy $customItem["value_type"] $customItem["value_data"] $customItem["service_name"]; break}
            "USER_RIGHTS_POLICY" {UserRightsPolicy $customItem["value_type"] $customItem["value_data"] $customItem["right_type"] $customItem["check_type"]; break;}
            default { $false; Write-Host ("#####Unknown Type#####" + $customItem["type"]) -BackgroundColor Red}
        })
        if ($node.type -ne $script:IF_NODE) {
            if ((-not $passed)) {
                $width = $customItem.Keys.length | Sort-Object | Select-Object -Last 1
                $str = "`n"
                $customItem.GetEnumerator() | ForEach-Object {
                    $str += ("  {0, -$width} : {1}`n" -F $_.Key, $_.Value) 
                }
                Write-Verbose $str 
                if ($customItem['severity'] -match "^LOW$|^HIGH$|^MEDIUM$") {
                    Write-Host "WARNING" $customItem["description"] -ForegroundColor Magenta
                } else {
                    Write-Host "FAILED" $customItem["description"] -ForegroundColor Red
                }
                if ($PassThru) {
                    [PSCustomObject]@{
                        Info = $customItem["info"]
                        Description = $customItem["description"]
                        Type = $customItem["type"]
                        ValueData = $customItem["value_data"]
                        PowerShellArgs = $customItem["powershell_args"]
                        ValueType = $customItem["value_type"]
                        Passed = $false
                    }
                }
            } else {
                Write-Host "PASSED" $customItem["description"] -ForegroundColor Green
                if ($PassThru) {
                    [PSCustomObject]@{
                        Info = $customItem["info"]
                        Description = $customItem["description"]
                        Type = $customItem["type"]
                        ValueData = $customItem["value_data"]
                        PowerShellArgs = $customItem["powershell_args"]
                        ValueType = $customItem["value_type"]
                        Passed = $true
                    }
                }
            }
        }
         
        $conditionList += $passed
    }

    if ($node.type -eq $script:IF_NODE) {
        if ($conditionList.Count -eq 0) {
            return #BAIL
        } else {
            $passed = $false
            if ($node.condition.CompareTo("or") -eq 0) {
                $tempBool = $false  #doesn't matter for 1 false in an OR operation, as long as theres one true
                foreach ($bool in $conditionList) {
                    $tempBool = $tempBool -or $bool
                }
                $passed = $tempBool
            } else { #and
                $tempBool = $true  #doesn't matter for 1 true in an AND operation, as long as its ALL true
                foreach ($bool in $conditionList) {
                    $tempBool = $tempBool -and $bool
                }
                $passed = $tempBool
            }
            if ($passed -and $node.thenNode -ne $null) {
                return (ProcessAudit $node.thenNode $FileAclList $RegAclList)
               
            } elseif ((-not $passed) -and $node.elseNode -ne $null){
                return (ProcessAudit $node.elseNode $FileAclList $RegAclList)
            }
        }
    } elseif ($node.type -eq $script:THEN_NODE -or $node.type -eq $script:ELSE_NODE -or $node.type -eq $script:HEAD_NODE) { #they do the same thing really..
        foreach ($ifNode in $node.ifNodes) {
            ProcessAudit $ifNode $FileAclList $RegAclList
        }
        return
    }else {
        Write-Verbose "[ProcessAudit] Unknown Node Type"
        return
    }
}


<#
    Top ACL Structure:
        { "ACL_NAME": [ACL_ITEM, ...], "ACL_NAME_2":[ACL_ITEM, ...], ... }
    ACL_ITEM:
        {user:string, acl_inheritance:string, acl_apply:string, acl_allow:string, acl_deny:string}


    Nodes { type:int, condition:string, items:[CUSTOM_ITEM], thenNode:Nodes, elseNode:Nodes, ifNodes:[Nodes], parent:Node}
    CUSTOM_ITEM: {variable:value, ...}
#>


function Test-Compliance {
     <#
    .SYNOPSIS
    Tests a system for compliance aganst compliance checks defined in a Nessus audit file.

    .DESCRIPTION
    Tests a system for compliance aganst compliance checks defined in a Nessus audit file.

    Script currently supports following audit items:
        ANONYMOUS_SID_SETTING
        AUDIT_POLICY_SUBCATEGORY
        AUDIT_POWERSHELL
        CHECK_ACCOUNT
        FILE_CHECK
        FILE_PERMISSIONS
        FILE_VERSION
        LOCKOUT_POLICY
        PASSWORD_POLICY
        REG_CHECK
        REGISTRY_PERMISSIONS
        REGISTRY_SETTING
        REPORT
        SERVICE_POLICY
        USER_RIGHTS_POLICY

    .PARAMETER Path
    The path of the audit file.

    .PARAMETER PassThru
    Writes test objects to pipeline.

    .EXAMPLE
    Test-Compliance -Path 'C:\File.audit' -Verbose
    #>
    [CmdletBinding()]
    [OutputType([void])] 
    Param(
        [Parameter(Mandatory=$true, HelpMessage='The path of the audit file')]
        [string]$Path,

        [Parameter(Mandatory=$false, HelpMessage='Writes test objects to pipeline')]
        [switch]$PassThru
    )

        $Path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)


    if (!(Test-Path $Path)) {
        Write-Host "$Path does not exist"
        return
    }

    $fd = Get-Content $Path

    $prevItem = ""                       #for multi-line definitions
    $lineNum = 0                         #line number for debugging
    $IsFileACL = $false                  #parsing file acls
    $IsRegACL = $false                   #parsing registry acls
    $file_acl = @{}                      #Contains Global File Access Control List declaration
    $reg_acl = @{}                       #Contains Global Registry Access Control List declaration
    $aclItem = @{}                       #Contains HashTable of a <user> item for ACL
    $aclItemList = @()                   #Array of HashTable defined as either <registry_acl> or <file_acl> or <acl>
    $aclName = ""                        #Global name of the file/registry ACL
    $IsAclUser = $false                  #parsing <user> definitions
    $IsCustomItem = $false               #parsing custom_item
    $customItem = @{}                    #custom_item container
    $isIf = $false                       #used to parse condition item
    $head = @{
        type = $script:HEAD_NODE         #Type of NODE
        condition = ""                   #for IF-Nodes. Can contain 'or', 'and', ''
        items = @()                      #custom_item and report items (array of hashtables)
        thenNode = $null                 #A reference to a THEN_NODE that branches off the IF_NODE
        elseNode = $null                 #A reference to a ELSE_NODE that branches off the IF_NODE
        ifNodes = @()                    #HEAD_NODE,ELSE_NODE,THEN_NODE can contain multiple IF_NODE that it will need to process
        parent = $null                   #Used in Building the grammar tree, specified the object that hold its reference
    }
    $headNode = New-Object psobject -Property $head
    $currentNode = $headNode             #Current Node that we are on
    foreach ($line in $fd) {
        $lineNum++
        $line = $line.Trim()
        #Identifying empty lines or Comments
        if ($line.Length -ge 1) {
            if ($line[0] -eq '#') {
                continue                 #Comment so skip
            }
        } elseif ($line.Length -eq 0) {
            continue                    #skip empty lines
        }

        #Go up to parent if end of statement
        if ($line -match "</if>|</then>|</else>") {
            if ($currentNode.parent -ne $null) {
                $currentNode = $currentNode.parent
            }
        }

        #extract condition type 'or','and'
        if ($isIf) {                     
            if ($line -match "<condition type.*>") {
                $cond = $line.Trim(">").Split(":")
                $cond[1] = $cond[1] -replace "`"", ""
                $currentNode.condition = $cond[1].Trim()
            } 
            $isIf = $false
        }

        #Identifying Branches of If Statements
        if ($line.CompareTo("<if>") -eq 0) {
            $isIf = $true                 #set to true so we can start parsing the items as a condition item
            $ifNode = @{
                type = $script:IF_NODE
                condition = ""
                items = @()
                thenNode = $null     
                elseNode = $null     
                ifNodes = @()       
                parent = $currentNode
            }
            $tempNode = New-Object psobject -Property $ifNode 
            $currentNode.ifNodes += $tempNode
            $currentNode = $tempNode
        } elseif ($line.CompareTo("<then>") -eq 0) {
            $thenNode = @{
                type = $script:THEN_NODE
                condition = ""
                items = @()
                thenNode = $null     
                elseNode = $null     
                ifNodes = @()        
                parent = $currentNode 
            }
            if ($currentNode.type -ne $script:IF_NODE) {
                Write-Host "[THEN_NODE:$lineNum] Current Parent node isn't a IF_NODE, something is wrong with syntax... bail" -BackgroundColor Red
                break
            } else {
                $tempNode = New-Object psobject -Property $thenNode
                $currentNode.thenNode = $tempNode
                $currentNode = $tempNode
                
            }
        } elseif ($line.CompareTo("<else>") -eq 0) {
            $elseNode = @{
                type = $script:ELSE_NODE
                condition = ""
                items = @()
                thenNode = $null      #can have 1 reference
                elseNode = $null      #can have 1 reference
                ifNodes = @()         #will be empty for If-Nodes 
                parent = $currentNode #parent node is what we came from
            }
            if ($currentNode.type -ne $script:IF_NODE) {
                Write-Host "[ELSE_NODE:$lineNum] Current Parent node isn't a IF_NODE, something is wrong with syntax... bail" -BackgroundColor Red
                break
            } else {
                $tempNode = New-Object psobject -Property $elseNode
                $currentNode.elseNode = $tempNode
                $currentNode = $tempNode
            }
        }


        #APPENDING TO CURRENT NODE ITEMS List
        if ($line -match "^</custom_item>$|^</report>$|^</item>$") {
            $IsCustomItem = $false
            $currentNode.items += $customItem
            $customItem = @{} #new container
        }

        #APPENDING TO Respective ACL list
        if ($line -match "^</acl>$|^</file_acl>$|^</registry_acl>$") {
            if ($IsFileACL) {
                $file_acl.Add($aclName, $aclItemList)
            } elseif ($IsRegACL) {
                $reg_acl.Add($aclName, $aclItemList)
            } else {
                Write-Host "[ACL_Parsing:$lineNum] ACL Missing Header"
                break
            }

            $IsFileACL = $false
            $IsRegACL = $false
            $aclItemList = @()
            $aclName = ""
        }elseif ($line -match "^</user>$") {
            $aclItemList += $aclItem
            $IsAclUser = $false
            $aclItem = @{}
        }

        if ($IsAclUser) {
            [String]$item = $line.Substring(0, $line.IndexOf(':')).Trim()
            [String]$data = ($line.Substring($line.IndexOf(':')+1) -replace '"', '').Trim()
            $aclItem.Add($item, $data)
        }


        #Parses the custom item and saves them into a hash table for easy access
        if ($IsCustomItem) {
            $line = $line.Trim()  #get rid of all start and end white spaces
            $firstQuoteIdx = $line.IndexOf('"') #find the first quote
            if (($line.Length-1) -eq $firstQuoteIdx) {     # the first quote is the last quote. This (...")
                if ($prevItem -eq "") {
                    Write-Host "[Parsing:CustomItem:$lineNum] Missing starting Quote <$line>" -BackgroundColor Red
                    break
                }
                $customItem[$prevItem] += "`r`n" +($line -replace '"','')
                $prevItem = ""
            }elseif ($firstQuoteIdx -eq -1) { #no quotes at all. Could either be a new single line item OR a continuation of previous item. This (...)
                if ($prevItem -ne "") { #part of the previous string
                    $customItem[$prevItem] += "`r`n" + $line
                } else { # A new item
                    [String]$item = $line.Substring(0, $line.IndexOf(':')).Trim()
                    [String]$data = $line.Substring($line.IndexOf(':') + 1).Trim()
                    if ($customItem.Contains($item)) {
                        $customItem[$item] += " " + $data
                    } else {
                        $customItem.Add($item, $data)
                    }
                }
            } elseif ((($line.Length-1) -ne $firstQuoteIdx) -and $line[-1] -eq '"') { #first quote exist on same line as last quote. This ("...")
                [String]$data = ($line.Substring($firstQuoteIdx) -replace '"','')
                [String]$item = $line.Substring(0, $line.IndexOf(':')).Trim()
                if ($customItem.Contains($item)) {
                    $customItem[$item] += " " + $data
                } else {
                    $customItem.Add($item, $data)
                }
            } elseif ( (($line.Length-1) -ne $firstQuoteIdx) -and $line[-1] -ne '"') { #first quote exist but last quote doesn't. This ("...)
                [String]$item = $line.Substring(0, $line.IndexOf(':')).Trim()
                [String]$data = ($line.Substring($firstQuoteIdx) -replace '"','')
                if ($customItem.Contains($item)) {
                    $customItem[$item] += " " + $data
                } else {
                    $customItem.Add($item, $data)
                }
                $prevItem = $item
            } 
        }


        #Identifying type of audit item
        if ($line.CompareTo("<custom_item>") -eq 0) {
            $IsCustomItem = $true
        } elseif ($line -match "<report.*>") {
            $IsCustomItem = $true
            $customItem.Add("type","REPORT");
            $status = $line.Trim(">").Split(":") -replace "`"", ""
            $customItem.Add("status",$status)
        } elseif ($line -match "<file_acl.*>") {
            $IsFileACL = $true
            $aclName = $line.Trim(">").Substring($line.IndexOf(':')+1).Trim() -replace "`"", ""
        } elseif ($line -match "<registry_acl.*>") {
            $IsRegACL = $true
            $aclName = $line.Trim(">").Substring($line.IndexOf(':')+1).Trim() -replace "`"", ""
        } elseif ($line -match "<user.*>") {
            $IsAclUser = $true
             $name = $line.Trim(">").Substring($line.IndexOf(':')+1).Trim() -replace "`"", ""
             $aclItem.Add("user", $name)
        }
        

    }

    #Process the audit file based on the grammar tree that was just created
    ProcessAudit $headNode $file_acl $reg_acl -PassThru:$PassThru
}

