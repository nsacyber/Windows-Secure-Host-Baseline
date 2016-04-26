# Microsoft BitLocker

[Microsoft BitLocker](https://technet.microsoft.com/en-us/library/cc731549.aspx) is a full volume encryption feature built into Windows. BitLocker is intended to protect data on devices that have been lost or stolen. BitLocker is available in the Ultimate and Enterprise editions of Windows Vista and Windows 7 and in the Professional and Enterprise editions of Windows 8 and later. A [Group Policy Object](./Group Policy Objects/Computer/) for BitLocker is included in the SHB. The Group Policy Object contains recommended security settings for BitLocker on Windows 10 Version 1511 and later.

## Importing the BitLocker Group Policy

### Importing the BitLocker domain Group Policy
Use the PowerShell Group Policy commands to import the BitLocker Group Policy into a domain. Run the following command on a domain controller from a PowerShell prompt running as a domain administrator. 

```
Import-Module GroupPolicy

Import-GPO -Path ".\BitLocker\Group Policy Objects\Computer\{9D614C55-E361-45A1-87CB-09A2B1EED0C4}"
```
### Importing the BitLocker local Group Policy
Use Microsoft's LGPO tool to apply the BitLocker Group Policy to a standalone system. Run the following command from a command prompt running as a local administrator.

```
lgpo.exe /g ".\BitLocker\Group Policy Objects\Computer\{9D614C55-E361-45A1-87CB-09A2B1EED0C4}"
```

## Common issues

### Conflicting BitLocker startup options
* **Issue**: Error message: *The Group Policy settings for BitLocker startup options are in conflict and cannot be applied*. Error code: 0x8031005B
* **Explanation**: The 'Require additional authentication at startup' policy description text can be misleading on how to correctly configure it.
* **Resolution**: 
    1. Go to **Computer Configuration** > **Administrative Templates** > **Windows Components** > **BitLocker Drive Encryption** > **Operating System Drives**
    1. Change the **Require additional authentication at startup** policy to configure all 4 dropdown menu options to **Allow** *OR* set 1 option to **Require** and the other 3 options to **Do not allow**.
    1. Run **gpupdate /force** from the command line.

### Support for pre-boot PIN entry on tablets

* **Issue**: Error message: *No pre-boot keyboard detected. The user may not be able to provide required input to unlock the volume*. Error code: 0x803100B5
* **Explanation**: BitLocker checks if the system is a tablet. If it is a tablet, then BitLocker displays the above error message when trying to use a PIN protector. BitLocker doesn't check if the system supports a pre-boot keyboard. Some tablets may have a BIOS that supports a software keyboard. For example, the [Dell Venue 11 Pro](http://www.dell.com/support/Article/us/en/19/SLN293013/EN), [Surface Pro 3, and Surface Pro 4](https://blogs.technet.microsoft.com/askpfeplat/2014/07/13/bitlocker-pin-on-surface-pro-3-and-other-tablets/) support entering a BitLocker PIN at pre-boot with a BIOS software keyboard. Some tablets may have detachable keyboard that works during pre-boot. For example, the Surface Pro 2 with [firmware update from March 2014](https://www.microsoft.com/surface/en-us/support/install-update-activate/pro-2-history), Surface Pro 3, and Surface Pro 4 support entering a BitLocker PIN at pre-boot with their detachable keyboards. If the tablet does not support a BIOS software keyboard or a detachable keyboard that works during pre-boot, then configuring the below policy will require a USB keyboard be plugged into the tablet to enter a BitLocker PIN at pre-boot. Contact the OEM to inquire about tablet support for this specific scenario.
* **Resolution**: 
    1. Go to **Computer Configuration** > **Administrative Templates** > **Windows Components** > **BitLocker Drive Encryption**
    1. Set the **Enable use of BitLocker authentication requiring preboot keyboard input on slates** policy to **Enabled**.
    1. Run **gpupdate /force** from the command line.
