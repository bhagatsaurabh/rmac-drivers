# RMAC Drivers

> Note: If you don't know what _RMAC_ is, please read [this](https://github.com/saurabh-prosoft/rmac#readme) first !

## :warning: Disclaimer

This software is built for educational purposes only and was tested on virtual machines, you may use this software at your own risk. The developers assume no liability and are not responsible for any misuse or damage caused by this software.

## :skull_and_crossbones: Caution

If you want to try out these drivers, please do so in a virtual machine.

These drivers are not tested vigorously like other production drivers out there, since this is a kernel mode driver, it gets loaded during boot sequence.

If anything fails while loading the driver due to incompatibility or any other reason, the operating system will not boot ever, even if the system loads up perfectly, and the driver crashes after that, the operating system will crash with it !

If you find yourself in a situation where you cannot boot the OS to remove the driver, Boot to Command Prompt and use [`pnputil`](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/pnputil).

<br />

### What are RMAC Drivers ?

RMAC Drivers are a set of Windows Kernel-mode drivers enabling specific features for [RMAC Host-Client](https://github.com/saurabh-prosoft/rmac/tree/main/host-client#rmac-host-client)

As of now only one Windows driver is available, the RMAC KMKL (Kernel-mode key-logger)

## RMAC KMKL

RMAC Kernel-mode key-logger is a Windows [filter driver](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/filter-drivers) that enables key-logging even on Windows Login screen, [UAC](https://learn.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) pop-ups and other programs running in Windows Secure Desktop mode

The key-log dumps are stored at a location that is known to RMAC Host-Client.

Each key-log dump contains key-log data starting from the moment a Windows Secure process was opened and the moment it was closed.

RMAC KMKL monitors start/stop of two such secure processes: `logonui.exe` and `consent.exe`

`logonui.exe` is responsible for showing the Windows Login screen while `consent.exe` shows the UAC pop-ups.
