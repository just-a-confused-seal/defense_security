## Introduction
- To follow the lab, at least you need to have a kali linux VM or any linux OS. Most of the tool that is used for the lab is easier to be setup on linux rather than windows. You can used WSL but I cannot guarantee 100% it will suitable thorughout the lab.
- In this lab I assume you have a good foundation of cyber security and linux knowledge. If you are first timer or a novice, it is better to look for other lab.

## Prerequisite
Install the following utilities through your kali linux terminal:

1. Python3 pip library tools
```
~# sudo apt install python3-pip
[sudo] password for kali: 
Upgrading:                      
  python3-pip  python3-pip-whl

Summary:
  Upgrading: 2, Installing: 0, Removing: 0, Not Upgrading: 699
  Download size: 2,814 kB
  Freed space: 433 kB

Continue? [Y/n] y
Get:1 http://http.kali.org/kali kali-rolling/main amd64 python3-pip all 25.2+dfsg-1 [1,386 kB]
Get:2 http://http.kali.org/kali kali-rolling/main amd64 python3-pip-whl all 25.2+dfsg-1 [1,428 kB]
Fetched 2,814 kB in 2s (1,219 kB/s)        
(Reading database ... 423342 files and directories currently installed.)
Preparing to unpack .../python3-pip_25.2+dfsg-1_all.deb ...
Unpacking python3-pip (25.2+dfsg-1) over (25.1.1+dfsg-1) ...
Preparing to unpack .../python3-pip-whl_25.2+dfsg-1_all.deb ...
Unpacking python3-pip-whl (25.2+dfsg-1) over (25.1.1+dfsg-1) ...
Setting up python3-pip-whl (25.2+dfsg-1) ...
Setting up python3-pip (25.2+dfsg-1) ...
Processing triggers for man-db (2.13.1-1) ...
Processing triggers for kali-menu (2025.2.7) ...
Scanning processes...                                                                               
Scanning linux images...                                                                            

Running kernel seems to be up-to-date.

No services need to be restarted.

No containers need to be restarted.

No user sessions are running outdated binaries.

No VM guests are running outdated hypervisor (qemu) binaries on this host.
```

## Volatility
In kali linux terminal type the following command to download volatility tool.
```
~# cd Documents
~# mkdir volatility
~# cd volatility
~# wget https://github.com/volatilityfoundation/volatility3/releases/download/v2.26.0/volatility3-2.26.0.tar.gz
~# tar -xzvf volatility3-2.26.0.tar.gz 
~# cd volatility3-2.26.0 
```
Once inside the folder we need to create and activate the python3 virtual environment.
```
┌──(kali㉿kali)-[~/Documents/volatility/volatility3-2.26.0]
└─$ python3 -m venv ./volatility_python
                                                                                                                     
┌──(kali㉿kali)-[~/Documents/volatility/volatility3-2.26.0]
└─$ source volatility_python/bin/activate
                                                                                                                     
┌──(volatility_python)─(kali㉿kali)-[~/Documents/volatility/volatility3-2.26.0]
└─$ 

```
Notice that there will be an additional context 'volatility_python' after you activate the virtual environment.
Next is to install the library depdency via pip3 like this:
```
┌──(volatility_python)─(kali㉿kali)-[~/Documents/volatility/volatility3-2.26.0]
└─$ pip3 install -e ".[full]"
Obtaining file:///home/kali/Documents/volatility/volatility3-2.26.0
  Installing build dependencies ... done
  Checking if build backend supports build_editable ... done
  Getting requirements to build editable ... done
  Preparing editable metadata (pyproject.toml) ... done
Collecting pefile>=2024.8.26 (from volatility3==2.26.0)
  Downloading pefile-2024.8.26-py3-none-any.whl.metadata (1.4 kB)
Collecting yara-python<5,>=4.5.1 (from volatility3==2.26.0)
  Downloading yara_python-4.5.4-cp313-cp313-manylinux_2_17_x86_64.manylinux2014_x86_64.whl.metadata (2.8 kB)
Collecting capstone<6,>=5.0.3 (from volatility3==2.26.0)
  Downloading capstone-5.0.6-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl.metadata (3.3 kB)
Collecting pycryptodome<4,>=3.21.0 (from volatility3==2.26.0)
  Using cached pycryptodome-3.23.0-cp37-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl.metadata (3.4 kB)
Collecting leechcorepyc<3,>=2.19.2 (from volatility3==2.26.0)
  Downloading leechcorepyc-2.22.3-cp36-abi3-manylinux1_x86_64.whl.metadata (557 bytes)
Collecting pillow<11.0.0,>=10.0.0 (from volatility3==2.26.0)
  Downloading pillow-10.4.0-cp313-cp313-manylinux_2_28_x86_64.whl.metadata (9.2 kB)
Downloading capstone-5.0.6-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl (1.5 MB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 1.5/1.5 MB 2.3 MB/s  0:00:00
Downloading leechcorepyc-2.22.3-cp36-abi3-manylinux1_x86_64.whl (197 kB)
Downloading pillow-10.4.0-cp313-cp313-manylinux_2_28_x86_64.whl (4.5 MB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 4.5/4.5 MB 4.5 MB/s  0:00:00
Using cached pycryptodome-3.23.0-cp37-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl (2.3 MB)
Downloading yara_python-4.5.4-cp313-cp313-manylinux_2_17_x86_64.manylinux2014_x86_64.whl (2.3 MB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 2.3/2.3 MB 4.9 MB/s  0:00:00
Downloading pefile-2024.8.26-py3-none-any.whl (74 kB)
Building wheels for collected packages: volatility3
  Building editable for volatility3 (pyproject.toml) ... done
  Created wheel for volatility3: filename=volatility3-2.26.0-0.editable-py3-none-any.whl size=7633 sha256=93730d6e483b4f1d967bec1e573d0b49c283a52fa483926df106a14a810f9ebd
  Stored in directory: /tmp/pip-ephem-wheel-cache-h4mn0_2g/wheels/2c/ac/b2/2a6bf6d34d1393790289ff4a27fb793baf2896dfb3d0b9f82b
Successfully built volatility3
Installing collected packages: yara-python, pycryptodome, pillow, pefile, leechcorepyc, capstone, volatility3
Successfully installed capstone-5.0.6 leechcorepyc-2.22.3 pefile-2024.8.26 pillow-10.4.0 pycryptodome-3.23.0 volatility3-2.26.0 yara-python-4.5.4
```
Once its done, you can check if volatility is installed correctly via the following command:
```
┌──(volatility_python)─(kali㉿kali)-[~/Documents/volatility/volatility3-2.26.0]
└─$ python3 vol.py -h
Volatility 3 Framework 2.26.0
usage: vol.py [-h] [-c CONFIG] [--parallelism [{processes,threads,off}]] [-e EXTEND] [-p PLUGIN_DIRS]
              [-s SYMBOL_DIRS] [-v] [-l LOG] [-o OUTPUT_DIR] [-q] [-r RENDERER] [-f FILE] [--write-config]
              [--save-config SAVE_CONFIG] [--clear-cache] [--cache-path CACHE_PATH] [--offline | -u URL]
              [--filters FILTERS] [--hide-columns [HIDE_COLUMNS ...]] [--single-location SINGLE_LOCATION]
              [--stackers [STACKERS ...]] [--single-swap-locations [SINGLE_SWAP_LOCATIONS ...]]
              PLUGIN ...

An open-source memory forensics framework

options:
  -h, --help            Show this help message and exit, for specific plugin options use 'vol.py <pluginname>
                        --help'
  -c, --config CONFIG   Load the configuration from a json file
  --parallelism [{processes,threads,off}]
                        Enables parallelism (defaults to off if no argument given)
  -e, --extend EXTEND   Extend the configuration with a new (or changed) setting
  -p, --plugin-dirs PLUGIN_DIRS
                        Semi-colon separated list of paths to find plugins
  -s, --symbol-dirs SYMBOL_DIRS
                        Semi-colon separated list of paths to find symbols
  -v, --verbosity       Increase output verbosity
  -l, --log LOG         Log output to a file as well as the console
  -o, --output-dir OUTPUT_DIR
                        Directory in which to output any generated files
  -q, --quiet           Remove progress feedback
  -r, --renderer RENDERER
                        Determines how to render the output (quick, none, csv, pretty, json, jsonl)
  -f, --file FILE       Shorthand for --single-location=file:// if single-location is not defined
  --write-config        Write configuration JSON file out to config.json
  --save-config SAVE_CONFIG
                        Save configuration JSON file to a file
  --clear-cache         Clears out all short-term cached items
  --cache-path CACHE_PATH
                        Change the default path (/home/kali/.cache/volatility3) used to store the cache
  --offline             Do not search online for additional JSON files
  -u, --remote-isf-url URL
                        Search online for ISF json files
  --filters FILTERS     List of filters to apply to the output (in the form of [+-]columname,pattern[!])
  --hide-columns [HIDE_COLUMNS ...]
                        Case-insensitive space separated list of prefixes to determine which columns to hide in the
                        output if provided
  --single-location SINGLE_LOCATION
                        Specifies a base location on which to stack
  --stackers [STACKERS ...]
                        List of stackers
  --single-swap-locations [SINGLE_SWAP_LOCATIONS ...]
                        Specifies a list of swap layer URIs for use with single-location

Plugins:
  For plugin specific options, run 'vol.py <plugin> --help'

  PLUGIN
    banners.Banners     Attempts to identify potential linux banners in an image
    configwriter.ConfigWriter
                        Runs the automagics and both prints and outputs configuration in the output directory.
    frameworkinfo.FrameworkInfo
                        Plugin to list the various modular components of Volatility
    isfinfo.IsfInfo     Determines information about the currently available ISF files, or a specific one
    layerwriter.LayerWriter
                        Runs the automagics and writes out the primary layer produced by the stacker.
    linux.bash.Bash     Recovers bash command history from memory.
    linux.boottime.Boottime
                        Shows the time the system was started
    linux.capabilities.Capabilities
                        Lists process capabilities
    linux.check_afinfo.Check_afinfo
                        Verifies the operation function pointers of network protocols.
    linux.check_creds.Check_creds
                        Checks if any processes are sharing credential structures
    linux.check_idt.Check_idt
                        Checks if the IDT has been altered
    linux.check_modules.Check_modules
                        Compares module list to sysfs info, if available
    linux.check_syscall.Check_syscall
                        Check system call table for hooks.
    linux.ebpf.EBPF     Enumerate eBPF programs
    linux.elfs.Elfs     Lists all memory mapped ELF files for all processes.
    linux.envars.Envars
                        Lists processes with their environment variables
    linux.graphics.fbdev.Fbdev
                        Extract framebuffers from the fbdev graphics subsystem
    linux.hidden_modules.Hidden_modules
                        Carves memory to find hidden kernel modules
    linux.iomem.IOMem   Generates an output similar to /proc/iomem on a running system.
    linux.ip.Addr       Lists network interface information for all devices
    linux.ip.Link       Lists information about network interfaces similar to `ip link show`
    linux.kallsyms.Kallsyms
                        Kallsyms symbols enumeration plugin.
    linux.keyboard_notifiers.Keyboard_notifiers
                        Parses the keyboard notifier call chain
    linux.kmsg.Kmsg     Kernel log buffer reader
    linux.kthreads.Kthreads
                        Enumerates kthread functions
    linux.library_list.LibraryList
                        Enumerate libraries loaded into processes
    linux.lsmod.Lsmod   Lists loaded kernel modules.
    linux.lsof.Lsof     Lists open files for each processes.
    linux.malfind.Malfind
                        Lists process memory ranges that potentially contain injected code.
    linux.module_extract.ModuleExtract
                        Recreates an ELF file from a specific address in the kernel
    linux.modxview.Modxview
                        Centralize lsmod, check_modules and hidden_modules results to efficiently spot modules
                        presence and taints.
    linux.mountinfo.MountInfo
                        Lists mount points on processes mount namespaces
    linux.netfilter.Netfilter
                        Lists Netfilter hooks.
    linux.pagecache.Files
                        Lists files from memory
    linux.pagecache.InodePages
                        Lists and recovers cached inode pages
    linux.pagecache.RecoverFs
                        Recovers the cached filesystem (directories, files, symlinks) into a compressed tarball.
    linux.pidhashtable.PIDHashTable
                        Enumerates processes through the PID hash table
    linux.proc.Maps     Lists all memory maps for all processes.
    linux.psaux.PsAux   Lists processes with their command line arguments
    linux.pscallstack.PsCallStack
                        Enumerates the call stack of each task
    linux.pslist.PsList
                        Lists the processes present in a particular linux memory image.
    linux.psscan.PsScan
                        Scans for processes present in a particular linux image.
    linux.pstree.PsTree
                        Plugin for listing processes in a tree based on their parent process ID.
    linux.ptrace.Ptrace
                        Enumerates ptrace's tracer and tracee tasks
    linux.sockstat.Sockstat
                        Lists all network connections for all processes.
    linux.tracing.ftrace.CheckFtrace
                        Detect ftrace hooking
    linux.tracing.perf_events.PerfEvents
                        Lists performance events for each process.
    linux.tracing.tracepoints.CheckTracepoints
                        Detect tracepoints hooking
    linux.tty_check.tty_check
                        Checks tty devices for hooks
    linux.vmaregexscan.VmaRegExScan
                        Scans all virtual memory areas for tasks using RegEx.
    linux.vmayarascan.VmaYaraScan
                        Scans all virtual memory areas for tasks using yara.
    linux.vmcoreinfo.VMCoreInfo
                        Enumerate VMCoreInfo tables
    mac.bash.Bash       Recovers bash command history from memory.
    mac.check_syscall.Check_syscall
                        Check system call table for hooks.
    mac.check_sysctl.Check_sysctl
                        Check sysctl handlers for hooks.
    mac.check_trap_table.Check_trap_table
                        Check mach trap table for hooks.
    mac.dmesg.Dmesg     Prints the kernel log buffer.
    mac.ifconfig.Ifconfig
                        Lists network interface information for all devices
    mac.kauth_listeners.Kauth_listeners
                        Lists kauth listeners and their status
    mac.kauth_scopes.Kauth_scopes
                        Lists kauth scopes and their status
    mac.kevents.Kevents
                        Lists event handlers registered by processes
    mac.list_files.List_Files
                        Lists all open file descriptors for all processes.
    mac.lsmod.Lsmod     Lists loaded kernel modules.
    mac.lsof.Lsof       Lists all open file descriptors for all processes.
    mac.malfind.Malfind
                        Lists process memory ranges that potentially contain injected code.
    mac.mount.Mount     A module containing a collection of plugins that produce data typically found in Mac's
                        mount command
    mac.netstat.Netstat
                        Lists all network connections for all processes.
    mac.proc_maps.Maps  Lists process memory ranges that potentially contain injected code.
    mac.psaux.Psaux     Recovers program command line arguments.
    mac.pslist.PsList   Lists the processes present in a particular mac memory image.
    mac.pstree.PsTree   Plugin for listing processes in a tree based on their parent process ID.
    mac.socket_filters.Socket_filters
                        Enumerates kernel socket filters.
    mac.timers.Timers   Check for malicious kernel timers.
    mac.trustedbsd.Trustedbsd
                        Checks for malicious trustedbsd modules
    mac.vfsevents.VFSevents
                        Lists processes that are filtering file system events
    regexscan.RegExScan
                        Scans kernel memory using RegEx patterns.
    timeliner.Timeliner
                        Runs all relevant plugins that provide time related information and orders the results by
                        time.
    vmscan.Vmscan       Scans for Intel VT-d structues and generates VM volatility configs for them
    windows.amcache.Amcache
                        Extract information on executed applications from the AmCache (deprecated).
    windows.bigpools.BigPools
                        List big page pools.
    windows.cachedump.Cachedump
                        Dumps lsa secrets from memory (deprecated)
    windows.callbacks.Callbacks
                        Lists kernel callbacks and notification routines.
    windows.cmdline.CmdLine
                        Lists process command line arguments.
    windows.cmdscan.CmdScan
                        Looks for Windows Command History lists
    windows.consoles.Consoles
                        Looks for Windows console buffers
    windows.crashinfo.Crashinfo
                        Lists the information from a Windows crash dump.
    windows.debugregisters.DebugRegisters
    windows.deskscan.DeskScan
                        Scans for the Desktop instances of each Window Station
    windows.desktops.Desktops
                        Enumerates the Desktop instances of each Window Station
    windows.devicetree.DeviceTree
                        Listing tree based on drivers and attached devices in a particular windows memory image.
    windows.direct_system_calls.DirectSystemCalls
                        Detects the Direct System Call technique used to bypass EDRs
    windows.dlllist.DllList
                        Lists the loaded DLLs in a particular windows memory image.
    windows.driverirp.DriverIrp
                        List IRPs for drivers in a particular windows memory image.
    windows.drivermodule.DriverModule
                        Determines if any loaded drivers were hidden by a rootkit
    windows.driverscan.DriverScan
                        Scans for drivers present in a particular windows memory image.
    windows.dumpfiles.DumpFiles
                        Dumps cached file contents from Windows memory samples.
    windows.envars.Envars
                        Display process environment variables
    windows.filescan.FileScan
                        Scans for file objects present in a particular windows memory image.
    windows.getservicesids.GetServiceSIDs
                        Lists process token sids.
    windows.getsids.GetSIDs
                        Print the SIDs owning each process
    windows.handles.Handles
                        Lists process open handles.
    windows.hashdump.Hashdump
                        Dumps user hashes from memory (deprecated)
    windows.hollowprocesses.HollowProcesses
                        Lists hollowed processes
    windows.iat.IAT     Extract Import Address Table to list API (functions) used by a program contained in
                        external libraries
    windows.indirect_system_calls.IndirectSystemCalls
    windows.info.Info   Show OS & kernel details of the memory sample being analyzed.
    windows.joblinks.JobLinks
                        Print process job link information
    windows.kpcrs.KPCRs
                        Print KPCR structure for each processor
    windows.ldrmodules.LdrModules
                        Lists the loaded modules in a particular windows memory image.
    windows.lsadump.Lsadump
                        Dumps lsa secrets from memory (deprecated)
    windows.malfind.Malfind
                        Lists process memory ranges that potentially contain injected code.
    windows.mbrscan.MBRScan
                        Scans for and parses potential Master Boot Records (MBRs)
    windows.memmap.Memmap
                        Prints the memory map
    windows.mftscan.ADS
                        Scans for Alternate Data Stream
    windows.mftscan.MFTScan
                        Scans for MFT FILE objects present in a particular windows memory image.
    windows.mftscan.ResidentData
                        Scans for MFT Records with Resident Data
    windows.modscan.ModScan
                        Scans for modules present in a particular windows memory image.
    windows.modules.Modules
                        Lists the loaded kernel modules.
    windows.mutantscan.MutantScan
                        Scans for mutexes present in a particular windows memory image.
    windows.netscan.NetScan
                        Scans for network objects present in a particular windows memory image.
    windows.netstat.NetStat
                        Traverses network tracking structures present in a particular windows memory image.
    windows.orphan_kernel_threads.Threads
                        Lists process threads
    windows.pe_symbols.PESymbols
                        Prints symbols in PE files in process and kernel memory
    windows.pedump.PEDump
                        Allows extracting PE Files from a specific address in a specific address space
    windows.poolscanner.PoolScanner
                        A generic pool scanner plugin.
    windows.privileges.Privs
                        Lists process token privileges
    windows.processghosting.ProcessGhosting
                        Lists processes whose DeletePending bit is set or whose FILE_OBJECT is set to 0 or Vads
                        that are DeleteOnClose
    windows.pslist.PsList
                        Lists the processes present in a particular windows memory image.
    windows.psscan.PsScan
                        Scans for processes present in a particular windows memory image.
    windows.pstree.PsTree
                        Plugin for listing processes in a tree based on their parent process ID.
    windows.psxview.PsXView
                        Lists all processes found via four of the methods described in "The Art of Memory
                        Forensics" which may help identify processes that are trying to hide themselves.
    windows.registry.amcache.Amcache
                        Extract information on executed applications from the AmCache.
    windows.registry.cachedump.Cachedump
                        Dumps lsa secrets from memory
    windows.registry.certificates.Certificates
                        Lists the certificates in the registry's Certificate Store.
    windows.registry.getcellroutine.GetCellRoutine
                        Reports registry hives with a hooked GetCellRoutine handler
    windows.registry.hashdump.Hashdump
                        Dumps user hashes from memory
    windows.registry.hivelist.HiveList
                        Lists the registry hives present in a particular memory image.
    windows.registry.hivescan.HiveScan
                        Scans for registry hives present in a particular windows memory image.
    windows.registry.lsadump.Lsadump
                        Dumps lsa secrets from memory
    windows.registry.printkey.PrintKey
                        Lists the registry keys under a hive or specific key value.
    windows.registry.scheduled_tasks.ScheduledTasks
                        Decodes scheduled task information from the Windows registry, including information about
                        triggers, actions, run times, and creation times.
    windows.registry.userassist.UserAssist
                        Print userassist registry keys and information.
    windows.scheduled_tasks.ScheduledTasks
                        Decodes scheduled task information from the Windows registry, including information about
                        triggers, actions, run times, and creation times (deprecated).
    windows.sessions.Sessions
                        lists Processes with Session information extracted from Environmental Variables
    windows.shimcachemem.ShimcacheMem
                        Reads Shimcache entries from the ahcache.sys AVL tree
    windows.skeleton_key_check.Skeleton_Key_Check
                        Looks for signs of Skeleton Key malware
    windows.ssdt.SSDT   Lists the system call table.
    windows.statistics.Statistics
                        Lists statistics about the memory space.
    windows.strings.Strings
                        Reads output from the strings command and indicates which process(es) each string belongs
                        to.
    windows.suspended_threads.SuspendedThreads
                        Enumerates suspended threads.
    windows.suspicious_threads.SuspiciousThreads
                        Lists suspicious userland process threads
    windows.svcdiff.SvcDiff
                        Compares services found through list walking versus scanning to find rootkits
    windows.svclist.SvcList
                        Lists services contained with the services.exe doubly linked list of services
    windows.svcscan.SvcScan
                        Scans for windows services.
    windows.symlinkscan.SymlinkScan
                        Scans for links present in a particular windows memory image.
    windows.thrdscan.ThrdScan
                        Scans for windows threads.
    windows.threads.Threads
                        Lists process threads
    windows.timers.Timers
                        Print kernel timers and associated module DPCs
    windows.truecrypt.Passphrase
                        TrueCrypt Cached Passphrase Finder
    windows.unhooked_system_calls.unhooked_system_calls
                        Looks for signs of Skeleton Key malware
    windows.unloadedmodules.UnloadedModules
                        Lists the unloaded kernel modules.
    windows.vadinfo.VadInfo
                        Lists process memory ranges.
    windows.vadregexscan.VadRegExScan
                        Scans all virtual memory areas for tasks using RegEx.
    windows.vadwalk.VadWalk
                        Walk the VAD tree.
    windows.vadyarascan.VadYaraScan
                        Scans all the Virtual Address Descriptor memory maps using yara.
    windows.verinfo.VerInfo
                        Lists version information from PE files.
    windows.virtmap.VirtMap
                        Lists virtual mapped sections.
    windows.windows.Windows
                        Enumerates the Windows of Desktop instances
    windows.windowstations.WindowStations
                        Scans for top level Windows Stations
    yarascan.YaraScan   Scans kernel memory using yara rules (string or file).
```
