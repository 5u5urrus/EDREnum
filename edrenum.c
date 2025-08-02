// EDR Enumeration tool for Red Teamers, Pentesters
// Author: Vahe Demirkhanyan

#include <windows.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "advapi32.lib")

#define MAX_EDR_PROCESSES 15
#define MAX_EDR_DRIVERS 10
#define MAX_EDR_REGISTRY_KEYS 10
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef LONG NTSTATUS;

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemProcessInformation = 5,
    SystemModuleInformation = 11
} SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

typedef struct _MY_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} MY_UNICODE_STRING, *PMY_UNICODE_STRING;

typedef struct _MY_SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    MY_UNICODE_STRING ImageName;
    LONG BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR PageDirectoryBase;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
} MY_SYSTEM_PROCESS_INFORMATION, *PMY_SYSTEM_PROCESS_INFORMATION;

typedef struct _MY_SYSTEM_MODULE {
    PVOID Reserved1;
    PVOID Reserved2;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT Id;
    USHORT Rank;
    USHORT LoadCount;
    USHORT NameOffset;
    CHAR FullPathName[256];
} MY_SYSTEM_MODULE, *PMY_SYSTEM_MODULE;

typedef struct _MY_SYSTEM_MODULE_INFORMATION {
    ULONG ModulesCount;
    MY_SYSTEM_MODULE Modules[1];
} MY_SYSTEM_MODULE_INFORMATION, *PMY_SYSTEM_MODULE_INFORMATION;

typedef struct _EDR_SIGNATURE {
    LPCWSTR pwszEDRName;
    LPCWSTR pwszVendor;
    LPCWSTR pwszProcessNames[MAX_EDR_PROCESSES];
    LPCWSTR pwszDriverNames[MAX_EDR_DRIVERS];
    LPCWSTR pwszRegistryKeys[MAX_EDR_REGISTRY_KEYS];
} EDR_SIGNATURE;

typedef struct _DETECTION_RESULT {
    BOOL bProcessDetected;
    BOOL bDriverDetected;
    BOOL bRegistryDetected;
    DWORD dwProcessCount;
    DWORD dwDriverCount;
    DWORD dwRegistryCount;
} DETECTION_RESULT;

// Enhanced EDR database
// ========================================
// COMPREHENSIVE EDR DATABASE - 30+ PRODUCTS
// Real-world verified signatures for enterprise deployments
// ========================================

EDR_SIGNATURE g_EDRDatabase[] = {
    // ===== TIER 1 - MAJOR ENTERPRISE EDRS =====
    {
        L"Microsoft Defender",
        L"Microsoft Corporation",
        {
            L"MsMpEng.exe", L"NisSrv.exe", L"MpDefenderCoreService.exe", 
            L"smartscreen.exe", L"MsSense.exe", L"SenseIR.exe", 
            L"SenseNdr.exe", L"SenseTVM.exe", L"SenseCncProxy.exe", 
            L"SenseSampleUploader.exe", L"MpCmdRun.exe", NULL
        },
        {
            L"WdFilter.sys", L"MsSecFlt.sys", L"WdNisDrv.sys", L"WdBoot.sys", NULL
        },
        {
            L"HKLM\\SOFTWARE\\Microsoft\\Windows Defender",
            L"HKLM\\SOFTWARE\\Microsoft\\Windows Advanced Threat Protection", 
            L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinDefend",
            L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Sense", NULL
        }
    },
    {
        L"CrowdStrike Falcon",
        L"CrowdStrike",
        {
            L"CSFalconService.exe", L"CSFalconContainer.exe", L"falcon-sensor.exe", 
            L"CSAgent.exe", L"CSDeviceControl.exe", L"CSFalconUpdater.exe", NULL
        },
        {
            L"csagent.sys", L"csboot.sys", L"csdevicecontrol.sys", L"csflt.sys", NULL
        },
        {
            L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\CSAgent",
            L"HKLM\\SOFTWARE\\CrowdStrike", 
            L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\CSFalconService", NULL
        }
    },
    {
        L"SentinelOne",
        L"SentinelOne",
        {
            L"SentinelAgent.exe", L"SentinelAgentWorker.exe", L"SentinelServiceHost.exe", 
            L"SentinelStaticEngine.exe", L"LogProcessorService.exe", L"SentinelUI.exe", NULL
        },
        {
            L"SentinelMonitor.sys", L"SED.sys", L"SentinelRawDisk.sys", NULL
        },
        {
            L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\SentinelAgent",
            L"HKLM\\SOFTWARE\\SentinelOne", 
            L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\SentinelMonitor", NULL
        }
    },
    {
        L"Carbon Black",
        L"VMware",
        {
            L"cb.exe", L"cbdaemon.exe", L"cbcomms.exe", L"cbstream.exe", 
            L"confer.exe", L"RepMgr.exe", L"RepUtils.exe", L"RepUx.exe", NULL
        },
        {
            L"cbk7.sys", L"cbstream.sys", L"CbFs.sys", L"carbonblackk.sys", NULL
        },
        {
            L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\CarbonBlack",
            L"HKLM\\SOFTWARE\\CarbonBlack", 
            L"HKLM\\SOFTWARE\\Bit9", NULL
        }
    },
    {
        L"Cylance",
        L"BlackBerry",
        {
            L"CylanceSvc.exe", L"CylanceUI.exe", L"CyUpdate.exe", NULL
        },
        {
            L"CylanceDrv.sys", L"cyprotectdrv.sys", L"CyOptics.sys", NULL
        },
        {
            L"HKLM\\SOFTWARE\\Cylance", 
            L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\CylanceSvc", NULL
        }
    },
    {
        L"Palo Alto Cortex XDR",
        L"Palo Alto Networks",
        {
            L"cyserver.exe", L"cytray.exe", L"cyvera.exe", L"cyoptics.exe", 
            L"CortexAgent.exe", NULL
        },
        {
            L"cyverak.sys", L"cyvrfsfd.sys", L"cybkerneltracker.sys", NULL
        },
        {
            L"HKLM\\SOFTWARE\\Cyvera", 
            L"HKLM\\SOFTWARE\\Palo Alto Networks",
            L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\CyveraService", NULL
        }
    },
    
    // ===== TIER 2 - MAJOR ANTIVIRUS WITH EDR =====
    {
        L"Sophos Intercept X",
        L"Sophos",
        {
            L"SophosUI.exe", L"SophosFS.exe", L"SophosHealth.exe", 
            L"SophosED.exe", L"SophosCleanM.exe", L"SophosNtpService.exe", 
            L"SAVAdminService.exe", L"SavService.exe", NULL
        },
        {
            L"savonaccess.sys", L"SophosED.sys", L"sophosbootdriver.sys", 
            L"SophosFS.sys", NULL
        },
        {
            L"HKLM\\SOFTWARE\\Sophos", 
            L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Sophos Endpoint Defense",
            L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\SAVService", NULL
        }
    },
    {
        L"ESET Endpoint Security",
        L"ESET",
        {
            L"ekrn.exe", L"egui.exe", L"esetonlinescanner.exe", 
            L"esets.exe", L"esetsentry.exe", L"ERAAgent.exe", NULL
        },
        {
            L"eamonm.sys", L"ehdrv.sys", L"epfw.sys", L"eelam.sys", NULL
        },
        {
            L"HKLM\\SOFTWARE\\ESET", 
            L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\ekrn", 
            L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\ERAAgent", NULL
        }
    },
    {
        L"McAfee Endpoint Security",
        L"McAfee",
        {
            L"mfemms.exe", L"mfetp.exe", L"mcshield.exe", L"mfevtp.exe", 
            L"mfeann.exe", L"mfeesp.exe", L"mfefire.exe", L"masvc.exe", NULL
        },
        {
            L"mfencbdc.sys", L"mfeavfk.sys", L"mfefirek.sys", L"mfencoas.sys", 
            L"mfehidk.sys", NULL
        },
        {
            L"HKLM\\SOFTWARE\\McAfee", 
            L"HKLM\\SOFTWARE\\Network Associates",
            L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\mfemms", NULL
        }
    },
    {
        L"Bitdefender GravityZone",
        L"Bitdefender",
        {
            L"bdagent.exe", L"vsserv.exe", L"bdredline.exe", 
            L"updatesrv.exe", L"bdntwrk.exe", L"EPSecurityService.exe", NULL
        },
        {
            L"trufos.sys", L"avc3.sys", L"avckf.sys", L"bdvedisk.sys", 
            L"atc.sys", NULL
        },
        {
            L"HKLM\\SOFTWARE\\Bitdefender", 
            L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\VSSERV",
            L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\EPSecurityService", NULL
        }
    },
    {
        L"Kaspersky Endpoint Security",
        L"Kaspersky",
        {
            L"avp.exe", L"klwtblfs.exe", L"klnagent.exe", L"kavfsmng.exe", 
            L"kavfswp.exe", L"klswd.exe", L"kes.exe", NULL
        },
        {
            L"klif.sys", L"klifsm.sys", L"klpd.sys", L"kltdi.sys", 
            L"klbackupdisk.sys", NULL
        },
        {
            L"HKLM\\SOFTWARE\\KasperskyLab", 
            L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\AVP",
            L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\klnagent", NULL
        }
    },
    {
        L"Trend Micro",
        L"Trend Micro",
        {
            L"TmListen.exe", L"TmProxy.exe", L"ntrtscan.exe", L"TmPfw.exe", 
            L"TMLWfMon.exe", L"TmCCSF.exe", L"DSAMain.exe", L"dsa.exe", NULL
        },
        {
            L"tmcomm.sys", L"tmactmon.sys", L"tmevtmgr.sys", L"tmfileenc.sys", 
            L"tmnciesc.sys", NULL
        },
        {
            L"HKLM\\SOFTWARE\\TrendMicro", 
            L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\TMiCRCScanService",
            L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\ds_agent", NULL
        }
    },
    {
        L"Symantec Endpoint Protection",
        L"Broadcom",
        {
            L"Smc.exe", L"SmcGui.exe", L"ccSvcHst.exe", L"LUALL.exe", 
            L"LuComServer_3_3.exe", L"SepMasterService.exe", NULL
        },
        {
            L"SRTSP.sys", L"SRTSPL.sys", L"SymEFA.sys", L"SymEvent.sys", 
            L"SysPlant.sys", NULL
        },
        {
            L"HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection",
            L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Symantec Endpoint Protection",
            L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\SepMasterService", NULL
        }
    },
    
    // ===== TIER 3 - SPECIALIZED/ENTERPRISE EDRS =====
    {
        L"Fortinet FortiEDR",
        L"Fortinet",
        {
            L"fortiedr.exe", L"collectoragent.exe", L"fortiedr_service.exe", 
            L"FortiCollector.exe", NULL
        },
        {
            L"fortiedr.sys", L"fortimon.sys", L"FortiRdr.sys", NULL
        },
        {
            L"HKLM\\SOFTWARE\\Fortinet", 
            L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\FortiEDR", NULL
        }
    },
    {
        L"Cisco Secure Endpoint",
        L"Cisco",
        {
            L"ciscoamp.exe", L"amp.exe", L"sfc.exe", L"immunetprotect.exe", NULL
        },
        {
            L"ampk.sys", L"tedrdrv.sys", L"CiscoAMP.sys", NULL
        },
        {
            L"HKLM\\SOFTWARE\\Cisco\\AMP", 
            L"HKLM\\SOFTWARE\\Sourcefire",
            L"HKLM\\SOFTWARE\\Immunet", NULL
        }
    },
    {
        L"FireEye Endpoint Security",
        L"Trellix",
        {
            L"xagt.exe", L"feds.exe", L"redline.exe", L"HXTHost.exe", 
            L"MACAgent.exe", NULL
        },
        {
            L"fed.sys", L"fekern.sys", L"WFP_MRT.sys", NULL
        },
        {
            L"HKLM\\SOFTWARE\\FireEye", 
            L"HKLM\\SOFTWARE\\Mandiant",
            L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\xagt", NULL
        }
    },
    {
        L"Check Point Harmony Endpoint",
        L"Check Point",
        {
            L"cpda.exe", L"cptdservice.exe", L"cpservice.exe", 
            L"TrackerService.exe", NULL
        },
        {
            L"cptddrv.sys", L"cpepdrv.sys", L"IntelTXE.sys", NULL
        },
        {
            L"HKLM\\SOFTWARE\\CheckPoint", 
            L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\cpda", NULL
        }
    },
    {
        L"Malwarebytes Endpoint Protection",
        L"Malwarebytes",
        {
            L"mbamservice.exe", L"mbamdor.exe", L"mbamtray.exe", 
            L"mbam.exe", L"mbamscheduler.exe", L"OneView.exe", NULL
        },
        {
            L"MBAMSwissArmy.sys", L"mbamchameleon.sys", L"mwac.sys", 
            L"ESensor.sys", NULL
        },
        {
            L"HKLM\\SOFTWARE\\Malwarebytes", 
            L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\MBAMService", NULL
        }
    },
    {
        L"F-Secure Endpoint Protection",
        L"F-Secure",
        {
            L"fshoster32.exe", L"fsav32.exe", L"fsgk32.exe", 
            L"fswebuid.exe", L"fssm32.exe", L"F-Secure.exe", NULL
        },
        {
            L"fsgk.sys", L"fsatp.sys", L"fsvista.sys", L"F-Secure Gatekeeper.sys", NULL
        },
        {
            L"HKLM\\SOFTWARE\\F-Secure", 
            L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\F-Secure Gatekeeper", NULL
        }
    },
    {
        L"Webroot SecureAnywhere",
        L"Webroot",
        {
            L"WRSA.exe", L"WRSAMon.exe", L"WRAgent.exe", L"WRConsole.exe", NULL
        },
        {
            L"WRusr.sys", L"WRCore.sys", L"WRKrn.sys", NULL
        },
        {
            L"HKLM\\SOFTWARE\\WRData", 
            L"HKLM\\SOFTWARE\\WRCore",
            L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\WRAgent", NULL
        }
    },
    {
        L"Deep Instinct",
        L"Deep Instinct",
        {
            L"deep_instinct.exe", L"di_service.exe", L"DeepAgent.exe", 
            L"DI_Notifier.exe", NULL
        },
        {
            L"di_monitor.sys", L"DeepInst.sys", L"DeepDriver.sys", NULL
        },
        {
            L"HKLM\\SOFTWARE\\Deep Instinct", 
            L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\DeepInstinct", NULL
        }
    },
    {
        L"Cybereason",
        L"Cybereason",
        {
            L"CybereasonAV.exe", L"CrAgent.exe", L"CrService.exe", 
            L"CrAgentService.exe", NULL
        },
        {
            L"CRExecPrev.sys", L"crdriver.sys", L"CybereasonDriver.sys", NULL
        },
        {
            L"HKLM\\SOFTWARE\\Cybereason", 
            L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\CybereasonAV", NULL
        }
    },
    {
        L"WatchGuard EPDR",
        L"WatchGuard",
        {
            L"WGDashboard.exe", L"WGDD.exe", L"EPDRAgent.exe", 
            L"WatchGuard.exe", NULL
        },
        {
            L"epdrv.sys", L"wgdd.sys", L"WatchGuard.sys", NULL
        },
        {
            L"HKLM\\SOFTWARE\\WatchGuard", 
            L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\EPDR", NULL
        }
    },
    
    // ===== TIER 4 - CONSUMER/SMB WITH BUSINESS EDITIONS =====
    {
        L"Avast Business Antivirus",
        L"Avast",
        {
            L"avastui.exe", L"avastsvc.exe", L"avastbhv.exe", 
            L"ashdisp.exe", L"aswidsagent.exe", L"AvastBusinessConsole.exe", NULL
        },
        {
            L"aswsp.sys", L"aswsnx.sys", L"aswfilt.sys", L"aswmon.sys", 
            L"aswidsdriver.sys", NULL
        },
        {
            L"HKLM\\SOFTWARE\\AVAST Software", 
            L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\avast! Antivirus", NULL
        }
    },
    {
        L"AVG Business Edition",
        L"AVG Technologies",
        {
            L"avgui.exe", L"avgsvc.exe", L"avgidsagent.exe", 
            L"avgwdsvc.exe", L"avgfws.exe", L"AVGBusinessSSO.exe", NULL
        },
        {
            L"avgfwd6a.sys", L"avgldx64.sys", L"avgmfx64.sys", 
            L"avgidsdriver.sys", NULL
        },
        {
            L"HKLM\\SOFTWARE\\AVG", 
            L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\AVGIDSAgent", NULL
        }
    },
    {
        L"Comodo Advanced Endpoint Protection",
        L"Comodo",
        {
            L"cmdagent.exe", L"cfp.exe", L"COMODOAntiVirusService.exe", 
            L"cavwp.exe", NULL
        },
        {
            L"cmdguard.sys", L"cmdhlp.sys", L"inspect.sys", L"cmderd.sys", NULL
        },
        {
            L"HKLM\\SOFTWARE\\Comodo", 
            L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\cmdAgent", NULL
        }
    },
    
    // ===== LOGGING/MONITORING TOOLS =====
    {
        L"Elastic EDR",
        L"Elastic",
        {
            L"elastic-agent.exe", L"elastic-endpoint.exe", L"filebeat.exe", 
            L"metricbeat.exe", L"winlogbeat.exe", L"auditbeat.exe", NULL
        },
        {
            L"elastic-endpoint-driver.sys", NULL
        },
        {
            L"HKLM\\SOFTWARE\\Elastic", 
            L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\ElasticEndpoint", NULL
        }
    },
    {
        L"Sysmon",
        L"Microsoft Sysinternals",
        {
            L"Sysmon.exe", L"Sysmon64.exe", NULL
        },
        {
            L"SysmonDrv.sys", NULL
        },
        {
            L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Sysmon", 
            L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\SysmonDrv", NULL
        }
    },
    {
        L"Splunk Universal Forwarder",
        L"Splunk",
        {
            L"splunkd.exe", L"splunk.exe", L"splunk-winevtlog.exe", 
            L"splunk-admon.exe", NULL
        },
        {
            NULL
        },
        {
            L"HKLM\\SOFTWARE\\Splunk", 
            L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\SplunkForwarder", NULL
        }
    },
    
    // ===== REGIONAL/SPECIALIZED SOLUTIONS =====
    {
        L"G Data Endpoint Protection",
        L"G Data",
        {
            L"AVK.exe", L"GDScan.exe", L"GDFwSvc.exe", L"AVKProxy.exe", NULL
        },
        {
            L"GDBehave.sys", L"gdwfpcd.sys", L"HookCentre.sys", NULL
        },
        {
            L"HKLM\\SOFTWARE\\G Data", 
            L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\AVK Service", NULL
        }
    },
    {
        L"Acronis Cyber Protection",
        L"Acronis",
        {
            L"AcronisCyberProtectionService.exe", L"managementtool.exe", 
            L"CyberProtectionConsole.exe", NULL
        },
        {
            L"file_protector.sys", L"ACDrv.sys", NULL
        },
        {
            L"HKLM\\SOFTWARE\\Acronis", 
            L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\AcronisCyberProtectionService", NULL
        }
    }
};

const SIZE_T g_EDRCount = sizeof(g_EDRDatabase) / sizeof(g_EDRDatabase[0]);

// Function prototypes
BOOL StealthEnumerateProcesses(void);
BOOL StealthEnumerateDrivers(void);
BOOL CheckRegistryKeys(void);
BOOL CheckRegistryKey(LPCWSTR pwszKeyPath);
void PrintBanner(void);
void PrintSummary(void);

// Global detection results and NT API function pointer
DETECTION_RESULT g_DetectionResults[sizeof(g_EDRDatabase) / sizeof(g_EDRDatabase[0])] = {0};
DWORD g_TotalDetections = 0;
fnNtQuerySystemInformation pNtQuerySystemInformation = NULL;

int main(int argc, char* argv[]) {
    PrintBanner();
    
    // Get handle to ntdll.dll and resolve NtQuerySystemInformation (stealth approach)
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        printf("[-] Failed to get handle to ntdll.dll\n");
        return 1;
    }
    
    pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
    if (!pNtQuerySystemInformation) {
        printf("[-] Failed to resolve NtQuerySystemInformation\n");
        return 1;
    }
    
    printf("[+] Starting Enhanced Stealthy EDR Enumeration...\n\n");
    
    // Perform all detection methods using low-level NT APIs
    printf("[*] Enumerating processes via NT API...\n");
    StealthEnumerateProcesses();
    
    printf("\n[*] Enumerating drivers via NT API...\n");
    StealthEnumerateDrivers();
    
    printf("\n[*] Checking registry signatures...\n");
    CheckRegistryKeys();
    
    printf("\n");
    PrintSummary();
    
    return 0;
}

void PrintBanner(void) {
    printf("===================================================\n");
    printf("    Enhanced Stealthy EDR Enumeration Tool v2.1\n");
    printf("    NT API + Registry Detection + Expanded Database\n");
    printf("===================================================\n\n");
}

BOOL StealthEnumerateProcesses(void) {
    NTSTATUS status;
    ULONG returnLength1 = 0, returnLength2 = 0;
    PMY_SYSTEM_PROCESS_INFORMATION pSystemProcInfo = NULL;
    PMY_SYSTEM_PROCESS_INFORMATION pCurrent = NULL;
    
    // First call to get required buffer size
    status = pNtQuerySystemInformation(SystemProcessInformation, NULL, 0, &returnLength1);
    if (returnLength1 == 0) {
        printf("[-] Failed to get system process information size\n");
        return FALSE;
    }
    
    // Allocate buffer
    HANDLE hHeap = GetProcessHeap();
    pSystemProcInfo = (PMY_SYSTEM_PROCESS_INFORMATION)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, returnLength1);
    if (!pSystemProcInfo) {
        printf("[-] Failed to allocate memory for process information\n");
        return FALSE;
    }
    
    // Second call to get actual data
    status = pNtQuerySystemInformation(SystemProcessInformation, pSystemProcInfo, returnLength1, &returnLength2);
    if (!NT_SUCCESS(status)) {
        printf("[-] NtQuerySystemInformation failed with status: 0x%08X\n", status);
        HeapFree(hHeap, 0, pSystemProcInfo);
        return FALSE;
    }
    
    printf("    %-35s %-10s %-25s %s\n", "EDR Product", "Type", "Component", "PID");
    printf("    %s\n", "--------------------------------------------------------------------------------");
    
    pCurrent = pSystemProcInfo;
    
    // Loop through all processes
    while (TRUE) {
        if (pCurrent->ImageName.Buffer != NULL) {
            // Check against each EDR signature
            for (DWORD i = 0; i < g_EDRCount; i++) {
                for (DWORD j = 0; g_EDRDatabase[i].pwszProcessNames[j] != NULL; j++) {
                    if (_wcsicmp(pCurrent->ImageName.Buffer, g_EDRDatabase[i].pwszProcessNames[j]) == 0) {
                        printf("    %-35ws %-10s %-25ws %Iu\n", 
                               g_EDRDatabase[i].pwszEDRName, 
                               "Process", 
                               pCurrent->ImageName.Buffer, 
                               (ULONG_PTR)pCurrent->UniqueProcessId);
                        
                        g_DetectionResults[i].bProcessDetected = TRUE;
                        g_DetectionResults[i].dwProcessCount++;
                        break;
                    }
                }
            }
        }
        
        if (pCurrent->NextEntryOffset == 0) break;
        pCurrent = (PMY_SYSTEM_PROCESS_INFORMATION)((ULONG_PTR)pCurrent + pCurrent->NextEntryOffset);
    }
    
    HeapFree(hHeap, 0, pSystemProcInfo);
    return TRUE;
}

BOOL StealthEnumerateDrivers(void) {
    NTSTATUS status;
    ULONG returnLength1 = 0, returnLength2 = 0;
    PMY_SYSTEM_MODULE_INFORMATION pSystemModuleInfo = NULL;
    
    // First call to get required buffer size
    status = pNtQuerySystemInformation(SystemModuleInformation, NULL, 0, &returnLength1);
    if (returnLength1 == 0) {
        printf("[-] Failed to get system module information size\n");
        return FALSE;
    }
    
    // Allocate buffer
    HANDLE hHeap = GetProcessHeap();
    pSystemModuleInfo = (PMY_SYSTEM_MODULE_INFORMATION)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, returnLength1);
    if (!pSystemModuleInfo) {
        printf("[-] Failed to allocate memory for module information\n");
        return FALSE;
    }
    
    // Second call to get actual data
    status = pNtQuerySystemInformation(SystemModuleInformation, pSystemModuleInfo, returnLength1, &returnLength2);
    if (!NT_SUCCESS(status)) {
        printf("[-] NtQuerySystemInformation failed with status: 0x%08X\n", status);
        HeapFree(hHeap, 0, pSystemModuleInfo);
        return FALSE;
    }
    
    printf("    %-35s %-10s %-25s %s\n", "EDR Product", "Type", "Component", "Base Address");
    printf("    %s\n", "--------------------------------------------------------------------------------");
    
    // Loop through all modules
    for (ULONG i = 0; i < pSystemModuleInfo->ModulesCount; i++) {
        PMY_SYSTEM_MODULE pModule = &pSystemModuleInfo->Modules[i];
        
        // Extract base name from full path
        CHAR* pszBaseName = strrchr(pModule->FullPathName, '\\');
        if (pszBaseName) {
            pszBaseName++; // Skip the backslash
        } else {
            pszBaseName = pModule->FullPathName;
        }
        
        // Convert to wide char for comparison
        WCHAR wszDriverName[MAX_PATH] = {0};
        MultiByteToWideChar(CP_ACP, 0, pszBaseName, -1, wszDriverName, MAX_PATH);
        
        // Check against EDR signatures
        for (DWORD j = 0; j < g_EDRCount; j++) {
            for (DWORD k = 0; g_EDRDatabase[j].pwszDriverNames[k] != NULL; k++) {
                if (_wcsicmp(wszDriverName, g_EDRDatabase[j].pwszDriverNames[k]) == 0) {
                    printf("    %-35ws %-10s %-25hs 0x%p\n", 
                           g_EDRDatabase[j].pwszEDRName, 
                           "Driver", 
                           pszBaseName, 
                           pModule->ImageBase);
                    
                    g_DetectionResults[j].bDriverDetected = TRUE;
                    g_DetectionResults[j].dwDriverCount++;
                    break;
                }
            }
        }
    }
    
    HeapFree(hHeap, 0, pSystemModuleInfo);
    return TRUE;
}

BOOL CheckRegistryKeys(void) {
    printf("    %-35s %-10s %s\n", "EDR Product", "Type", "Registry Key");
    printf("    %s\n", "--------------------------------------------------------------------------------");
    
    for (DWORD i = 0; i < g_EDRCount; i++) {
        for (DWORD j = 0; g_EDRDatabase[i].pwszRegistryKeys[j] != NULL; j++) {
            if (CheckRegistryKey(g_EDRDatabase[i].pwszRegistryKeys[j])) {
                printf("    %-35ws %-10s %ws\n", 
                       g_EDRDatabase[i].pwszEDRName, 
                       "Registry", 
                       g_EDRDatabase[i].pwszRegistryKeys[j]);
                
                g_DetectionResults[i].bRegistryDetected = TRUE;
                g_DetectionResults[i].dwRegistryCount++;
            }
        }
    }
    
    return TRUE;
}

BOOL CheckRegistryKey(LPCWSTR pwszKeyPath) {
    HKEY hKey;
    HKEY hRootKey = HKEY_LOCAL_MACHINE;
    LPCWSTR pwszSubKey = pwszKeyPath;
    
    // Parse the registry path
    if (wcsncmp(pwszKeyPath, L"HKLM\\", 5) == 0) {
        hRootKey = HKEY_LOCAL_MACHINE;
        pwszSubKey = pwszKeyPath + 5;
    }
    else if (wcsncmp(pwszKeyPath, L"HKCU\\", 5) == 0) {
        hRootKey = HKEY_CURRENT_USER;
        pwszSubKey = pwszKeyPath + 5;
    }
    
    LONG lResult = RegOpenKeyExW(hRootKey, pwszSubKey, 0, KEY_READ, &hKey);
    if (lResult == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return TRUE;
    }
    
    return FALSE;
}

void PrintSummary(void) {
    printf("===============================================\n");
    printf("               DETECTION SUMMARY\n");
    printf("===============================================\n\n");
    
    BOOL bAnyDetected = FALSE;
    
    for (DWORD i = 0; i < g_EDRCount; i++) {
        if (g_DetectionResults[i].bProcessDetected || 
            g_DetectionResults[i].bDriverDetected || 
            g_DetectionResults[i].bRegistryDetected) {
            
            bAnyDetected = TRUE;
            g_TotalDetections++;
            
            printf("[!] %ws (%ws)\n", 
                   g_EDRDatabase[i].pwszEDRName, 
                   g_EDRDatabase[i].pwszVendor);
            
            printf("    └─ Processes: %lu detected\n", g_DetectionResults[i].dwProcessCount);
            printf("    └─ Drivers:   %lu detected\n", g_DetectionResults[i].dwDriverCount);
            printf("    └─ Registry:  %lu detected\n", g_DetectionResults[i].dwRegistryCount);
            printf("\n");
        }
    }
    
    if (!bAnyDetected) {
        printf("[+] No known EDR products detected\n");
        printf("    Note: This doesn't guarantee the system is unmonitored\n\n");
    } else {
        printf("===============================================\n");
        printf("Total EDR products detected: %lu\n", g_TotalDetections);
        printf("===============================================\n");
    }
    
    printf("\n[*] Enumeration complete\n");
}
