#pragma once

constexpr auto OFFSET_PROTECTION = 0x6CA;
constexpr auto OFFSET_FLAGS2 = 0x828; // MitigationFlags offset

typedef union _PS_PROTECTION
{
    UCHAR Level;
    struct
    {
        int Type : 3;
        int Audit : 1;
        int Signer : 4;
    } Flags;
} PS_PROTECTION, * PPS_PROTECTION;

typedef enum _PS_PROTECTED_TYPE
{
    PsProtectedTypeNone = 0,
    PsProtectedTypeProtectedLight = 1,
    PsProtectedTypeProtected = 2,
    PsProtectedTypeMax = 3
} PS_PROTECTED_TYPE;

typedef enum _PS_PROTECTED_SIGNER
{
    PsProtectedSignerNone = 0,
    PsProtectedSignerAuthenticode = 1,
    PsProtectedSignerCodeGen = 2,
    PsProtectedSignerAntimalware = 3,
    PsProtectedSignerLsa = 4,
    PsProtectedSignerWindows = 5,
    PsProtectedSignerWinTcb = 6,
    PsProtectedSignerMax = 7
} PS_PROTECTED_SIGNER;

typedef struct _MITIGATION_FLAGS
{
    unsigned int ControlFlowGuardEnabled : 1;
    unsigned int ControlFlowGuardExportSuppressionEnabled : 1;
    unsigned int ControlFlowGuardStrict : 1;
    unsigned int DisallowStrippedImages : 1;
    unsigned int ForceRelocateImages : 1;
    unsigned int HighEntropyASLREnabled : 1;
    unsigned int StackRandomizationDisabled : 1;
    unsigned int ExtensionPointDisable : 1;
    unsigned int DisableDynamicCode : 1;
    unsigned int DisableDynamicCodeAllowOptOut : 1;
    unsigned int DisableDynamicCodeAllowRemoteDowngrade : 1;
    unsigned int AuditDisableDynamicCode : 1;
    unsigned int DisallowWin32kSystemCalls : 1;
    unsigned int AuditDisallowWin32kSystemCalls : 1;
    unsigned int EnableFilteredWin32kAPIs : 1;
    unsigned int AuditFilteredWin32kAPIs : 1;
    unsigned int DisableNonSystemFonts : 1;
    unsigned int AuditNonSystemFontLoading : 1;
    unsigned int PreferSystem32Images : 1;
    unsigned int ProhibitRemoteImageMap : 1;
    unsigned int AuditProhibitRemoteImageMap : 1;
    unsigned int ProhibitLowILImageMap : 1;
    unsigned int AuditProhibitLowILImageMap : 1;
    unsigned int SignatureMitigationOptIn : 1;
    unsigned int AuditBlockNonMicrosoftBinaries : 1;
    unsigned int AuditBlockNonMicrosoftBinariesAllowStore : 1;
    unsigned int LoaderIntegrityContinuityEnabled : 1;
    unsigned int AuditLoaderIntegrityContinuity : 1;
    unsigned int EnableModuleTamperingProtection : 1;
    unsigned int EnableModuleTamperingProtectionNoInherit : 1;
    unsigned int RestrictIndirectBranchPrediction;
    unsigned int IsolateSecurityDomain;
} MITIGATION_FLAGS, * PMITIGATION_FLAGS;

class Protection
{
public:
	static void SetProcessProtection(int pid);
};