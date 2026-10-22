[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$MsiPath,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ReleaseManifest,
    [ValidateSet('Install','RetireInitialRuntime','RecoverInterruptedInstall','RecoverStagedUpdate','Uninstall')]
    [string]$Operation = 'Install',
    [string]$StagedOperationId,
    [string]$SetupImagePath,
    [string]$CoreArchivePath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$SystemSid = 'S-1-5-18'
$AdministratorsSid = 'S-1-5-32-544'
$CacheSids = @($SystemSid, $AdministratorsSid)
$ManagedServiceNames = @('EndpointAgent', 'EndpointAgentUpdater', 'EndpointBrowserPolicy')
$WindowsInstallerServiceName = 'msiserver'
$ManagedServiceTimeout = [TimeSpan]::FromSeconds(45)
$script:InstallerLaunchBroker = $null
$script:InstallerPhaseMetrics = [Collections.Generic.List[object]]::new()

function Initialize-InstallerBridgeTypes {
    if ('EndpointInstallerBridge.Policy' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Pipes;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Security.AccessControl;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;
namespace EndpointInstallerBridge {
    public static class LaunchDirectory {
        [StructLayout(LayoutKind.Sequential)] struct Attributes { public int Length; public IntPtr Descriptor; public int Inherit; }
        [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string text,uint revision,out IntPtr descriptor,out uint length);
        [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool ConvertSecurityDescriptorToStringSecurityDescriptor(IntPtr descriptor,uint revision,uint information,out IntPtr text,out uint length);
        [DllImport("advapi32.dll",CharSet=CharSet.Unicode)] static extern uint GetNamedSecurityInfo(string name,int kind,uint information,out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr descriptor);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateDirectory(string path,ref Attributes attributes);
        [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr value);
        public static void Create(string path) {
            IntPtr descriptor=IntPtr.Zero;uint length;
            if(!ConvertStringSecurityDescriptorToSecurityDescriptor("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)S:(ML;OICI;NW;;;HI)",1,out descriptor,out length)) throw new Win32Exception();
            try {
                var attributes=new Attributes { Length=Marshal.SizeOf(typeof(Attributes)),Descriptor=descriptor,Inherit=0 };
                if(!CreateDirectory(path,ref attributes)) throw new Win32Exception();
            } finally { LocalFree(descriptor); }
            Validate(path);
        }
        public static void Validate(string path) {
            if(!Path.IsPathRooted(path) || (File.GetAttributes(path)&(FileAttributes.ReparsePoint|FileAttributes.Directory))!=FileAttributes.Directory) throw new InvalidOperationException("OWNER_AUTH_FAILED");
            var security=Directory.GetAccessControl(path,AccessControlSections.Owner|AccessControlSections.Access);
            if(!security.AreAccessRulesProtected || security.GetOwner(typeof(SecurityIdentifier)).Value!="S-1-5-32-544") throw new InvalidOperationException("OWNER_AUTH_FAILED");
            var seen=new HashSet<string>();
            foreach(FileSystemAccessRule rule in security.GetAccessRules(true,true,typeof(SecurityIdentifier))) {
                string sid=rule.IdentityReference.Value;
                if((sid!="S-1-5-18" && sid!="S-1-5-32-544") || rule.IsInherited || rule.AccessControlType!=AccessControlType.Allow ||
                    rule.FileSystemRights!=FileSystemRights.FullControl || rule.InheritanceFlags!=(InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit) ||
                    rule.PropagationFlags!=PropagationFlags.None || !seen.Add(sid)) throw new InvalidOperationException("OWNER_AUTH_FAILED");
            }
            if(seen.Count!=2) throw new InvalidOperationException("OWNER_AUTH_FAILED");
            ValidateAncestors(path);
            IntPtr owner,group,dacl,sacl,descriptor=IntPtr.Zero,text=IntPtr.Zero;uint length;
            uint error=GetNamedSecurityInfo(path,1,0x10,out owner,out group,out dacl,out sacl,out descriptor);
            if(error!=0) throw new Win32Exception((int)error);
            try {
                if(!ConvertSecurityDescriptorToStringSecurityDescriptor(descriptor,1,0x10,out text,out length)) throw new Win32Exception();
                // Windows records the auto-inherited SACL control bit on
                // creation even though the sole mandatory ACE is explicit.
                string label=Marshal.PtrToStringUni(text);
                if(label!="S:(ML;OICI;NW;;;HI)" && label!="S:AI(ML;OICI;NW;;;HI)") throw new InvalidOperationException("OWNER_AUTH_FAILED");
            } finally { if(text!=IntPtr.Zero) LocalFree(text);if(descriptor!=IntPtr.Zero) LocalFree(descriptor); }
        }
        public static void ValidateAncestors(string path) {
            if(!Path.IsPathRooted(path)) throw new InvalidOperationException("OWNER_AUTH_FAILED");
            var trusted=new HashSet<string>(new string[]{"S-1-5-18","S-1-5-32-544","S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"});
            for(var parent=Directory.GetParent(path);parent!=null;parent=parent.Parent) {
                if((parent.Attributes&FileAttributes.ReparsePoint)!=0) throw new InvalidOperationException("OWNER_AUTH_FAILED");
                var ancestor=parent.GetAccessControl(AccessControlSections.Owner|AccessControlSections.Access);
                if(!trusted.Contains(ancestor.GetOwner(typeof(SecurityIdentifier)).Value)) throw new InvalidOperationException("OWNER_AUTH_FAILED");
                var rules=ancestor.GetAccessRules(true,true,typeof(SecurityIdentifier));
                if(rules.Count==0) throw new InvalidOperationException("OWNER_AUTH_FAILED");
                foreach(FileSystemAccessRule rule in rules) {
                    if(rule.AccessControlType!=AccessControlType.Allow) throw new InvalidOperationException("OWNER_AUTH_FAILED");
                    if((rule.PropagationFlags&PropagationFlags.InheritOnly)!=0) continue;
                    if(!trusted.Contains(rule.IdentityReference.Value) && (((uint)rule.FileSystemRights)&0x500d0040)!=0) throw new InvalidOperationException("OWNER_AUTH_FAILED");
                }
            }
        }
        public static ProcessStartInfo StartInfo(string executable,string arguments,string directory) {
            Validate(directory);
            if(!Path.IsPathRooted(executable) || String.IsNullOrEmpty(arguments) || arguments.Length>4096 || arguments.IndexOfAny(new char[]{'\r','\n','\0'})>=0) throw new InvalidOperationException("OWNER_AUTH_FAILED");
            var info=new ProcessStartInfo(executable,arguments) { UseShellExecute=false,CreateNoWindow=true,WindowStyle=ProcessWindowStyle.Hidden,WorkingDirectory=directory };
            info.EnvironmentVariables["TEMP"]=directory;info.EnvironmentVariables["TMP"]=directory;
            return info;
        }
    }
    public static class PackageHelper {
        [DllImport("msi.dll",CharSet=CharSet.Unicode)] static extern uint MsiOpenDatabase(string path,IntPtr persist,out uint database);
        [DllImport("msi.dll",CharSet=CharSet.Unicode)] static extern uint MsiDatabaseOpenView(uint database,string sql,out uint view);
        [DllImport("msi.dll")] static extern uint MsiViewExecute(uint view,uint record);
        [DllImport("msi.dll")] static extern uint MsiViewFetch(uint view,out uint record);
        [DllImport("msi.dll")] static extern uint MsiRecordReadStream(uint record,uint field,byte[] data,ref uint size);
        [DllImport("msi.dll",CharSet=CharSet.Unicode)] static extern uint MsiRecordGetString(uint record,uint field,StringBuilder value,ref uint size);
        [DllImport("msi.dll")] static extern uint MsiCloseHandle(uint handle);
        public static string ProductCode(string package) {
            uint database=0,view=0,record=0;
            try {
                if(MsiOpenDatabase(package,IntPtr.Zero,out database)!=0 ||
                    MsiDatabaseOpenView(database,"SELECT `Value` FROM `Property` WHERE `Property`='ProductCode'",out view)!=0 ||
                    MsiViewExecute(view,0)!=0 || MsiViewFetch(view,out record)!=0) throw new InvalidOperationException("PROVENANCE_CONFLICT");
                var value=new StringBuilder(39);uint length=39;
                if(MsiRecordGetString(record,1,value,ref length)!=0 || length!=38) throw new InvalidOperationException("PROVENANCE_CONFLICT");
                Guid parsed;string text=value.ToString();
                if(!Guid.TryParseExact(text,"B",out parsed) || "{"+parsed.ToString("D").ToUpperInvariant()+"}"!=text)
                    throw new InvalidOperationException("PROVENANCE_CONFLICT");
                return text;
            } finally {
                if(record!=0) MsiCloseHandle(record);if(view!=0) MsiCloseHandle(view);if(database!=0) MsiCloseHandle(database);
            }
        }
        public static FileSecurity SecretSecurity() {
            var security=new FileSecurity();security.SetAccessRuleProtection(true,false);
            security.SetOwner(new SecurityIdentifier("S-1-5-32-544"));
            foreach(var sid in new string[]{"S-1-5-18","S-1-5-32-544"})
                security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid),FileSystemRights.FullControl,AccessControlType.Allow));
            return security;
        }
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool MoveFileExW(string from,string to,uint flags);
        public static void CopyCacheArtifact(string source,string destination) {
            LaunchDirectory.ValidateAncestors(destination);
            if(File.Exists(destination) || (File.GetAttributes(source)&FileAttributes.ReparsePoint)!=0) throw new InvalidOperationException("PROVENANCE_CONFLICT");
            string temporary=destination+"."+Guid.NewGuid().ToString("N")+".tmp";
            using(var input=new FileStream(source,FileMode.Open,FileAccess.Read,FileShare.Read))
            using(var output=new FileStream(temporary,FileMode.CreateNew,FileSystemRights.Write,FileShare.None,1024*1024,FileOptions.WriteThrough,SecretSecurity())) {
                input.CopyTo(output,1024*1024);output.Flush(true);
            }
            // No REPLACE_EXISTING; write-through publication keeps a crash from
            // making the operation-bound recovery path point at an empty file.
            if(!MoveFileExW(temporary,destination,8)) throw new Win32Exception();
        }
        public static void WriteCapability(string path,byte[] bytes) {
            if(bytes.Length>16384) throw new InvalidOperationException("OWNER_AUTH_FAILED");
            var temporary=path+"."+Guid.NewGuid().ToString("N")+".tmp";
            using(var file=new FileStream(temporary,FileMode.CreateNew,FileSystemRights.Write,FileShare.None,4096,FileOptions.WriteThrough,SecretSecurity())) {
                file.Write(bytes,0,bytes.Length);file.Flush(true);
            }
            // A capability filename is immutable for its entire session.
            File.Move(temporary,path);
        }
        public static string Extract(string package,string destination) {
            uint database=0,view=0,record=0;
            FileStream target=null;
            try {
                if(MsiOpenDatabase(package,IntPtr.Zero,out database)!=0 ||
                   MsiDatabaseOpenView(database,"SELECT `Data` FROM `Binary` WHERE `Name`='EndpointInstallerHost'",out view)!=0 ||
                   MsiViewExecute(view,0)!=0 || MsiViewFetch(view,out record)!=0) throw new InvalidOperationException("PROVENANCE_CONFLICT");
                bool existing=File.Exists(destination);
                string prepared=existing ? destination : destination+"."+Guid.NewGuid().ToString("N")+".tmp";
                if(!existing) target=new FileStream(prepared,FileMode.CreateNew,FileSystemRights.Write,FileShare.None,1048576,FileOptions.WriteThrough,SecretSecurity());
                string hash;long total=0;
                using(var sha=SHA256.Create()) {
                    byte[] buffer=new byte[1048576];
                    while(true) {
                        uint count=(uint)buffer.Length;
                        if(MsiRecordReadStream(record,1,buffer,ref count)!=0) throw new InvalidOperationException("PROVENANCE_CONFLICT");
                        if(count==0) break;
                        total+=count;if(total>134217728) throw new InvalidOperationException("PROVENANCE_CONFLICT");
                        sha.TransformBlock(buffer,0,(int)count,null,0);
                        if(target!=null) target.Write(buffer,0,(int)count);
                    }
                    if(total==0) throw new InvalidOperationException("PROVENANCE_CONFLICT");
                    sha.TransformFinalBlock(new byte[0],0,0);hash=Policy.Hex(sha.Hash);
                }
                if(target!=null){target.Flush(true);target.Dispose();target=null;}
                using(var file=new FileStream(prepared,FileMode.Open,FileAccess.Read,FileShare.Read))
                using(var sha=SHA256.Create()) if(Policy.Hex(sha.ComputeHash(file))!=hash) throw new InvalidOperationException("PROVENANCE_CONFLICT");
                if(!existing) File.Move(prepared,destination);
                return hash;
            } finally {
                if(target!=null) target.Dispose();
                if(record!=0) MsiCloseHandle(record);if(view!=0) MsiCloseHandle(view);if(database!=0) MsiCloseHandle(database);
            }
        }
    }
    public sealed class NativeProcess : IDisposable {
        [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,int pid);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessTimes(IntPtr handle,out long created,out long exit,out long kernel,out long user);
        [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)] static extern bool QueryFullProcessImageName(IntPtr handle,int flags,StringBuilder path,ref int length);
        [DllImport("kernel32.dll",SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle,uint timeout);
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
        [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
        [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetTokenInformation(IntPtr token,int kind,out int value,int length,out int returned);
        [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr CreateToolhelp32Snapshot(uint flags,uint process);
        [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct ProcessEntry {
            public uint Size,Usage,Pid; public IntPtr Heap; public uint Module,Threads,Parent;
            public int Priority; public uint Flags; [MarshalAs(UnmanagedType.ByValTStr,SizeConst=260)] public string File;
        }
        [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)] static extern bool Process32First(IntPtr snapshot,ref ProcessEntry entry);
        [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)] static extern bool Process32Next(IntPtr snapshot,ref ProcessEntry entry);
        private IntPtr handle;
        private FileStream image;
        public readonly Identity Identity;
        public readonly string ImagePath;
        public NativeProcess(int pid) {
            handle=OpenProcess(0x00101000,false,pid);
            if(handle==IntPtr.Zero) throw new Win32Exception();
            try {
                long created,exit,kernel,user;
                if(!GetProcessTimes(handle,out created,out exit,out kernel,out user)) throw new Win32Exception();
                var path=new StringBuilder(32768); int length=path.Capacity;
                if(!QueryFullProcessImageName(handle,0,path,ref length)) throw new Win32Exception();
                ImagePath=Path.GetFullPath(path.ToString());
                for(var parent=new FileInfo(ImagePath).Directory;parent!=null;parent=parent.Parent)
                    if((parent.Attributes & FileAttributes.ReparsePoint)!=0) throw new InvalidOperationException("OWNER_AUTH_FAILED");
                if((File.GetAttributes(ImagePath) & FileAttributes.ReparsePoint)!=0) throw new InvalidOperationException("OWNER_AUTH_FAILED");
                image=new FileStream(ImagePath,FileMode.Open,FileAccess.Read,FileShare.Read);
                string hash; using(var sha=SHA256.Create()) hash=Policy.Hex(sha.ComputeHash(image));
                IntPtr token;
                if(!OpenProcessToken(handle,8,out token)) throw new Win32Exception();
                try {
                    int elevation,returned;
                    if(!GetTokenInformation(token,20,out elevation,4,out returned)) throw new Win32Exception();
                    using(var identity=new WindowsIdentity(token))
                        Identity=new Identity(pid,created,hash,identity.User.Value,elevation!=0 || identity.User.Value=="S-1-5-18");
                } finally { CloseHandle(token); }
                if(!Alive) throw new InvalidOperationException("OWNER_AUTH_FAILED");
            } catch { Dispose(); throw; }
        }
        public bool Alive { get { return handle!=IntPtr.Zero && WaitForSingleObject(handle,0)==258; } }
        public bool DirectChildOf(NativeProcess parent) {
            if(parent==null || !parent.Alive || !Alive || Identity.Created<parent.Identity.Created ||
                Identity.Hash!=parent.Identity.Hash || Identity.Sid!=parent.Identity.Sid || Identity.Elevated!=parent.Identity.Elevated) return false;
            IntPtr snapshot=CreateToolhelp32Snapshot(2,0);
            if(snapshot==new IntPtr(-1)) throw new Win32Exception();
            try {
                var entry=new ProcessEntry(); entry.Size=(uint)Marshal.SizeOf(typeof(ProcessEntry));
                bool more=Process32First(snapshot,ref entry);
                while(more) { if(entry.Pid==(uint)Identity.Pid) return entry.Parent==(uint)parent.Identity.Pid; more=Process32Next(snapshot,ref entry); }
                return false;
            } finally { CloseHandle(snapshot); }
        }
        public void Dispose() { if(image!=null){image.Dispose();image=null;} if(handle!=IntPtr.Zero){CloseHandle(handle);handle=IntPtr.Zero;} }
    }
    // A single local instance, bounded framing, asynchronous transport only.
    // No callback grants phases: the owning PowerShell thread polls and grants.
    public sealed class Channel : IDisposable {
        [StructLayout(LayoutKind.Sequential)] struct SecurityAttributes { public int Length; public IntPtr Descriptor; public int Inherit; }
        [DllImport("advapi32.dll",SetLastError=true,CharSet=CharSet.Unicode)] static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string text,uint revision,out IntPtr descriptor,out uint size);
        [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)] static extern SafePipeHandle CreateNamedPipe(string name,uint access,uint mode,uint instances,uint output,uint input,uint timeout,ref SecurityAttributes security);
        [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe,out uint pid);
        private readonly NamedPipeServerStream stream;
        private IAsyncResult connect,read,write;
        private byte[] input=new byte[4],output;
        private int offset,target=4;
        private bool header=true;
        public bool Connected { get; private set; }
        public Channel(string name) {
            if(!Regex.IsMatch(name ?? "","\\AEndpointInstaller-[0-9a-f-]{36}-[0-9a-f]{32}\\z")) throw new InvalidOperationException("OWNER_AUTH_FAILED");
            IntPtr descriptor; uint size;
            // FILE_CREATE_PIPE_INSTANCE (0x4) is deliberately absent.
            if(!ConvertStringSecurityDescriptorToSecurityDescriptor("O:BAG:BAD:P(A;;0x12019b;;;SY)(A;;0x12019b;;;BA)",1,out descriptor,out size)) throw new Win32Exception();
            try {
                var security=new SecurityAttributes { Length=Marshal.SizeOf(typeof(SecurityAttributes)),Descriptor=descriptor,Inherit=0 };
                var pipe=CreateNamedPipe(@"\\.\pipe\"+name,0x40080003,8,1,65536,65536,5000,ref security);
                if(pipe.IsInvalid) throw new Win32Exception();
                try { stream=new NamedPipeServerStream(PipeDirection.InOut,true,false,pipe); }
                catch { pipe.Dispose();throw; }
                connect=stream.BeginWaitForConnection(null,null);
            } finally { LocalFree(descriptor); }
        }
        public int PeerPid() { uint pid;if(!Connected || !GetNamedPipeClientProcessId(stream.SafePipeHandle,out pid)) throw new Win32Exception(); return checked((int)pid); }
        public byte[] Poll() {
            if(!Connected) { if(!connect.IsCompleted) return null;stream.EndWaitForConnection(connect);Connected=true; }
            if(write!=null) { if(!write.IsCompleted) return null;stream.EndWrite(write);write=null;output=null; }
            // Drain a buffered header/body without an artificial owner-loop
            // sleep between them. Bound the work even for fragmented input.
            for(int budget=0;budget<64;budget++) {
                if(read==null) read=stream.BeginRead(input,offset,target-offset,null,null);
                if(!read.IsCompleted) return null;
                int count=stream.EndRead(read);read=null;
                if(count<=0) throw new IOException("OWNER_AUTH_FAILED");
                offset+=count;
                if(offset!=target) continue;
                if(header) {
                    int length=BitConverter.ToInt32(input,0);
                    if(length<=0 || length>32768) throw new IOException("OWNER_AUTH_FAILED");
                    input=new byte[length];target=length;offset=0;header=false;continue;
                }
                var result=input;input=new byte[4];target=4;offset=0;header=true;return result;
            }
            return null;
        }
        public void WaitForActivity(int milliseconds) {
            if(milliseconds<0 || milliseconds>10) throw new ArgumentOutOfRangeException("milliseconds");
            var pending=!Connected ? connect : (write ?? read);
            if(pending!=null) pending.AsyncWaitHandle.WaitOne(milliseconds);
            else if(milliseconds>0) Thread.Sleep(1);
            // EndRead/EndWrite/EndWaitForConnection own the async handle's
            // lifetime. Never close its event while the I/O can still complete.
        }
        public static void WaitForAnyActivity(Channel[] channels,IAsyncResult native,int milliseconds) {
            if(milliseconds<0 || milliseconds>10) throw new ArgumentOutOfRangeException("milliseconds");
            if(channels==null || channels.Length<1 || channels.Length>2) throw new ArgumentException("channels");
            var handles=new List<WaitHandle>();
            for(int i=0;i<channels.Length;i++) {
                var channel=channels[i];
                if(channel==null || (i>0 && Object.ReferenceEquals(channel,channels[0]))) throw new ArgumentException("channels");
                var pending=!channel.Connected ? channel.connect : (channel.write ?? channel.read);
                if(pending!=null) handles.Add(pending.AsyncWaitHandle);
            }
            if(native!=null && !native.IsCompleted) handles.Add(native.AsyncWaitHandle);
            // Observe readiness only. Poll/End* still run on the retained owner
            // thread and retain the original framing, authentication and grants.
            // The async operations own these handles; this wait never closes them.
            if(handles.Count>0) WaitHandle.WaitAny(handles.ToArray(),milliseconds);
            else if(milliseconds>0) Thread.Sleep(1);
        }
        public void Send(byte[] data) {
            if(!Connected || write!=null || data==null || data.Length==0 || data.Length>32768) throw new IOException("OWNER_AUTH_FAILED");
            output=new byte[data.Length+4];Buffer.BlockCopy(BitConverter.GetBytes(data.Length),0,output,0,4);Buffer.BlockCopy(data,0,output,4,data.Length);
            write=stream.BeginWrite(output,0,output.Length,null,null);
        }
        public void Disconnect() {
            if(write!=null && !write.IsCompleted) throw new IOException("OWNER_AUTH_FAILED");
            if(write!=null){stream.EndWrite(write);write=null;output=null;}
            if(read!=null) throw new IOException("OWNER_AUTH_FAILED");
            stream.Disconnect();Connected=false;input=new byte[4];target=4;offset=0;header=true;
            connect=stream.BeginWaitForConnection(null,null);
        }
        public void Dispose() { stream.Dispose(); }
    }
    public sealed class Identity {
        public readonly int Pid;
        public readonly long Created;
        public readonly string Hash, Sid;
        public readonly bool Elevated;
        public Identity(int pid, long created, string hash, string sid, bool elevated) {
            if (pid <= 0 || created <= 0 || !Regex.IsMatch(hash ?? "", "\\A[0-9a-f]{64}\\z") ||
                !Regex.IsMatch(sid ?? "", "\\AS-1-[0-9-]+\\z")) throw new InvalidOperationException("OWNER_AUTH_FAILED");
            Pid=pid; Created=created; Hash=hash; Sid=sid; Elevated=elevated;
        }
        public string Key { get { return Pid.ToString(CultureInfo.InvariantCulture)+":"+Created.ToString(CultureInfo.InvariantCulture); } }
        public bool Same(Identity value) { return value != null && Key==value.Key && Hash==value.Hash && Sid==value.Sid && Elevated==value.Elevated; }
    }
    public sealed class Challenge {
        public string Nonce, Phase, Action, PayloadHash, Transcript;
        public long Sequence;
        public Identity Peer;
    }
    public sealed class Registration {
        public Identity Peer;
        public string Phase;
        public bool Begun, Complete, Exited;
    }
    // Pure policy is called only on the mutex-owning PowerShell thread. The
    // transport supplies opened/retained native identities, never wire claims.
    public sealed class Policy {
        public readonly string TransactionId, SessionId, PackageHash, Operation, HelperHash;
        public readonly Identity Owner;
        private readonly byte[] secret;
        private readonly Dictionary<string,Registration> helpers=new Dictionary<string,Registration>();
        private Challenge pending;
        private long sequence;
        private bool alive=true, quiescent, preparedComplete, msiAlive, preflightComplete, nativeEntered, foundationComplete, nativeComplete;
        private bool onlineRegistered, onlineComplete, sealRegistered;
        private int? nativeResult;
        private CompoundPolicy compound;
        private SuccessorRepairPolicy repair;
        private StagedRollbackPolicy reverse;
        private bool reversePrepared,stagedRecoverySettled;
        public void AuthorizeStagedRecovery(StagedSettlementProof proof) {
            if(!alive || proof==null || !proof.ValidFor(Owner) || msiAlive || nativeResult.HasValue ||
                compound!=null || repair!=null || reverse!=null || Recovery || UninstallFinalization) Fail();
            stagedRecoverySettled=true;
        }
        internal string ReversePlanHash,ReverseOldHash,ReverseHelperHash;
        internal bool ReverseLegacy { get { return ReverseHelperHash==null; } }
        internal bool Prepared { get { return preparedComplete; } }
        internal void BindReverse(StagedRollbackPolicy value,int role) {
            if(reverse!=null || compound!=null || repair!=null || Recovery || UninstallFinalization || msiAlive ||
                nativeResult.HasValue || !AllHelpersComplete || (role==0 ? !reversePrepared : role==1 ? !preparedComplete : preparedComplete || helpers.Count!=0)) Fail();
            reverse=value;
        }
        public void AuthorizeStagedReversePlan(string planHash,string oldHash,string oldHelperHash) {
            // Windows PowerShell binds its null argument to an empty string.
            if(oldHelperHash=="")oldHelperHash=null;
            if(!alive || !reversePrepared || !AllHelpersComplete || ReversePlanHash!=null || msiAlive || nativeResult.HasValue ||
                !Regex.IsMatch(planHash??"","\\A[0-9a-f]{64}\\z") || !Regex.IsMatch(oldHash??"","\\A[0-9a-f]{64}\\z") ||
                oldHash==PackageHash || (oldHelperHash!=null && !Regex.IsMatch(oldHelperHash,"\\A[0-9a-f]{64}\\z")) ||
                (oldHelperHash==null && oldHash!="2f7d778799f1e32645af7936dfaf3f090d6ad4df5bb883827ea8a0a5d859f72a")) Fail();
            ReversePlanHash=planHash;ReverseOldHash=oldHash;ReverseHelperHash=oldHelperHash;
        }
        private bool recoveryLocator, preparedRemovalSealed, preparedRemovalBound;
        public bool Recovery, UninstallFinalization;
        public Policy(string transactionId,string sessionId,string packageHash,string operation,Identity owner,string helperHash,byte[] key) {
            Guid parsed;
            if (!Guid.TryParseExact(transactionId,"D",out parsed) || parsed.ToString("D")!=transactionId ||
                !Guid.TryParseExact(sessionId,"D",out parsed) || parsed.ToString("D")!=sessionId ||
                !Regex.IsMatch(packageHash ?? "","\\A[0-9a-f]{64}\\z") ||
                !Regex.IsMatch(helperHash ?? "","\\A[0-9a-f]{64}\\z") ||
                (operation!="install" && operation!="retire-initial-runtime" && operation!="uninstall") ||
                owner==null || !owner.Elevated || key==null || key.Length!=32) Fail();
            TransactionId=transactionId; SessionId=sessionId; PackageHash=packageHash; Operation=operation;
            Owner=owner; HelperHash=helperHash; secret=(byte[])key.Clone();
        }
        private static void Fail() { throw new InvalidOperationException("OWNER_AUTH_FAILED"); }
        internal bool Alive { get { return alive; } }
        internal bool FoundationComplete { get { return foundationComplete; } }
        internal bool PreparedRemovalActive { get { return alive && preparedRemovalSealed && !Recovery && !UninstallFinalization; } }
        public void MarkHelperExited(Identity peer,int code) {
            CheckPeer(peer);
            Registration item=null;
            if(code!=0 || pending!=null || !helpers.TryGetValue(peer.Key,out item) || !item.Peer.Same(peer) || !item.Complete || item.Exited) Fail();
            item.Exited=true;
        }
        public void SealPreparedRemoval() {
            if(!alive || preparedRemovalSealed || recoveryLocator || compound!=null || repair!=null ||
                Operation!="uninstall" || Recovery || UninstallFinalization || !quiescent || !preparedComplete ||
                !AllHelpersComplete || msiAlive || nativeEntered || nativeComplete || nativeResult.HasValue || pending!=null) Fail();
            foreach(var item in helpers.Values) if(!item.Exited) Fail();
            preparedRemovalSealed=true;
        }
        internal void ConsumePreparedRemoval(Policy replacement) {
            if(!PreparedRemovalActive || preparedRemovalBound || replacement==null || !replacement.Recovery ||
                replacement.UninstallFinalization || replacement.Operation!="uninstall" ||
                !Owner.Same(replacement.Owner) || TransactionId!=replacement.TransactionId ||
                PackageHash!=replacement.PackageHash || HelperHash!=replacement.HelperHash || SessionId==replacement.SessionId) Fail();
            preparedRemovalBound=true;
        }
        internal void BindCompound(CompoundPolicy value) {
            if(preparedRemovalSealed || recoveryLocator || compound!=null || repair!=null || Recovery!=value.ExpectedRecovery(this) || UninstallFinalization || msiAlive || nativeResult.HasValue || !preparedComplete || !AllHelpersComplete) Fail();
            compound=value;
        }
        internal void BindRepair(SuccessorRepairPolicy value) {
            if(recoveryLocator || compound!=null || repair!=null || !Recovery || UninstallFinalization || msiAlive || nativeResult.HasValue || !preparedComplete || !AllHelpersComplete) Fail();
            repair=value;
        }
        public void MarkRecoveryLocator() {
            if(recoveryLocator || compound!=null || repair!=null || Operation!="install" || !Recovery || UninstallFinalization || helpers.Count!=0 || msiAlive || nativeResult.HasValue) Fail();
            recoveryLocator=true;
        }
        private void CheckPeer(Identity peer) {
            if (!alive || preparedRemovalSealed || (compound!=null && !compound.OwnerActive) || (repair!=null && !repair.OwnerActive) || (reverse!=null && !reverse.OwnerActive) || peer==null || !peer.Elevated || peer.Hash!=HelperHash ||
                (peer.Sid!=Owner.Sid && peer.Sid!="S-1-5-18")) Fail();
        }
        public void RegisterHelper(Identity peer,string phase) {
            CheckPeer(peer);
            bool recoveryHelper=phase=="restore-staged-companions" || phase=="inspect-staged-recovery" || phase=="recover-staged-owner" || phase=="record-staged-reboot-3010" || phase=="record-staged-reboot-1641";
            if(phase=="recover-staged-owner" && !stagedRecoverySettled) Fail();
            bool reverseControl=phase=="inspect-staged-state" || phase=="prepare-foundation-rollback" || phase=="bind-foundation-rollback-roles" ||
                phase=="rollback-candidate-removed" || phase=="rollback-native-committed" || phase=="verify-foundation-rollback";
            if(reverseControl && (Operation!="install" || Recovery || UninstallFinalization || compound!=null || repair!=null ||
                preparedComplete || msiAlive || nativeResult.HasValue)) Fail();
            bool trial=phase=="begin-staged-trial" || phase=="observe-staged-trial" || phase=="accept-staged-trial";
            if(trial && (Operation!="install" || Recovery || UninstallFinalization || compound!=null || repair!=null ||
                preparedComplete || msiAlive || nativeResult.HasValue)) Fail();
            if(phase=="stage-online" && (Operation!="install" || Recovery || UninstallFinalization ||
                compound!=null || repair!=null || quiescent || onlineRegistered || msiAlive || nativeResult.HasValue)) Fail();
            if(phase=="seal-staged-switch" && (!onlineComplete || sealRegistered || Operation!="install" ||
                Recovery || UninstallFinalization || compound!=null || repair!=null || msiAlive || nativeResult.HasValue)) Fail();
            if(phase=="adopt-staged-switch" && (Operation!="install" || Recovery || UninstallFinalization ||
                preparedComplete || msiAlive || nativeResult.HasValue || helpers.Count!=0)) Fail();
            if(recoveryLocator && phase!="inspect-compound") Fail();
            if(compound!=null && !compound.AllowsHelper(this,phase)) Fail();
            if(repair!=null && !repair.AllowsHelper(phase)) Fail();
            if(reverse!=null && !reverse.AllowsHelper(this,phase)) Fail();
            if (!trial && !reverseControl && !recoveryHelper && phase!="inspect" && phase!="inspect-compound" && phase!="prepare" && phase!="stage-online" && phase!="seal-staged-switch" && phase!="adopt-staged-switch" && phase!="reconcile" && phase!="finish" && phase!="verify-settled" &&
                !(compound!=null && (phase=="compound-old-returned" || phase=="compound-new-returned" ||
                    phase=="compound-commit" || phase=="compound-retire" || phase=="compound-complete")) &&
                !(repair!=null && (phase=="compound-repair-returned" || phase=="compound-repair-commit" || phase=="compound-retire" || phase=="compound-complete"))) Fail();
            if (phase!="inspect" && phase!="inspect-compound" && phase!="verify-settled" && phase!="stage-online" && phase!="inspect-staged-state" && phase!="inspect-staged-recovery" && phase!="recover-staged-owner" && phase!="restore-staged-companions" && !quiescent) Fail();
            if ((phase=="reconcile" || phase=="finish") && (!nativeComplete || !nativeResult.HasValue ||
                nativeResult.Value!=0)) Fail();
            if (helpers.Count>=64 || helpers.ContainsKey(peer.Key)) Fail();
            helpers.Add(peer.Key,new Registration { Peer=peer, Phase=phase });
            if(phase=="stage-online") onlineRegistered=true;
            if(phase=="seal-staged-switch") sealRegistered=true;
        }
        public void RegisterMsi(Identity peer,string operation) {
            if(preparedRemovalSealed || recoveryLocator) Fail();
            if(compound!=null && !compound.Registering) Fail();
            if(repair!=null && !repair.Registering) Fail();
            if(reverse!=null && !reverse.Registering) Fail();
            if (!alive || !quiescent || !preparedComplete || !AllHelpersComplete || msiAlive || peer==null || !peer.Elevated || operation!=Operation || nativeResult.HasValue) Fail();
            msiAlive=true;
        }
        public void MarkQuiescent() { if(!alive || !AllHelpersComplete) Fail(); quiescent=true; }
        public void MarkMsiExited(int code) {
            if(compound!=null && !compound.Settling) Fail();
            if(repair!=null && !repair.Settling) Fail();
            if(reverse!=null && !reverse.Settling) Fail();
            msiAlive=false; nativeResult=code; pending=null;
        }
        public void OwnerLost() { alive=false; pending=null; }
        public bool NativeEntered { get { return nativeEntered; } }
        public bool NativeComplete { get { return nativeComplete; } }
        public bool AllHelpersComplete { get { foreach(var item in helpers.Values) if(!item.Complete) return false; return true; } }
        public Challenge Issue(Identity peer,string phase,string action,string payloadHash,string sessionId) {
            CheckPeer(peer);
            if(recoveryLocator && (phase!="inspect-compound" || action=="mutation")) Fail();
            if(compound!=null && (phase.StartsWith("msi-",StringComparison.Ordinal) || phase=="recover-enter" || phase=="foundation-config") &&
                !compound.AllowsNative(this,phase)) Fail();
            if(repair!=null && (phase.StartsWith("msi-",StringComparison.Ordinal) || phase=="recover-enter" || phase=="foundation-config") && !repair.AllowsNative(phase)) Fail();
            if(reverse!=null && (phase.StartsWith("msi-",StringComparison.Ordinal) || phase=="recover-enter" || phase=="foundation-config") && !reverse.AllowsNative(this,phase)) Fail();
            if ((phase=="msi-enter" || phase=="recover-enter" || phase=="foundation-config" ||
                phase=="msi-complete" || phase=="uninstall-finalize-enter" || phase=="uninstall-finalize-complete") &&
                peer.Sid!="S-1-5-18") Fail();
            if (sessionId!=SessionId || pending!=null || sequence>=100000 || !Regex.IsMatch(payloadHash ?? "","\\A[0-9a-f]{64}\\z") ||
                (action!="begin" && action!="mutation" && action!="complete")) Fail();
            Registration item;
            if (!helpers.TryGetValue(peer.Key,out item)) {
                bool admitted=msiAlive && ((phase==(UninstallFinalization ? "uninstall-finalize-preflight" : "msi-preflight") && !preflightComplete) ||
                    (phase==(UninstallFinalization ? "uninstall-finalize-enter" : (Recovery ? "recover-enter" : "msi-enter")) && preflightComplete && !nativeEntered) ||
                    (phase=="foundation-config" && Operation=="install" && nativeEntered && !foundationComplete && !nativeComplete) ||
                    (phase==(UninstallFinalization ? "uninstall-finalize-complete" : "msi-complete") && nativeEntered && !nativeComplete && (Operation!="install" || foundationComplete)));
                if (!admitted || action!="begin" || helpers.Count>=64) Fail();
                item=new Registration { Peer=peer, Phase=phase }; helpers.Add(peer.Key,item);
            }
            if (!item.Peer.Same(peer) || item.Phase!=phase || item.Complete ||
                (action=="begin" && item.Begun) || (action!="begin" && !item.Begun) ||
                (phase.StartsWith("msi-",StringComparison.Ordinal) && !msiAlive) ||
                (phase=="recover-enter" && !msiAlive) ||
                (phase=="foundation-config" && !msiAlive) ||
                (phase.StartsWith("uninstall-finalize-",StringComparison.Ordinal) && (!msiAlive || !Recovery || Operation!="uninstall")) ||
                (action=="mutation" && (phase=="inspect" || phase.EndsWith("preflight",StringComparison.Ordinal) || phase=="verify-settled" || phase=="observe-staged-trial" || phase=="inspect-staged-state" || phase=="inspect-staged-recovery"))) Fail();
            byte[] nonce=new byte[32]; using(var rng=RandomNumberGenerator.Create()) rng.GetBytes(nonce);
            var value=new Challenge { Peer=peer,Phase=phase,Action=action,PayloadHash=payloadHash,
                Sequence=++sequence,Nonce=Hex(nonce) };
            value.Transcript=String.Join("|",new string[]{"1",TransactionId,SessionId,PackageHash,Operation,phase,action,
                value.Sequence.ToString(CultureInfo.InvariantCulture),peer.Pid.ToString(CultureInfo.InvariantCulture),
                peer.Created.ToString(CultureInfo.InvariantCulture),value.Nonce,payloadHash});
            pending=value; return value;
        }
        public string Sign(string prefix,Challenge value) {
            using(var hmac=new HMACSHA256(secret)) return Hex(hmac.ComputeHash(Encoding.ASCII.GetBytes(prefix+"|"+value.Transcript)));
        }
        public string Accept(Identity peer,Challenge value,string signature) {
            var expected=pending; pending=null;
            CheckPeer(peer);
            if(expected==null || !Object.ReferenceEquals(expected,value) || !value.Peer.Same(peer) ||
                !FixedEquals(Sign("request",value),signature)) Fail();
            var item=helpers[peer.Key];
            if(value.Action=="begin") { item.Begun=true; if(value.Phase=="msi-enter" || value.Phase=="recover-enter" || value.Phase=="uninstall-finalize-enter") nativeEntered=true; }
            if(value.Action=="complete") { item.Complete=true; if(value.Phase=="prepare") preparedComplete=true; if(value.Phase.EndsWith("preflight",StringComparison.Ordinal)) preflightComplete=true; if(value.Phase=="foundation-config") foundationComplete=true; if(value.Phase=="msi-complete" || value.Phase=="uninstall-finalize-complete") nativeComplete=true; }
            if(value.Action=="complete" && value.Phase=="stage-online") onlineComplete=true;
            if(value.Action=="complete" && value.Phase=="prepare-foundation-rollback") reversePrepared=true;
            if(value.Action=="complete" && compound!=null) compound.HelperComplete(this,value.Phase);
            if(value.Action=="complete" && repair!=null) repair.HelperComplete(value.Phase);
            if(value.Action=="complete" && reverse!=null) reverse.HelperComplete(this,value.Phase);
            return Sign("grant",value);
        }
        public static bool FixedEquals(string a,string b) {
            if(a==null || b==null || a.Length!=b.Length) return false;
            int difference=0; for(int i=0;i<a.Length;i++) difference|=a[i]^b[i]; return difference==0;
        }
        public static string Hex(byte[] bytes) { return BitConverter.ToString(bytes).Replace("-","").ToLowerInvariant(); }
    }
    // This owner-thread coordinator retains both independent package policies
    // through MsiEndTransaction. A package API return never grants finalization.
    public sealed class CompoundPolicy {
        private readonly Policy oldPackage, newPackage;
        private readonly Policy preparedOld;
        private readonly bool recovering;
        internal bool Recovering { get { return recovering; } }
        internal bool ExpectedRecovery(Policy policy) { return recovering || (preparedOld!=null && Object.ReferenceEquals(policy,oldPackage)); }
        private string state="prepared";
        private bool registering, settling;
        private bool oldRecorded,newRecorded;
        private string postStage="unrecorded";
        internal bool Registering { get { return registering; } }
        internal bool Settling { get { return settling; } }
        public bool OwnerActive { get { return oldPackage.Alive && newPackage.Alive &&
            (preparedOld==null || preparedOld.PreparedRemovalActive) &&
            oldPackage.Recovery==ExpectedRecovery(oldPackage) && newPackage.Recovery==recovering && !oldPackage.UninstallFinalization &&
            !newPackage.UninstallFinalization && state!="owner-lost"; } }
        public bool Committed { get { return state=="committed" && OwnerActive; } }
        internal bool ReadyToPublish { get { return Committed && postStage=="complete" && oldPackage.AllHelpersComplete && newPackage.AllHelpersComplete; } }
        public string State { get { return state; } }
        internal Policy OldPackage { get { return oldPackage; } }
        internal Policy NewPackage { get { return newPackage; } }
        private static void Fail() { throw new InvalidOperationException("OWNER_AUTH_FAILED"); }
        private void Require(string expected) { if(!OwnerActive || state!=expected) Fail(); }
        public CompoundPolicy(Policy oldPolicy,Policy newPolicy) : this(oldPolicy,newPolicy,false) {}
        public static CompoundPolicy CreateRecovery(Policy oldPolicy,Policy newPolicy) { return new CompoundPolicy(oldPolicy,newPolicy,true); }
        public static CompoundPolicy CreatePreparedRemoval(Policy preparedPolicy,Policy oldPolicy,Policy newPolicy) {
            if(preparedPolicy==null) Fail();
            preparedPolicy.ConsumePreparedRemoval(oldPolicy);
            return new CompoundPolicy(oldPolicy,newPolicy,false,preparedPolicy);
        }
        private CompoundPolicy(Policy oldPolicy,Policy newPolicy,bool recovery,Policy preparedPolicy=null) {
            if(oldPolicy==null || newPolicy==null || Object.ReferenceEquals(oldPolicy,newPolicy) ||
                oldPolicy.Recovery!=(recovery || preparedPolicy!=null) || newPolicy.Recovery!=recovery || oldPolicy.UninstallFinalization || newPolicy.UninstallFinalization ||
                !oldPolicy.Owner.Same(newPolicy.Owner) || oldPolicy.Operation!="uninstall" || newPolicy.Operation!="install" ||
                oldPolicy.PackageHash==newPolicy.PackageHash || oldPolicy.HelperHash==newPolicy.HelperHash ||
                oldPolicy.TransactionId==newPolicy.TransactionId || oldPolicy.SessionId==newPolicy.SessionId) Fail();
            oldPackage=oldPolicy;newPackage=newPolicy;recovering=recovery;preparedOld=preparedPolicy;
            oldPackage.BindCompound(this);newPackage.BindCompound(this);
        }
        public void BeginNative() {
            Require("prepared");registering=true;
            try { oldPackage.RegisterMsi(oldPackage.Owner,"uninstall");newPackage.RegisterMsi(newPackage.Owner,"install");state="begun"; }
            catch { OwnerLost();throw; } finally { registering=false; }
        }
        public void BeginOldScript() { Require("begun");state="old-script"; }
        public void OldScriptReturned(int code) {
            Require("old-script");
            if(code!=0) { state="failed";if(code==3010 || code==1641) Fail();return; }
            if(!oldPackage.NativeEntered || !oldPackage.AllHelpersComplete || oldPackage.NativeComplete) Fail();
            state="old-returned";
        }
        public void BeginNewScript() { Require("old-returned");if(!oldRecorded) Fail();state="new-script"; }
        public void NewScriptReturned(int code) {
            Require("new-script");
            if(code!=0) { state="failed";if(code==3010 || code==1641) Fail();return; }
            if(!newPackage.NativeEntered || !newPackage.FoundationComplete || !newPackage.AllHelpersComplete || newPackage.NativeComplete) Fail();
            state="scripts-returned";
        }
        public void BeginEnd(bool commit) {
            if(commit) { Require("scripts-returned");if(!newRecorded) Fail(); }
            else if(!OwnerActive || (state!="failed" && state!="begun" && state!="old-script" && state!="old-returned" && state!="new-script" && state!="scripts-returned")) Fail();
            state=commit ? "ending-commit" : "ending-rollback";
        }
        public void EndReturned(int code) {
            if(!OwnerActive || (state!="ending-commit" && state!="ending-rollback")) Fail();
            if(code!=0 || (state=="ending-commit" && (!oldPackage.NativeComplete || !newPackage.NativeComplete ||
                !oldPackage.AllHelpersComplete || !newPackage.AllHelpersComplete))) { OwnerLost();Fail(); }
            bool commit=state=="ending-commit";settling=true;
            try { oldPackage.MarkMsiExited(commit ? 0 : 1603);newPackage.MarkMsiExited(commit ? 0 : 1603); }
            finally { settling=false; }
            state=commit ? "committed" : "rolled-back";
        }
        internal bool AllowsNative(Policy policy,string phase) {
            if(!OwnerActive) return false;
            if(phase=="msi-complete") return state=="ending-commit";
            return Object.ReferenceEquals(policy,oldPackage) ? state=="old-script" : state=="new-script";
        }
        internal bool AllowsHelper(Policy policy,string phase) {
            if(!OwnerActive || !Object.ReferenceEquals(policy,newPackage) || !oldPackage.AllHelpersComplete || !newPackage.AllHelpersComplete) return false;
            if(phase=="compound-old-returned") return state=="old-returned" && !oldRecorded;
            if(phase=="compound-new-returned") return state=="scripts-returned" && !newRecorded;
            if(state!="committed") return false;
            if(phase=="verify-settled") return postStage=="complete";
            return (phase=="compound-commit" && postStage=="unrecorded") ||
                (phase=="compound-retire" && postStage=="committed") ||
                (phase=="reconcile" && postStage=="retired") ||
                (phase=="finish" && postStage=="reconciled") ||
                (phase=="compound-complete" && postStage=="finished");
        }
        internal void HelperComplete(Policy policy,string phase) {
            if(!Object.ReferenceEquals(policy,newPackage)) return;
            if(phase=="compound-old-returned") oldRecorded=true;
            else if(phase=="compound-new-returned") newRecorded=true;
            else if(phase=="compound-commit") postStage="committed";
            else if(phase=="compound-retire") postStage="retired";
            else if(phase=="reconcile") postStage="reconciled";
            else if(phase=="finish") postStage="finished";
            else if(phase=="compound-complete") postStage="complete";
        }
        public void OwnerLost() { state="owner-lost";oldPackage.OwnerLost();newPackage.OwnerLost();if(preparedOld!=null) preparedOld.OwnerLost(); }
    }
    // Native work runs on same-process workers while this original thread
    // retains the product mutex and pumps both authenticated package channels.
    public sealed class SuccessorRepairPolicy {
        internal readonly Policy Package;
        public readonly string OldPackageHash;
        private string state="prepared",post="unrecorded";
        private bool registering,settling,recorded;
        internal bool Registering { get { return registering; } }
        internal bool Settling { get { return settling; } }
        public bool OwnerActive { get { return Package.Alive && Package.Recovery && !Package.UninstallFinalization && state!="owner-lost"; } }
        public bool ReadyToPublish { get { return OwnerActive && state=="committed" && post=="complete" && Package.AllHelpersComplete; } }
        public string State { get { return state; } }
        private static void Fail() { throw new InvalidOperationException("OWNER_AUTH_FAILED"); }
        private void Require(string expected) { if(!OwnerActive || state!=expected) Fail(); }
        public SuccessorRepairPolicy(Policy package,string oldPackageHash) {
            if(package==null || package.Operation!="install" || !package.Recovery || package.UninstallFinalization ||
                !Regex.IsMatch(oldPackageHash ?? "","\\A[0-9a-f]{64}\\z") || oldPackageHash==package.PackageHash) Fail();
            Package=package;OldPackageHash=oldPackageHash;package.BindRepair(this);
        }
        public void BeginNative() {
            Require("prepared");registering=true;
            try { Package.RegisterMsi(Package.Owner,"install");state="begun"; }
            catch { OwnerLost();throw; } finally { registering=false; }
        }
        public void BeginScript() { Require("begun");state="script"; }
        public void ScriptReturned(int code) {
            Require("script");
            if(code!=0) { state="failed";if(code==3010 || code==1641) Fail();return; }
            if(!Package.NativeEntered || !Package.FoundationComplete || !Package.AllHelpersComplete || Package.NativeComplete) Fail();
            state="script-returned";
        }
        public void BeginEnd(bool commit) {
            if(commit) { Require("script-returned");if(!recorded) Fail(); }
            else if(!OwnerActive || (state!="failed" && state!="begun" && state!="script" && state!="script-returned")) Fail();
            state=commit ? "ending-commit" : "ending-rollback";
        }
        public void EndReturned(int code) {
            if(!OwnerActive || (state!="ending-commit" && state!="ending-rollback")) Fail();
            if(code!=0 || (state=="ending-commit" && (!Package.NativeComplete || !Package.AllHelpersComplete))) { OwnerLost();Fail(); }
            bool commit=state=="ending-commit";settling=true;
            try { Package.MarkMsiExited(commit ? 0 : 1603); } finally { settling=false; }
            state=commit ? "committed" : "rolled-back";
        }
        internal bool AllowsNative(string phase) { return OwnerActive && (phase=="msi-complete" ? state=="ending-commit" : state=="script"); }
        internal bool AllowsHelper(string phase) {
            if(!OwnerActive || !Package.AllHelpersComplete) return false;
            if(phase=="compound-repair-returned") return state=="script-returned" && !recorded;
            if(state!="committed") return false;
            return (phase=="compound-repair-commit" && post=="unrecorded") || (phase=="compound-retire" && post=="committed") ||
                (phase=="reconcile" && post=="retired") || (phase=="finish" && post=="reconciled") ||
                (phase=="compound-complete" && post=="finished") || (phase=="verify-settled" && post=="complete");
        }
        internal void HelperComplete(string phase) {
            if(phase=="compound-repair-returned") recorded=true;
            else if(phase=="compound-repair-commit") post="committed";
            else if(phase=="compound-retire") post="retired";
            else if(phase=="reconcile") post="reconciled";
            else if(phase=="finish") post="finished";
            else if(phase=="compound-complete") post="complete";
        }
        public void OwnerLost() { state="owner-lost";Package.OwnerLost(); }
    }
    public sealed class StagedRollbackPolicy {
        internal readonly Policy Control,Removal,Restoration;
        private string state="prepared",restorationPost="unrecorded";
        private bool registering,settling,removedRecorded,commitRecorded;
        public string State { get { return state; } }
        internal bool Registering { get { return registering; } }
        internal bool Settling { get { return settling; } }
        internal bool Legacy { get { return Restoration==null; } }
        public bool OwnerActive { get { return state!="owner-lost" && Control.Alive && Removal.Alive &&
            (Restoration==null || Restoration.Alive); } }
        internal bool NativeProofComplete { get { return Removal.NativeComplete && Removal.AllHelpersComplete &&
            (Legacy || (Restoration.NativeComplete && Restoration.AllHelpersComplete)); } }
        private static void Fail() { throw new InvalidOperationException("OWNER_AUTH_FAILED"); }
        private void Require(string value) { if(!OwnerActive || state!=value) Fail(); }
        public StagedRollbackPolicy(Policy control,Policy removal,Policy restoration) {
            if(control==null || removal==null || control.ReversePlanHash==null ||
                !control.Owner.Same(removal.Owner) || removal.Operation!="uninstall" || removal.Recovery ||
                removal.UninstallFinalization || removal.PackageHash!=control.PackageHash ||
                removal.HelperHash!=control.HelperHash || control.TransactionId==removal.TransactionId ||
                control.SessionId==removal.SessionId || (control.ReverseLegacy!=(restoration==null))) Fail();
            if(restoration!=null && (!control.Owner.Same(restoration.Owner) || restoration.Operation!="install" ||
                restoration.Recovery || restoration.UninstallFinalization || restoration.PackageHash!=control.ReverseOldHash ||
                restoration.HelperHash!=control.ReverseHelperHash || restoration.TransactionId==removal.TransactionId ||
                restoration.TransactionId==control.TransactionId || restoration.SessionId==removal.SessionId ||
                restoration.SessionId==control.SessionId)) Fail();
            Control=control;Removal=removal;Restoration=restoration;
            control.BindReverse(this,0);removal.BindReverse(this,1);
            if(restoration!=null)restoration.BindReverse(this,2);
            else restorationPost="finished";
        }
        public void BeginNative() {
            Require("prepared");registering=true;
            try { Removal.RegisterMsi(Removal.Owner,"uninstall");state="begun"; }
            catch { OwnerLost();throw; } finally { registering=false; }
        }
        public void BeginRemovalScript() { Require("begun");state="remove-script"; }
        public void RemovalReturned(int code) {
            Require("remove-script");
            if(code!=0) { state="failed";return; }
            if(!Removal.NativeEntered || !Removal.AllHelpersComplete || Removal.NativeComplete) Fail();
            state="removed";
        }
        public void BeginRestorationScript() {
            Require("removed");
            if(!removedRecorded) Fail();
            if(!Legacy) {
                if(!Restoration.Prepared || !Restoration.AllHelpersComplete) Fail();
                registering=true;
                try { Restoration.RegisterMsi(Restoration.Owner,"install"); }
                catch { OwnerLost();throw; } finally { registering=false; }
            }
            state="restore-script";
        }
        public void RestorationReturned(int code) {
            Require("restore-script");
            if(code!=0) { state="failed";return; }
            if(!Legacy && (!Restoration.NativeEntered || !Restoration.FoundationComplete ||
                !Restoration.AllHelpersComplete || Restoration.NativeComplete)) Fail();
            state="scripts-returned";
        }
        public void BeginEnd(bool commit) {
            if(commit) Require("scripts-returned");
            else if(!OwnerActive || (state!="failed" && state!="begun" && state!="remove-script" &&
                state!="removed" && state!="restore-script" && state!="scripts-returned")) Fail();
            state=commit ? "ending-commit" : "ending-rollback";
        }
        public void EndReturned(int code) {
            if(!OwnerActive || (state!="ending-commit" && state!="ending-rollback")) Fail();
            if(code!=0 || (state=="ending-commit" && !NativeProofComplete)) { OwnerLost();Fail(); }
            bool commit=state=="ending-commit";settling=true;
            try { Removal.MarkMsiExited(commit ? 0 : 1603);if(!Legacy)Restoration.MarkMsiExited(commit ? 0 : 1603); }
            finally { settling=false; }
            state=commit ? "committed" : "rolled-back";
        }
        internal bool AllowsNative(Policy policy,string phase) {
            if(!OwnerActive || Object.ReferenceEquals(policy,Control)) return false;
            if(phase=="msi-complete")return state=="ending-commit";
            return Object.ReferenceEquals(policy,Removal) ? state=="remove-script" :
                Object.ReferenceEquals(policy,Restoration) && state=="restore-script";
        }
        internal bool AllowsHelper(Policy policy,string phase) {
            if(!OwnerActive) return false;
            if(Object.ReferenceEquals(policy,Control)) {
                return (phase=="rollback-candidate-removed" && state=="removed" && !removedRecorded) ||
                    (phase=="rollback-native-committed" && state=="committed" && restorationPost=="finished" && !commitRecorded) ||
                    (phase=="verify-foundation-rollback" && state=="committed" && commitRecorded);
            }
            if(!Object.ReferenceEquals(policy,Restoration))return false;
            return (phase=="prepare" && state=="removed" && removedRecorded && !Restoration.Prepared) ||
                (phase=="reconcile" && state=="committed" && restorationPost=="unrecorded") ||
                (phase=="finish" && state=="committed" && restorationPost=="reconciled");
        }
        internal void HelperComplete(Policy policy,string phase) {
            if(Object.ReferenceEquals(policy,Control)) {
                if(phase=="rollback-candidate-removed")removedRecorded=true;
                else if(phase=="rollback-native-committed")commitRecorded=true;
            } else if(Object.ReferenceEquals(policy,Restoration)) {
                if(phase=="reconcile")restorationPost="reconciled";
                else if(phase=="finish")restorationPost="finished";
            }
        }
        public void OwnerLost() {
            state="owner-lost";Control.OwnerLost();Removal.OwnerLost();if(!Legacy)Restoration.OwnerLost();
        }
    }
    public sealed class StagedSettlementProof {
        private readonly NativeProcess retained;
        internal StagedSettlementProof(NativeProcess owner) { retained=owner; }
        internal bool ValidFor(Identity owner) { return retained!=null && retained.Alive && retained.Identity.Same(owner); }
    }
    public sealed class NativeTransaction : IDisposable {
        [StructLayout(LayoutKind.Sequential)] struct FileInformation {
            public uint Attributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME Created,Accessed,Written;
            public uint Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;
        }
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle file,out FileInformation information);
        [DllImport("msi.dll",CharSet=CharSet.Unicode)] static extern uint MsiBeginTransactionW(string name,uint attributes,out uint handle,out IntPtr ownerEvent);
        [DllImport("msi.dll",CharSet=CharSet.Unicode)] static extern uint MsiInstallProductW(string path,string properties);
        [DllImport("msi.dll")] static extern uint MsiEndTransaction(uint state);
        [DllImport("msi.dll")] static extern uint MsiCloseHandle(uint handle);
        [DllImport("msi.dll")] static extern uint MsiSetInternalUI(uint level,IntPtr parent);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr LoadLibraryExW(string path,IntPtr file,uint flags);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] static extern IntPtr GetModuleHandleW(string name);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] static extern uint GetModuleFileNameW(IntPtr module,StringBuilder path,uint size);
        [DllImport("kernel32.dll")] static extern bool FreeLibrary(IntPtr module);
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr handle,uint milliseconds);
        private readonly CompoundPolicy policy;
        private readonly SuccessorRepairPolicy repair;
        private readonly StagedRollbackPolicy reverse;
        private readonly NativeProcess owner;
        private readonly FileStream oldMedia,newMedia;
        private readonly string oldPath,newPath,successor;
        private readonly int ownerThread;
        private IntPtr module,ownerEvent;
        private uint handle,previousUi;
        private bool transactionOpen,disposed,uiChanged;
        private Task<uint> task;
        private string taskKind;
        public bool HasNativeTransaction { get { return transactionOpen; } }
        public Task<uint> PendingTask { get { return task; } }
        private Policy NewPolicy { get { return policy!=null ? policy.NewPackage : repair!=null ? repair.Package : reverse.Restoration ?? reverse.Control; } }
        private Identity OwnerIdentity { get { return NewPolicy.Owner; } }
        private bool AuthorityActive { get { return policy!=null ? policy.OwnerActive : repair!=null ? repair.OwnerActive : reverse.OwnerActive; } }
        private string OldHash { get { return policy!=null ? policy.OldPackage.PackageHash : repair!=null ? repair.OldPackageHash : reverse.Removal.PackageHash; } }
        private string NewHash { get { return reverse!=null ? reverse.Control.ReverseOldHash : NewPolicy.PackageHash; } }
        private void Revoke() { if(policy!=null)policy.OwnerLost();else if(repair!=null)repair.OwnerLost();else reverse.OwnerLost(); }
        private static void Fail() { throw new InvalidOperationException("OWNER_AUTH_FAILED"); }
        private static string MediaPath(FileStream stream,string expectedHash) {
            if(stream==null || !stream.CanRead || stream.CanWrite || stream.Length<=0 || stream.Length>512L*1024*1024) Fail();
            string path=Path.GetFullPath(stream.Name);
            LaunchDirectory.ValidateAncestors(path);
            FileInformation information;
            if(!GetFileInformationByHandle(stream.SafeFileHandle,out information) || information.Links!=1 ||
                (information.Attributes&((uint)FileAttributes.ReparsePoint|(uint)FileAttributes.Directory))!=0) Fail();
            var security=File.GetAccessControl(path,AccessControlSections.Owner|AccessControlSections.Access);
            string ownerSid=security.GetOwner(typeof(SecurityIdentifier)).Value;
            if(ownerSid!="S-1-5-18" && ownerSid!="S-1-5-32-544") Fail();
            var seen=new HashSet<string>();
            foreach(FileSystemAccessRule rule in security.GetAccessRules(true,true,typeof(SecurityIdentifier))) {
                string sid=rule.IdentityReference.Value;
                if((sid!="S-1-5-18" && sid!="S-1-5-32-544") || rule.AccessControlType!=AccessControlType.Allow ||
                    rule.FileSystemRights!=FileSystemRights.FullControl || !seen.Add(sid)) Fail();
            }
            if(seen.Count!=2 || (File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0) Fail();
            long position=stream.Position;
            try {
                stream.Position=0;
                using(var sha=SHA256.Create()) if(Policy.Hex(sha.ComputeHash(stream))!=expectedHash) Fail();
            } finally { stream.Position=position; }
            return path;
        }
        private static bool SystemModule(IntPtr value,string expected) {
            var path=new StringBuilder(32768);
            uint length=GetModuleFileNameW(value,path,(uint)path.Capacity);
            return value!=IntPtr.Zero && length>0 && length<path.Capacity &&
                String.Equals(Path.GetFullPath(path.ToString()),expected,StringComparison.OrdinalIgnoreCase);
        }
        public NativeTransaction(CompoundPolicy compound,NativeProcess retainedOwner,FileStream oldPin,FileStream newPin,string successorProduct)
            : this(compound,null,null,retainedOwner,oldPin,newPin,successorProduct) {}
        public NativeTransaction(SuccessorRepairPolicy successorRepair,NativeProcess retainedOwner,FileStream oldPin,FileStream newPin,string successorProduct)
            : this(null,successorRepair,null,retainedOwner,oldPin,newPin,successorProduct) {}
        public NativeTransaction(StagedRollbackPolicy stagedReverse,NativeProcess retainedOwner,FileStream candidatePin,FileStream originalPin,string originalProduct)
            : this(null,null,stagedReverse,retainedOwner,candidatePin,originalPin,originalProduct) {}
        private NativeTransaction(CompoundPolicy compound,SuccessorRepairPolicy successorRepair,StagedRollbackPolicy stagedReverse,NativeProcess retainedOwner,FileStream oldPin,FileStream newPin,string successorProduct) {
            if((compound==null ? 0 : 1)+(successorRepair==null ? 0 : 1)+(stagedReverse==null ? 0 : 1)!=1) Fail();
            policy=compound;repair=successorRepair;reverse=stagedReverse;
            string state=compound!=null ? compound.State : successorRepair!=null ? successorRepair.State : stagedReverse.State;
            Guid parsed;
            if(retainedOwner==null || !retainedOwner.Alive || !OwnerIdentity.Same(retainedOwner.Identity) ||
                retainedOwner.Identity.Pid!=Process.GetCurrentProcess().Id || !AuthorityActive || state!="prepared" ||
                !Guid.TryParseExact(successorProduct,"B",out parsed) ||
                "{"+parsed.ToString("D").ToUpperInvariant()+"}"!=successorProduct) Fail();
            oldPath=MediaPath(oldPin,OldHash);
            newPath=MediaPath(newPin,NewHash);
            if(String.Equals(oldPath,newPath,StringComparison.OrdinalIgnoreCase)) Fail();
            owner=retainedOwner;successor=successorProduct;
            ownerThread=Thread.CurrentThread.ManagedThreadId;
            string system=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"msi.dll");
            module=LoadLibraryExW(system,IntPtr.Zero,0x800); // LOAD_LIBRARY_SEARCH_SYSTEM32
            try {
                if(!SystemModule(module,system) || !SystemModule(GetModuleHandleW("msi.dll"),system)) Fail();
                // Own the no-write/no-delete pins. A caller's FileShare choice
                // cannot weaken the pathname consumed later by Windows Installer.
                oldMedia=new FileStream(oldPath,FileMode.Open,FileAccess.Read,FileShare.Read);
                newMedia=new FileStream(newPath,FileMode.Open,FileAccess.Read,FileShare.Read);
                MediaPath(oldMedia,OldHash);MediaPath(newMedia,NewHash);
                if(PackageHelper.ProductCode(newPath)!=successor) Fail();
            } catch {
                if(oldMedia!=null) oldMedia.Dispose();if(newMedia!=null) newMedia.Dispose();
                if(module!=IntPtr.Zero) FreeLibrary(module);module=IntPtr.Zero;throw;
            }
        }
        public static StagedSettlementProof EstablishSettlement(NativeProcess retainedOwner) {
            if(retainedOwner==null || !retainedOwner.Alive || retainedOwner.Identity.Pid!=Process.GetCurrentProcess().Id) Fail();
            string system=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"msi.dll");
            IntPtr pin=LoadLibraryExW(system,IntPtr.Zero,0x800),eventHandle=IntPtr.Zero;
            uint transaction=0;bool open=false;
            try {
                if(!SystemModule(pin,system) || !SystemModule(GetModuleHandleW("msi.dll"),system)) Fail();
                uint code=MsiBeginTransactionW("EndpointStagedSettlement-"+Guid.NewGuid().ToString("D"),0,out transaction,out eventHandle);
                if(code!=0 || transaction==0 || eventHandle==IntPtr.Zero) Fail();
                open=true;
                code=MsiEndTransaction(0); // no scripts and no product mutation
                if(code!=0) Fail();
                open=false;
                if(WaitForSingleObject(eventHandle,0)!=0 || !retainedOwner.Alive) Fail();
                return new StagedSettlementProof(retainedOwner);
            } finally {
                if(open)MsiEndTransaction(0);
                if(transaction!=0)MsiCloseHandle(transaction);
                if(eventHandle!=IntPtr.Zero)CloseHandle(eventHandle);
                if(pin!=IntPtr.Zero)FreeLibrary(pin);
            }
        }
        private bool SuccessfulNativeClosure { get { return task!=null &&
            (taskKind=="end" || taskKind=="abort") && task.Status==TaskStatus.RanToCompletion && task.Result==0; } }
        private bool AuthenticatedClosure { get {
            if(taskKind!="end") return false;
            if(reverse!=null)return reverse.State=="ending-commit" && reverse.NativeProofComplete;
            return policy!=null ? policy.State=="ending-commit" && policy.OldPackage.NativeComplete &&
                policy.NewPackage.NativeComplete && policy.OldPackage.AllHelpersComplete && policy.NewPackage.AllHelpersComplete :
                repair.State=="ending-commit" && repair.Package.NativeComplete && repair.Package.AllHelpersComplete;
        } }
        private void CheckPhysicalOwner(bool authority) {
            if(disposed || Thread.CurrentThread.ManagedThreadId!=ownerThread || !owner.Alive ||
                !owner.Identity.Same(OwnerIdentity) || (authority && !AuthorityActive)) Fail();
        }
        private void CheckOwner(bool authority) {
            CheckPhysicalOwner(authority);
            if(transactionOpen && ownerEvent!=IntPtr.Zero) {
                uint signal=WaitForSingleObject(ownerEvent,0);
                if(signal!=258 && !(signal==0 && SuccessfulNativeClosure &&
                    (!authority || AuthenticatedClosure))) Fail();
            }
        }
        // This is permission to wait for the private End result only. It never
        // authorizes a bridge operation, result consumption or publication.
        public bool IsNativeClosurePending() {
            CheckPhysicalOwner(true);
            if(!transactionOpen || ownerEvent==IntPtr.Zero) return false;
            uint signal=WaitForSingleObject(ownerEvent,0);
            if(signal==258) return false;
            if(signal!=0 || task==null || taskKind!="end" || !AuthenticatedClosure) Fail();
            return !task.IsCompleted;
        }
        public void CheckOwnership() { CheckOwner(true); }
        public void PublishCompletion(string upgradeId,string sourceRevision,string readyHash) {
            CheckOwner(true);
            if(reverse!=null || transactionOpen || task!=null || !(policy!=null ? policy.ReadyToPublish : repair.ReadyToPublish)) Fail();
            string root=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"Endpoint Platform","installer-state");
            TerminalPublication.PublishAt(root,upgradeId,NewPolicy.TransactionId,
                OldHash,NewPolicy.PackageHash,successor,sourceRevision,readyHash,CheckOwnership);
        }
        public void BeginNative() {
            CheckOwner(true);
            if(transactionOpen || task!=null || (policy!=null ? policy.State : repair!=null ? repair.State : reverse.State)!="prepared") Fail();
            // Driver-owned pins remain open and unmodified until every native call,
            // delayed custom action and both bridge conversations have settled.
            MediaPath(oldMedia,OldHash);MediaPath(newMedia,NewHash);
            previousUi=MsiSetInternalUI(2,IntPtr.Zero);uiChanged=true;
            uint result=MsiBeginTransactionW("EndpointFoundation-"+NewPolicy.SessionId,0,out handle,out ownerEvent);
            if(result!=0) throw new InvalidOperationException(result==1618 ? "UPDATE_IN_PROGRESS" : "RECOVERY_REQUIRED");
            transactionOpen=true;
            if(policy!=null)policy.BeginNative();else if(repair!=null)repair.BeginNative();else reverse.BeginNative();
        }
        private void Ready() { CheckOwner(true);if(!transactionOpen || task!=null) Fail(); }
        public void StartOldScript() {
            Ready();if(policy==null && reverse==null) Fail();
            if(reverse!=null)reverse.BeginRemovalScript();else policy.BeginOldScript();taskKind="old";
            string properties=reverse!=null ? "REMOVE=ALL ENDPOINT_STAGED_REMOVE=1 REBOOT=ReallySuppress ENDPOINT_INSTALLER_SESSION="+reverse.Removal.SessionId :
                "REMOVE=ALL UPGRADINGPRODUCTCODE="+successor+" REBOOT=ReallySuppress ENDPOINT_INSTALLER_SESSION="+policy.OldPackage.SessionId;
            task=Task.Run(()=>MsiInstallProductW(oldPath,properties));
        }
        public void StartNewScript() {
            Ready();if(policy!=null)policy.BeginNewScript();else if(repair!=null)repair.BeginScript();else reverse.BeginRestorationScript();taskKind="new";
            string properties=(repair!=null ? "REINSTALL=ALL REINSTALLMODE=amus " : "")+
                "ADDLOCAL=EndpointAgentFeature,EndpointAgentInitialRuntimeFeature REBOOT=ReallySuppress"+
                (reverse!=null && reverse.Legacy ? "" : " ENDPOINT_INSTALLER_SESSION="+NewPolicy.SessionId);
            task=Task.Run(()=>MsiInstallProductW(newPath,properties));
        }
        private int Result(string expected,bool authority=true) {
            CheckOwner(authority);
            if(task==null || taskKind!=expected || !task.IsCompleted) Fail();
            var completed=task;task=null;taskKind=null;
            return checked((int)completed.GetAwaiter().GetResult());
        }
        public int CompleteOldScript() { int code=Result("old");if(reverse!=null)reverse.RemovalReturned(code);else policy.OldScriptReturned(code);return code; }
        public int CompleteNewScript() { int code=Result("new");if(policy!=null)policy.NewScriptReturned(code);else if(repair!=null)repair.ScriptReturned(code);else reverse.RestorationReturned(code);return code; }
        public void StartEnd(bool commit) {
            Ready();if(policy!=null)policy.BeginEnd(commit);else if(repair!=null)repair.BeginEnd(commit);else reverse.BeginEnd(commit);taskKind="end";
            task=Task.Run(()=>MsiEndTransaction(commit ? 1u : 0u));
        }
        public int CompleteEnd() {
            if((policy!=null ? policy.State : repair!=null ? repair.State : reverse.State)=="ending-rollback") {
                CheckPhysicalOwner(true);
                int rollback=Result("end",false);if(rollback==0) transactionOpen=false;
                // Match the abort route: consuming native rollback cannot leave
                // bridge authority active, even when the native result is zero.
                Revoke();return rollback;
            }
            int code=Result("end");if(code==0) transactionOpen=false;
            if(policy!=null)policy.EndReturned(code);else if(repair!=null)repair.EndReturned(code);else reverse.EndReturned(code);return code;
        }
        public int DiscardInterruptedCall() {
            CheckOwner(false);
            if(task==null || !task.IsCompleted || (taskKind!="old" && taskKind!="new" && taskKind!="end")) Fail();
            Revoke();string interrupted=taskKind;
            int code=Result(interrupted,false);
            // End may already have committed before channel/owner authority
            // was revoked. Record native closure, never application completion.
            if(interrupted=="end" && code==0) transactionOpen=false;
            return code;
        }
        public void StartAbort() {
            // Revoking bridge authority never revokes the retained owner's
            // ability to request native rollback. This cannot request commit.
            CheckOwner(false);if(!transactionOpen || task!=null) Fail();
            Revoke();taskKind="abort";task=Task.Run(()=>MsiEndTransaction(0));
        }
        public int CompleteAbort() {
            int code=Result("abort",false);if(code==0) transactionOpen=false;
            return code;
        }
        public void Dispose() {
            if(disposed) return;
            if(Thread.CurrentThread.ManagedThreadId!=ownerThread || transactionOpen || task!=null) throw new InvalidOperationException("RECOVERY_REQUIRED");
            if(handle!=0) { MsiCloseHandle(handle);handle=0; }
            if(ownerEvent!=IntPtr.Zero) { CloseHandle(ownerEvent);ownerEvent=IntPtr.Zero; }
            if(uiChanged) { MsiSetInternalUI(previousUi,IntPtr.Zero);uiChanged=false; }
            if(module!=IntPtr.Zero) { FreeLibrary(module);module=IntPtr.Zero; }
            oldMedia.Dispose();newMedia.Dispose();
            disposed=true;
        }
    }
    // No helper/ACK or required directory flush follows the authoritative move.
    // If the controller loses the return, disk evidence remains the authority;
    // the controller reports uncertainty rather than removing/replacing it.
    internal static class TerminalPublication {
        [StructLayout(LayoutKind.Sequential)] struct Information {
            public uint Attributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME Created,Accessed,Written;
            public uint Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;
        }
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle file,out Information value);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool MoveFileExW(string from,string to,uint flags);
        private static readonly string[] readers={"S-1-5-80-1102781572-1373263041-1070489469-7526906-1468061691","S-1-5-80-327494974-20047353-929432329-1920152597-707704661"};
        private static void Fail() { throw new InvalidOperationException("PROVENANCE_CONFLICT"); }
        private static void Id(string value) { Guid parsed;if(!Guid.TryParseExact(value,"D",out parsed) || parsed.ToString("D")!=value) Fail(); }
        private static void Hash(string value,int length) { if(value==null || !Regex.IsMatch(value,"\\A[0-9a-f]{"+length+"}\\z")) Fail(); }
        private static FileSecurity Security() {
            var value=PackageHelper.SecretSecurity();
            foreach(string sid in readers) value.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid),(FileSystemRights)0x1200a9,AccessControlType.Allow));
            return value;
        }
        private static void Validate(string path,bool directory) {
            LaunchDirectory.ValidateAncestors(path);
            var attributes=File.GetAttributes(path);
            if((attributes&FileAttributes.ReparsePoint)!=0 || ((attributes&FileAttributes.Directory)!=0)!=directory) Fail();
            FileSystemSecurity security=directory ? (FileSystemSecurity)Directory.GetAccessControl(path,AccessControlSections.Owner|AccessControlSections.Access) : File.GetAccessControl(path,AccessControlSections.Owner|AccessControlSections.Access);
            string owner=security.GetOwner(typeof(SecurityIdentifier)).Value;
            if(!security.AreAccessRulesProtected || (owner!="S-1-5-18" && owner!="S-1-5-32-544")) Fail();
            var seen=new HashSet<string>();
            foreach(FileSystemAccessRule rule in security.GetAccessRules(true,true,typeof(SecurityIdentifier))) {
                string sid=rule.IdentityReference.Value;
                int rights=(sid=="S-1-5-18" || sid=="S-1-5-32-544") ? (int)FileSystemRights.FullControl : (Array.IndexOf(readers,sid)>=0 ? 0x1200a9 : -1);
                if(rule.AccessControlType!=AccessControlType.Allow || (int)rule.FileSystemRights!=rights || !seen.Add(sid)) Fail();
            }
            if(seen.Count!=4) Fail();
        }
        private static FileStream Pin(string path,byte[] expected) {
            Validate(path,false);
            var file=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read);
            try {
                Information value;
                if(!GetFileInformationByHandle(file.SafeFileHandle,out value) || value.Links!=1 || (value.Attributes&0x410)!=0 || file.Length!=expected.Length) Fail();
                byte[] actual=new byte[expected.Length];int offset=0;
                while(offset<actual.Length) { int count=file.Read(actual,offset,actual.Length-offset);if(count==0) Fail();offset+=count; }
                for(int i=0;i<actual.Length;i++) if(actual[i]!=expected[i]) Fail();
                return file;
            } catch { file.Dispose();throw; }
        }
        internal static void PublishAt(string root,string upgrade,string transaction,string oldHash,string newHash,string product,string source,string readyHash,Action check) {
            Id(upgrade);Id(transaction);Hash(oldHash,64);Hash(newHash,64);Hash(source,40);Hash(readyHash,64);
            Guid code;if(oldHash==newHash || !Guid.TryParseExact(product,"B",out code) || "{"+code.ToString("D").ToUpperInvariant()+"}"!=product) Fail();
            root=Path.GetFullPath(root);
            var volume=new DriveInfo(Path.GetPathRoot(root));
            if(volume.DriveType!=DriveType.Fixed || !String.Equals(volume.DriveFormat,"NTFS",StringComparison.OrdinalIgnoreCase)) Fail();
            string history=Path.Combine(root,"upgrade-history",upgrade);
            Validate(root,true);Validate(Path.Combine(root,"upgrade-history"),true);Validate(history,true);
            string barrier="{\"schema_version\":1,\"upgrade_id\":\""+upgrade+"\",\"new_transaction_id\":\""+transaction+"\",\"old_package_sha256\":\""+oldHash+"\",\"new_package_sha256\":\""+newHash+"\"}";
            string prefix=barrier.Substring(0,barrier.Length-1)+",\"successor_product_code\":\""+product+"\",\"source_revision\":\""+source+"\"";
            byte[] ready=Encoding.ASCII.GetBytes(prefix+",\"phase\":\"ready\"}");
            using(var sha=SHA256.Create()) if(Policy.Hex(sha.ComputeHash(ready))!=readyHash) Fail();
            byte[] marker=Encoding.ASCII.GetBytes(prefix+",\"ready_sha256\":\""+readyHash+"\"}");
            string destination=Path.Combine(history,"complete.json");
            using(var active=Pin(Path.Combine(root,"upgrade.json"),Encoding.ASCII.GetBytes(barrier)))
            using(var archived=Pin(Path.Combine(history,"barrier.json"),Encoding.ASCII.GetBytes(barrier)))
            using(var receipt=Pin(Path.Combine(history,"ready.json"),ready)) {
                // An existing marker is evidence to inspect, never overwrite.
                if(File.Exists(destination)) Fail();
                check();
                string temporary=Path.Combine(history,"complete-"+Guid.NewGuid().ToString("N")+".tmp");
                using(var file=new FileStream(temporary,FileMode.CreateNew,FileSystemRights.Write,FileShare.None,4096,FileOptions.WriteThrough,Security())) {
                    file.Write(marker,0,marker.Length);file.Flush(true);
                    Information value;
                    if(!GetFileInformationByHandle(file.SafeFileHandle,out value) || value.Links!=1 || (value.Attributes&0x410)!=0 || file.Length!=marker.Length) Fail();
                    Validate(temporary,false);
                }
                using(var prepared=Pin(temporary,marker)) { check(); }
                // The fixed, protected same-volume directory prevents an
                // unrelated writer replacing the prepared leaf at this edge.
                check();
                if(!MoveFileExW(temporary,destination,8)) throw new Win32Exception(Marshal.GetLastWin32Error(),"RECOVERY_REQUIRED");
            }
        }
    }
}
'@
}

function Assert-RegularNonReparseFile {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Label)
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or [bool]($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "$Label must be a regular non-reparse file."
    }
}

function ConvertFrom-BridgeHex {
    param([string]$Value, [int]$Maximum = 16384)
    if ($Value.Length -gt $Maximum * 2 -or $Value.Length % 2 -or $Value -cnotmatch '^[0-9a-f]*$') { throw 'OWNER_AUTH_FAILED' }
    $bytes = New-Object byte[] ($Value.Length / 2)
    for ($index = 0; $index -lt $bytes.Length; $index++) { $bytes[$index] = [Convert]::ToByte($Value.Substring($index * 2, 2), 16) }
    return ,$bytes
}

function Send-InstallerBridgePacket {
    param($Bridge, $Value)
    $bytes = [Text.Encoding]::ASCII.GetBytes(($Value | ConvertTo-Json -Depth 10 -Compress))
    $Bridge.Channel.Send($bytes)
}

function New-InstallerConversation {
    param($Bridge,$Launched,[string]$Phase,[bool]$Native)
    return @{Bridge=$Bridge;Launched=$Launched;Phase=$Phase;Native=$Native;Peer=$null;
        Challenge=$null;Payload=$null;Acknowledgement=$null;Completed=$false;CompletedPeer=$null;Result=$null}
}

function Invoke-InstallerConversationStep {
    param([Parameter(Mandatory)]$State)
    $Bridge=$State.Bridge;$launched=$State.Launched;$Phase=$State.Phase;$Msi=$State.Native
    $peer=$State.Peer;$challenge=$State.Challenge;$payload=$State.Payload
    $acknowledgement=$State.Acknowledgement;$completed=$State.Completed;$result=$State.Result
    try {
        if (-not $Bridge.Owner.Alive) { throw 'OWNER_AUTH_FAILED' }
    $packetBytes = $Bridge.Channel.Poll()
    if ($null -ne $packetBytes) {
        if ($null -eq $peer) {
            $peer = [EndpointInstallerBridge.NativeProcess]::new($Bridge.Channel.PeerPid())
            $Bridge.Peers.Add($peer)
            if ($Msi) {
                if (-not $launched.Alive) { throw 'OWNER_AUTH_FAILED' }
            } else {
                if (-not $peer.Identity.Same($launched.Identity) -and -not $peer.DirectChildOf($launched)) { throw 'OWNER_AUTH_FAILED' }
                $Bridge.Policy.RegisterHelper($peer.Identity, $Phase)
            }
        }
        if (($null -eq $acknowledgement -and -not $peer.Alive) -or $Bridge.Channel.PeerPid() -ne $peer.Identity.Pid) { throw 'OWNER_AUTH_FAILED' }
        $packet = [Text.Encoding]::ASCII.GetString($packetBytes) | ConvertFrom-Json
        $keys = @($packet.PSObject.Properties.Name | Sort-Object)
        if ($null -ne $acknowledgement) {
            if ([string]::Join('|', $keys) -ne 'received' -or $packet.received -ne $acknowledgement) { throw 'OWNER_AUTH_FAILED' }
            $Bridge.Channel.Disconnect()
            $acknowledgement = $null
            $completed = $true
            $State.CompletedPeer=$peer.Identity
            $peer = $null
        } elseif ($null -ne $challenge) {
            if ([string]::Join('|', $keys) -ne 'proof') { throw 'OWNER_AUTH_FAILED' }
            if ($Bridge.ContainsKey('NativeDriver')) { $Bridge.NativeDriver.CheckOwnership() }
            $signature = $Bridge.Policy.Accept($peer.Identity, $challenge, [string]$packet.proof)
            if ($Bridge.ContainsKey('NativeDriver')) { $Bridge.NativeDriver.CheckOwnership() }
            Send-InstallerBridgePacket $Bridge @{ sequence = $challenge.Sequence; proof = $signature }
            if ($challenge.Action -eq 'complete') {
                $result = $payload
                $acknowledgement = $challenge.Sequence
            }
            $challenge = $null
        } else {
            if ([string]::Join('|', $keys) -ne 'action|payload|phase|session' -or $packet.session -cne $Bridge.SessionId -or $packet.phase -isnot [string] -or $packet.action -isnot [string] -or $packet.payload -isnot [string]) { throw 'OWNER_AUTH_FAILED' }
            if (-not $Msi -and $packet.phase -cne $Phase) { throw 'OWNER_AUTH_FAILED' }
            $raw = ConvertFrom-BridgeHex -Value $packet.payload -Maximum 8192
            $sha = [Security.Cryptography.SHA256]::Create()
            try { $payloadHash = [EndpointInstallerBridge.Policy]::Hex($sha.ComputeHash($raw)) } finally { $sha.Dispose() }
            $payload = [Text.Encoding]::ASCII.GetString($raw) | ConvertFrom-Json
            if ($Bridge.ContainsKey('NativeDriver')) { $Bridge.NativeDriver.CheckOwnership() }
            $challenge = $Bridge.Policy.Issue($peer.Identity, $packet.phase, $packet.action, $payloadHash, $packet.session)
            Send-InstallerBridgePacket $Bridge @{ sequence = $challenge.Sequence; nonce = $challenge.Nonce; proof = $Bridge.Policy.Sign('owner', $challenge) }
        }
    }
        return $null -ne $packetBytes
    } finally {
        $State.Peer=$peer;$State.Challenge=$challenge;$State.Payload=$payload
        $State.Acknowledgement=$acknowledgement;$State.Completed=$completed;$State.Result=$result
    }
}

function Assert-InstallerPumpDeadline {
    param([Parameter(Mandatory)][TimeSpan]$Elapsed,
        [Parameter(Mandatory)][string]$Phase, [Parameter(Mandatory)][bool]$Msi)
    # Full retained catalogs require a fresh owner grant at every mutation.
    # Preparation captures the full archive and repeatedly proves the live legacy
    # owner before and after ZIP ACL hardening; it needs a four-hour window.
    # Rehydration retains two hours. Native MSI and other helpers retain thirty
    # minutes; every phase still pumps the same live owner conversation.
    $minutes = if (-not $Msi -and $Phase -ceq 'prepare') { 240 } elseif (-not $Msi -and $Phase -ceq 'reconcile') { 120 } else { 30 }
    if ($Elapsed -gt [TimeSpan]::FromMinutes($minutes)) { throw 'RECOVERY_REQUIRED' }
}

function Invoke-InstallerOwnerPump {
    param([Parameter(Mandatory)]$Bridge, [Parameter(Mandatory)]$Process,
        [Parameter(Mandatory)][string]$Phase, [switch]$Msi)
    $launched = [EndpointInstallerBridge.NativeProcess]::new($Process.Id)
    $peer = $null
    $challenge = $null
    $payload = $null
    $acknowledgement = $null
    $completed = $false
    $result = $null
    $conversation = New-InstallerConversation $Bridge $launched $Phase ([bool]$Msi)
    $timer = [Diagnostics.Stopwatch]::StartNew()
    if ($Msi) {
        $canonicalMsi = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::System)) 'msiexec.exe'
        if ($launched.ImagePath -ine $canonicalMsi) { $launched.Dispose(); throw 'OWNER_AUTH_FAILED' }
        $Bridge.Policy.RegisterMsi($launched.Identity, $Bridge.Operation)
    } elseif ($launched.Identity.Hash -cne $Bridge.HelperHash) {
        $launched.Dispose(); throw 'OWNER_AUTH_FAILED'
    }
    try {
        do {
            Assert-InstallerPumpDeadline -Elapsed $timer.Elapsed -Phase $Phase -Msi ([bool]$Msi)
            if ($Bridge.ContainsKey('StagedDeadline') -and (Get-StagedMonotonicSeconds) -ge $Bridge.StagedDeadline) { throw 'STAGED_TRIAL_FAILED' }
            $worked = Invoke-InstallerConversationStep -State $conversation
            $Process.Refresh()
            if ($Process.HasExited) {
                $activePeers = @($Bridge.Peers | Where-Object { $_.Alive })
                if ($activePeers.Count -eq 0 -and $null -eq $conversation.Acknowledgement -and $null -eq $conversation.Challenge) { break }
            }
            if (-not $worked) { $Bridge.Channel.WaitForActivity(10) }
        } while ($true)
        if ($Msi) {
            $Bridge.Policy.MarkMsiExited($Process.ExitCode)
            if ($Process.ExitCode -eq 1618) { throw 'UPDATE_IN_PROGRESS' }
            if ($Process.ExitCode -notin @(0,3010,1641) -or -not $Bridge.Policy.NativeComplete -or -not $Bridge.Policy.AllHelpersComplete) { throw 'RECOVERY_REQUIRED' }
        } elseif ($Process.ExitCode -eq 61) {
            throw 'UPDATE_IN_PROGRESS'
        } elseif ($Process.ExitCode -eq 62) {
            throw 'UPDATE_STATE_INVALID'
        } elseif ($Process.ExitCode -eq 63) {
            throw 'PROVENANCE_CONFLICT'
        } elseif ($Process.ExitCode -ne 0 -or -not $conversation.Completed -or -not $Bridge.Policy.AllHelpersComplete) {
            throw 'RECOVERY_REQUIRED'
        }
        if (-not $Msi) { $Bridge.Policy.MarkHelperExited($conversation.CompletedPeer,0) }
        return $conversation.Result
    } catch {
        $Bridge.Policy.OwnerLost()
        throw
    } finally {
        $launched.Dispose()
    }
}

function Assert-InstallerWarmLaunchReply {
    param($Broker,$Bridge,$Packet,$Candidate)
    if (-not $Broker.Owner.Alive -or -not $Broker.Peer.Alive -or -not $Bridge.Owner.Alive -or
        [string]::Join('|',@($Packet.PSObject.Properties.Name|Sort-Object)) -cne 'created|pid|sequence' -or
        ($Packet.pid -isnot [int] -and $Packet.pid -isnot [long]) -or
        ($Packet.created -isnot [long] -and $Packet.created -isnot [int]) -or
        ($Packet.sequence -isnot [int] -and $Packet.sequence -isnot [long]) -or
        $Packet.sequence -ne $Broker.Sequence -or $Packet.pid -le 0 -or $Packet.pid -gt [int]::MaxValue -or
        $Packet.created -le 0 -or -not $Candidate.Alive -or
        $Candidate.Identity.Pid -ne $Packet.pid -or $Candidate.Identity.Created -ne $Packet.created -or
        $Candidate.Identity.Hash -cne $Broker.HelperHash -or $Candidate.ImagePath -ine $Broker.HelperPath -or
        $Candidate.Identity.Sid -cne $Bridge.Owner.Identity.Sid -or -not $Candidate.Identity.Elevated -or
        -not $Candidate.DirectChildOf($Broker.Peer)) { throw 'OWNER_AUTH_FAILED' }
}

function Receive-InstallerLaunchPacket {
    param($Broker)
    $timer=[Diagnostics.Stopwatch]::StartNew()
    do {
        if ($timer.Elapsed.TotalSeconds -gt 30 -or -not $Broker.Owner.Alive -or -not $Broker.Launched.Alive) { throw 'OWNER_AUTH_FAILED' }
        $raw=$Broker.Channel.Poll()
        if ($null -ne $raw) {
            if ($null -eq $Broker.Peer) {
                $Broker.Peer=[EndpointInstallerBridge.NativeProcess]::new($Broker.Channel.PeerPid())
                if (($Broker.Peer.Identity.Same($Broker.Launched.Identity) -eq $false -and
                     -not $Broker.Peer.DirectChildOf($Broker.Launched)) -or
                    $Broker.Peer.Identity.Hash -cne $Broker.HelperHash -or
                    $Broker.Peer.ImagePath -ine $Broker.HelperPath -or
                    $Broker.Peer.Identity.Sid -cne $Broker.Owner.Identity.Sid -or
                    -not $Broker.Peer.Identity.Elevated) { throw 'OWNER_AUTH_FAILED' }
            }
            if (-not $Broker.Peer.Alive -or $Broker.Channel.PeerPid() -ne $Broker.Peer.Identity.Pid) { throw 'OWNER_AUTH_FAILED' }
            return ([Text.Encoding]::ASCII.GetString($raw)|ConvertFrom-Json)
        }
        $Broker.Channel.WaitForActivity(10)
    } while ($true)
}

function Start-InstallerLaunchBroker {
    param($Bridge)
    Assert-ExistingPathChain $Bridge.LaunchDirectory
    Assert-InstallerCacheProtection $Bridge.LaunchDirectory
    $nonce=[Guid]::NewGuid().ToString('N')
    $channel=[EndpointInstallerBridge.Channel]::new('EndpointInstaller-'+$Bridge.SessionId+'-'+$nonce)
    $broker=@{Channel=$channel;Peer=$null;Process=$null;Launched=$null;Owner=$null;
        HelperPath=$Bridge.HelperPath;HelperHash=$Bridge.HelperHash;LaunchDirectory=$Bridge.LaunchDirectory;
        TransactionId=$Bridge.TransactionId;Sequence=0}
    try {
        $broker.Owner=[EndpointInstallerBridge.NativeProcess]::new($PID)
        if (-not $broker.Owner.Identity.Same($Bridge.Owner.Identity)) { throw 'OWNER_AUTH_FAILED' }
        $info=[EndpointInstallerBridge.LaunchDirectory]::StartInfo($Bridge.HelperPath,
            ('--installer-launcher '+$Bridge.SessionId+' --installer-launch-nonce '+$nonce),$Bridge.LaunchDirectory)
        $broker.Process=[Diagnostics.Process]::Start($info)
        $retainedHandle=$broker.Process.Handle
        $broker.Launched=[EndpointInstallerBridge.NativeProcess]::new($broker.Process.Id)
        if ($broker.Launched.Identity.Hash -cne $broker.HelperHash -or
            $broker.Launched.ImagePath -ine $broker.HelperPath) { throw 'OWNER_AUTH_FAILED' }
        $ready=Receive-InstallerLaunchPacket $broker
        if ([string]::Join('|',@($ready.PSObject.Properties.Name)) -cne 'ready' -or
            $ready.ready -isnot [bool] -or -not $ready.ready) { throw 'OWNER_AUTH_FAILED' }
        return $broker
    } catch {
        Stop-InstallerLaunchBroker $broker
        throw
    }
}

function Start-InstallerWarmPhase {
    param($Broker,$Bridge,[string]$Phase)
    if ($Broker.Sequence -ge 511 -or -not $Broker.Owner.Identity.Same($Bridge.Owner.Identity) -or
        $Bridge.TransactionId -cne $Broker.TransactionId -or $Bridge.HelperHash -cne $Broker.HelperHash -or
        $Bridge.HelperPath -ine $Broker.HelperPath) { throw 'OWNER_AUTH_FAILED' }
    Assert-ExistingPathChain $Broker.LaunchDirectory
    Assert-InstallerCacheProtection $Broker.LaunchDirectory
    if ($Bridge.ContainsKey('NativeDriver')) { $Bridge.NativeDriver.CheckOwnership() }
    $Broker.Sequence++
    Send-InstallerBridgePacket $Broker @{sequence=$Broker.Sequence;action='launch';phase=$Phase;session=$Bridge.SessionId}
    $packet=Receive-InstallerLaunchPacket $Broker
    if ($packet.pid -isnot [int] -or $packet.pid -le 0) { throw 'OWNER_AUTH_FAILED' }
    $candidate=[EndpointInstallerBridge.NativeProcess]::new([int]$packet.pid)
    try {
        Assert-InstallerWarmLaunchReply $Broker $Bridge $packet $candidate
        if ($Bridge.ContainsKey('NativeDriver')) { $Bridge.NativeDriver.CheckOwnership() }
        $process=[Diagnostics.Process]::GetProcessById([int]$packet.pid)
        $retainedHandle=$process.Handle
        if ($process.HasExited -or -not $candidate.Alive -or
            $process.StartTime.ToUniversalTime().ToFileTimeUtc() -ne $packet.created) { $process.Dispose();throw 'OWNER_AUTH_FAILED' }
        return $process
    } finally { $candidate.Dispose() }
}

function Stop-InstallerLaunchPeer {
    param($Broker)
    if ($null -eq $Broker.Peer -or -not $Broker.Peer.Alive -or
        $Broker.Peer.Identity.Hash -cne $Broker.HelperHash -or $Broker.Peer.ImagePath -ine $Broker.HelperPath) { return }
    $inner=[Diagnostics.Process]::GetProcessById($Broker.Peer.Identity.Pid)
    try {
        $retainedInnerHandle=$inner.Handle
        if ($Broker.Peer.Alive -and $inner.StartTime.ToUniversalTime().ToFileTimeUtc() -eq $Broker.Peer.Identity.Created) {
            $inner.Kill();$inner.WaitForExit(5000)|Out-Null
        }
    } finally { $inner.Dispose() }
}

function Stop-InstallerLaunchBroker {
    param($Broker)
    if ($null -eq $Broker) { return }
    try {
        if ($null -ne $Broker.Peer -and $Broker.Peer.Alive -and $Broker.Owner.Alive -and $Broker.Launched.Alive) {
            $Broker.Sequence++
            Send-InstallerBridgePacket $Broker @{sequence=$Broker.Sequence;action='close'}
            $closed=Receive-InstallerLaunchPacket $Broker
            if ($closed.sequence -ne $Broker.Sequence -or $closed.closed -ne $true) { throw 'OWNER_AUTH_FAILED' }
        }
    } catch { } finally {
        $Broker.Channel.Dispose()
        if ($null -ne $Broker.Process) {
            if (-not $Broker.Process.WaitForExit(5000)) {
                Stop-InstallerLaunchPeer $Broker
                if (-not $Broker.Process.WaitForExit(5000) -and $null -ne $Broker.Launched -and $Broker.Launched.Alive -and
                    $Broker.Launched.Identity.Hash -ceq $Broker.HelperHash) {
                    $Broker.Process.Kill();$Broker.Process.WaitForExit(5000)|Out-Null
                }
            }
            $Broker.Process.Dispose()
        }
        foreach ($item in @($Broker.Peer,$Broker.Launched,$Broker.Owner)) { if ($null -ne $item) { $item.Dispose() } }
    }
}

function Invoke-InstallerHelper {
    param([Parameter(Mandatory)]$Bridge,[Parameter(Mandatory)][string]$Phase)
    if ($Phase -notin @('inspect','inspect-compound','prepare','stage-online','seal-staged-switch','adopt-staged-switch','begin-staged-trial','observe-staged-trial','accept-staged-trial','inspect-staged-state','prepare-foundation-rollback','bind-foundation-rollback-roles','rollback-candidate-removed','rollback-native-committed','verify-foundation-rollback','restore-staged-companions','inspect-staged-recovery','recover-staged-owner','record-staged-reboot-3010','record-staged-reboot-1641','reconcile','finish','verify-settled','compound-old-returned','compound-new-returned','compound-commit','compound-retire','compound-complete','compound-repair-returned','compound-repair-commit') -or $Bridge.SessionId -cnotmatch '^[0-9a-f-]{36}$') { throw 'OWNER_AUTH_FAILED' }
    $phaseTimer=[Diagnostics.Stopwatch]::StartNew()
    $phaseStarted=[DateTime]::UtcNow.ToString('o')
    $launchSeconds=$null;$warmLaunch=$false;$phaseSucceeded=$false
    try {
    Assert-ExistingPathChain $Bridge.LaunchDirectory
    Assert-InstallerCacheProtection $Bridge.LaunchDirectory
    if ($null -ne $script:InstallerLaunchBroker -and $Bridge.HelperHash -ceq $script:InstallerLaunchBroker.HelperHash -and
        $Bridge.HelperPath -ieq $script:InstallerLaunchBroker.HelperPath -and $Bridge.TransactionId -ceq $script:InstallerLaunchBroker.TransactionId) {
        $warmLaunch=$true
        $process=Start-InstallerWarmPhase $script:InstallerLaunchBroker $Bridge $Phase
    } else {
        $info = [EndpointInstallerBridge.LaunchDirectory]::StartInfo($Bridge.HelperPath, ('--installer-phase ' + $Phase + ' --installer-session ' + $Bridge.SessionId), $Bridge.LaunchDirectory)
        $process = [Diagnostics.Process]::Start($info)
    }
    $launchSeconds=$phaseTimer.Elapsed.TotalSeconds
    $phaseResult=Invoke-InstallerOwnerPump -Bridge $Bridge -Process $process -Phase $Phase
    $phaseSucceeded=$true
    return $phaseResult
    } finally {
        # Diagnostics carry no authority or private paths. In-memory collection
        # adds no file writes or grants to a measured phase.
        if (Get-Variable -Name InstallerPhaseMetrics -Scope Script -ErrorAction SilentlyContinue) {
            $script:InstallerPhaseMetrics.Add(@{phase=$Phase;warm=$warmLaunch;started_utc=$phaseStarted;
                launch_seconds=$launchSeconds;total_seconds=$phaseTimer.Elapsed.TotalSeconds;success=$phaseSucceeded})
        }
    }
}

function Get-StagedAgentObservation {
    $service=Get-CimInstance -ClassName Win32_Service -Filter "Name='EndpointAgent'" -ErrorAction Stop
    if ($null -eq $service -or $service.State -cne 'Running' -or $service.ProcessId -le 0) { throw 'UPDATE_IN_PROGRESS' }
    $process=Get-Process -Id $service.ProcessId -ErrorAction Stop
    try { return ([string]$service.ProcessId+':'+[string]$process.StartTime.ToUniversalTime().Ticks) }
    finally { $process.Dispose() }
}

function Get-StagedMonotonicSeconds {
    return [double][Diagnostics.Stopwatch]::GetTimestamp()/[Diagnostics.Stopwatch]::Frequency
}

function Assert-StagedCandidateRunning {
    param([Parameter(Mandatory)]$Observation,[Parameter(Mandatory)][string]$InstallRoot)
    $service=Get-Service -Name 'EndpointAgent' -ErrorAction Stop
    if ($service.Status -ne [ServiceProcess.ServiceControllerStatus]::Running) { throw 'STAGED_TRIAL_FAILED' }
    if ($null -ne $Observation.pid) {
        if ($Observation.pid -le 0 -or $Observation.pid -gt [int]::MaxValue -or
            $Observation.candidate_version -cnotmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$') { throw 'OWNER_AUTH_FAILED' }
        $process=[EndpointInstallerBridge.NativeProcess]::new([int]$Observation.pid)
        try {
            $expected=Join-Path $InstallRoot ('versions\'+$Observation.candidate_version+'\pc_agent.exe')
            if (-not $process.Alive -or $process.ImagePath -ine $expected) { throw 'STAGED_TRIAL_FAILED' }
        } finally { $process.Dispose() }
    }
}

function Invoke-StagedHealthTrial {
    param([Parameter(Mandatory)]$Bridge,[Parameter(Mandatory)][string]$InstallRoot)
    $started=Get-StagedMonotonicSeconds
    $Bridge.StagedDeadline=$started+180
    try {
        $begun=Invoke-InstallerHelper -Bridge $Bridge -Phase 'begin-staged-trial'
        if ($begun.result -cne 'staged-trial' -or $begun.operation_id -cne $Bridge.TransactionId -or
            $begun.attempt_id -cnotmatch '^[0-9a-f-]{36}$') { throw 'OWNER_AUTH_FAILED' }
        Start-VerifiedTrialServices
        $nonce=$null;$stableSince=0
        do {
            $now=Get-StagedMonotonicSeconds
            if ($now-$started -ge 180) { return 'rollback' }
            $observed=Invoke-InstallerHelper -Bridge $Bridge -Phase 'observe-staged-trial'
            if ($observed.operation_id -cne $Bridge.TransactionId -or $observed.attempt_id -cne $begun.attempt_id -or
                $observed.decision -notin @('waiting','accept','rollback')) { throw 'OWNER_AUTH_FAILED' }
            if ($observed.decision -ceq 'rollback') { return 'rollback' }
            Assert-StagedCandidateRunning -Observation $observed -InstallRoot $InstallRoot
            $now=Get-StagedMonotonicSeconds
            if ($now-$started -ge 180) { return 'rollback' }
            if ($null -ne $observed.connection_nonce) {
                if ($observed.connection_nonce -cnotmatch '^[0-9a-f-]{36}$') { throw 'OWNER_AUTH_FAILED' }
                if ($nonce -cne $observed.connection_nonce) { $nonce=$observed.connection_nonce;$stableSince=$now }
                if ($observed.decision -ceq 'accept' -and $now-$stableSince -ge 60) {
                    $accepted=Invoke-InstallerHelper -Bridge $Bridge -Phase 'accept-staged-trial'
                    if ($accepted.result -cne 'staged-accepted' -or $accepted.operation_id -cne $Bridge.TransactionId -or
                        $accepted.attempt_id -cne $begun.attempt_id) { throw 'OWNER_AUTH_FAILED' }
                    return 'accepted'
                }
            } else { $nonce=$null;$stableSince=0 }
            Start-Sleep -Seconds 3
        } while ($true)
    } catch { return 'rollback' }
}

function Get-StagedRollbackMedia {
    param([Parameter(Mandatory)]$Item,[Parameter(Mandatory)][string]$StateRoot,
        [Parameter(Mandatory)][string]$CacheRoot)
    $relative=[string]$Item.relative_path
    $digest=[string]$Item.release.package_sha256
    if ($digest -cnotmatch '^[0-9a-f]{64}$' -or
        $relative -cnotmatch '^(packages/[0-9a-f]{64}/EndpointAgent\.msi|retained/[0-9a-f]{64}/package\.msi)$') { throw 'PROVENANCE_CONFLICT' }
    $original=Join-Path $StateRoot $relative.Replace('/','\')
    Assert-InstallerPublicStateAcl $original
    $sourcePin=[IO.File]::Open($original,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        $sha=[Security.Cryptography.SHA256]::Create()
        try { if ([EndpointInstallerBridge.Policy]::Hex($sha.ComputeHash($sourcePin)) -cne $digest) { throw 'PROVENANCE_CONFLICT' } }
        finally { $sha.Dispose() }
        $signature=Get-AuthenticodeSignature -LiteralPath $original
        if ($signature.Status.ToString() -cne 'Valid') { throw 'SIGNED_ROLLBACK_MEDIA_REQUIRED' }
        $directory=Join-Path $CacheRoot ('msi-'+$digest)
        if (-not (Test-Path -LiteralPath $directory)) { New-ProtectedDirectory $directory }
        Assert-InstallerCacheProtection $directory
        $path=Join-Path $directory 'EndpointAgent.msi'
        if (-not (Test-Path -LiteralPath $path)) {
            [EndpointInstallerBridge.PackageHelper]::CopyCacheArtifact($original,$path)
            Set-CacheArtifactProtection $path
        }
        Assert-CacheArtifactProtection $path
        if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $digest) { throw 'PROVENANCE_CONFLICT' }
        return $path
    } finally { $sourcePin.Dispose() }
}

function New-StagedRollbackNativeDriver {
    param($Control,$Removal,$Restoration,$CandidateMedia,$OriginalMedia,[string]$OriginalProduct)
    $restorationPolicy=if($null -eq $Restoration){$null}else{$Restoration.Policy}
    $policy=[EndpointInstallerBridge.StagedRollbackPolicy]::new($Control.Policy,$Removal.Policy,$restorationPolicy)
    return [EndpointInstallerBridge.NativeTransaction]::new($policy,$Control.Owner,$CandidateMedia,$OriginalMedia,$OriginalProduct)
}

function Assert-StagedRollbackPostconditions {
    param([Parameter(Mandatory)]$Control)
    $verified=Invoke-InstallerHelper -Bridge $Control -Phase 'verify-foundation-rollback'
    if ($verified.result -cne 'rolled-back' -or $verified.operation_id -cne $Control.TransactionId) { throw 'RECOVERY_REQUIRED' }
}

function Invoke-StagedFoundationRollback {
    param($Manifest,[string]$HelperPath,[string]$HelperHash,[string]$StateRoot,[string]$CacheRoot,
        [hashtable]$ServiceStates,$Selection,$CandidateMedia,[string]$OperationId,[string]$InstallRoot)
    $bridges=[Collections.Generic.List[object]]::new()
    $driver=$null;$originalPin=$null;$originalHelperPin=$null
    $control=$null;$removal=$null;$restoration=$null
    $legacy=$Selection.foundation_release.package_sha256 -ceq '2f7d778799f1e32645af7936dfaf3f090d6ad4df5bb883827ea8a0a5d859f72a'
    $metadata=@{role='control';operation_id=$OperationId;removal_session_id=[Guid]::NewGuid().ToString('D');
        restoration_session_id=$(if($legacy){$null}else{[Guid]::NewGuid().ToString('D')})}
    try {
        $control=New-InstallerBridge -Manifest $Manifest -HelperPath $HelperPath -HelperHash $HelperHash -StateRoot $StateRoot -ServiceStates $ServiceStates -Intent 'install' -TransactionId $OperationId -StagedRollback $metadata
        $bridges.Add($control)
        $observed=Invoke-InstallerHelper -Bridge $control -Phase 'inspect-staged-state'
        if ($observed.operation_id -cne $OperationId) { throw 'OWNER_AUTH_FAILED' }
        if ($observed.phase -ceq 'accepted') { return 'accepted' }
        if ($observed.phase -ceq 'rolled-back') { return 'rolled-back' }
        if ($observed.phase -notin @('switching','native-settled','trial')) { throw 'RECOVERY_REQUIRED' }
        $stopped=@{}
        Stop-ManagedAgentServices -PreviousStates (Get-ManagedAgentServiceStates) -StoppedBySetup $stopped
        $control.Policy.MarkQuiescent()
        $prepared=Invoke-InstallerHelper -Bridge $control -Phase 'prepare-foundation-rollback'
        if ($prepared.result -cne 'rollback-prepared' -or $prepared.operation_id -cne $OperationId -or
            $prepared.plan.operation_id -cne $OperationId -or $prepared.plan_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            $prepared.plan.new.release.package_sha256 -cne $Manifest.package_sha256 -or
            $prepared.plan.old.release.package_sha256 -cne $Selection.foundation_release.package_sha256 -or
            $legacy -ne ($null -eq $prepared.plan.old.helper_sha256)) { throw 'OWNER_AUTH_FAILED' }
        $originalPath=Get-StagedRollbackMedia -Item $prepared.plan.old -StateRoot $StateRoot -CacheRoot $CacheRoot
        $originalPin=[IO.File]::Open($originalPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        if (-not $legacy) {
            $originalHelper=Join-Path (Split-Path $originalPath -Parent) 'endpoint-installer-host.exe'
            $originalHash=[EndpointInstallerBridge.PackageHelper]::Extract($originalPath,$originalHelper)
            Assert-CacheArtifactProtection $originalHelper
            if ($originalHash -cne $prepared.plan.old.helper_sha256) { throw 'PROVENANCE_CONFLICT' }
            $originalHelperPin=[IO.File]::Open($originalHelper,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
            $restoration=New-InstallerBridge -Manifest $prepared.plan.old.release -HelperPath $originalHelper -HelperHash $originalHash -StateRoot $StateRoot -ServiceStates $ServiceStates -Intent 'install' -BoundSessionId $metadata.restoration_session_id -Selection $prepared.restoration_selection
            $restoration.Policy.MarkQuiescent()
            $bridges.Add($restoration)
        }
        $removal=New-InstallerBridge -Manifest $Manifest -HelperPath $HelperPath -HelperHash $HelperHash -StateRoot $StateRoot -ServiceStates $ServiceStates -Intent 'uninstall' -Selection $observed -BoundSessionId $metadata.removal_session_id -StagedRollback @{role='remove';operation_id=$OperationId;control_session_id=$control.SessionId}
        $removal.Policy.MarkQuiescent();$bridges.Add($removal)
        $bound=Invoke-InstallerHelper -Bridge $control -Phase 'bind-foundation-rollback-roles'
        if ($bound.result -cne 'rollback-roles-bound' -or $bound.operation_id -cne $OperationId -or
            $bound.plan_sha256 -cne $prepared.plan_sha256) { throw 'OWNER_AUTH_FAILED' }
        $control.Policy.AuthorizeStagedReversePlan($prepared.plan_sha256,$prepared.plan.old.release.package_sha256,$prepared.plan.old.helper_sha256)
        Invoke-InstallerHelper -Bridge $removal -Phase 'prepare' | Out-Null
        $driver=New-StagedRollbackNativeDriver $control $removal $restoration $CandidateMedia $originalPin $prepared.plan.old.release.product_code
        foreach($bridge in $bridges){$bridge.NativeDriver=$driver}
        $nativeBridges=@($removal)
        if($null -ne $restoration){$nativeBridges+=@($restoration)}
        $conversations=@(foreach($bridge in $nativeBridges){New-InstallerConversation $bridge $bridge.Owner 'native' $true})
        Start-WindowsInstaller
        $driver.BeginNative()
        $driver.StartOldScript()
        Invoke-CompoundNativePump $driver $conversations -Channels $nativeBridges.Count
        if($driver.CompleteOldScript() -ne 0){throw 'RECOVERY_REQUIRED'}
        $removed=Invoke-InstallerHelper -Bridge $control -Phase 'rollback-candidate-removed'
        if($removed.result -cne 'rollback-candidate-removed' -or $removed.operation_id -cne $OperationId){throw 'RECOVERY_REQUIRED'}
        if($null -ne $restoration){Invoke-InstallerHelper -Bridge $restoration -Phase 'prepare' | Out-Null}
        $driver.StartNewScript()
        Invoke-CompoundNativePump $driver $conversations -Channels $nativeBridges.Count
        if($driver.CompleteNewScript() -ne 0){throw 'RECOVERY_REQUIRED'}
        $driver.StartEnd($true)
        Invoke-CompoundNativePump $driver $conversations -Channels $nativeBridges.Count
        if($driver.CompleteEnd() -ne 0){throw 'RECOVERY_REQUIRED'}
        if($legacy){
            # Genuine79 has native ServiceControl install-start events and no
            # modern helper callback. Stop those original services after actual
            # End(Commit), before restoring selectors and publishing proof.
            $legacyStopped=@{}
            Stop-ManagedAgentServices -PreviousStates (Get-ManagedAgentServiceStates) -StoppedBySetup $legacyStopped
        }
        if($null -ne $restoration){
            Invoke-InstallerHelper -Bridge $restoration -Phase 'reconcile' | Out-Null
            Invoke-InstallerHelper -Bridge $restoration -Phase 'finish' | Out-Null
        }
        $committed=Invoke-InstallerHelper -Bridge $control -Phase 'rollback-native-committed'
        if($committed.result -cne 'rollback-native-committed' -or $committed.operation_id -cne $OperationId){throw 'RECOVERY_REQUIRED'}
        Assert-StagedRollbackPostconditions -Control $control
        if($ServiceStates['EndpointBrowserPolicy'] -ceq 'Running'){Start-VerifiedBrowserPolicy}
        Start-ManagedEndpointAgent
        return 'rolled-back'
    } catch {
        foreach($bridge in $bridges){$bridge.Policy.OwnerLost();$bridge.Channel.Dispose()}
        if($null -ne $driver){
            try {
                $timer=[Diagnostics.Stopwatch]::StartNew()
                while($null -ne $driver.PendingTask -and -not $driver.PendingTask.IsCompleted){
                    if($timer.Elapsed.TotalMinutes -gt 30){throw 'RECOVERY_REQUIRED'}
                    Start-Sleep -Milliseconds 20
                }
                if($null -ne $driver.PendingTask){$driver.DiscardInterruptedCall()|Out-Null}
                if($driver.HasNativeTransaction){
                    $driver.StartAbort()
                    while(-not $driver.PendingTask.IsCompleted){
                        if($timer.Elapsed.TotalMinutes -gt 30){throw 'RECOVERY_REQUIRED'}
                        Start-Sleep -Milliseconds 20
                    }
                    if($driver.CompleteAbort() -ne 0){throw 'RECOVERY_REQUIRED'}
                }
            } catch { Write-Warning 'RECOVERY_REQUIRED: reverse native settlement unavailable' }
        }
        throw
    } finally {
        foreach($bridge in $bridges){[void]$bridge.Remove('NativeDriver')}
        if($null -ne $driver){
            if($driver.HasNativeTransaction -or $null -ne $driver.PendingTask){Write-Warning 'RECOVERY_REQUIRED: reverse native ownership remains unsettled'}
            else{$driver.Dispose()}
        }
        foreach($bridge in $bridges){
            $bridge.Policy.OwnerLost();$bridge.Channel.Dispose()
            foreach($peer in $bridge.Peers){$peer.Dispose()}
            $bridge.Owner.Dispose()
        }
        if($null -ne $originalHelperPin){$originalHelperPin.Dispose()}
        if($null -ne $originalPin){$originalPin.Dispose()}
    }
}

function New-StagedRecoverySettings {
    # A verified terminal operation can outlive transient service/session or
    # metadata observation failures. Each restart repeats native admission and
    # fresh owner authentication; the captured task XML binds these limits.
    return New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::FromMinutes(250)) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval ([TimeSpan]::FromMinutes(1))
}

function Register-StagedRecoveryTask {
    param($Bridge,[string]$SetupImage,[string]$WrapperPath,[string]$ManifestPath,[string]$CacheRoot,[string]$StateRoot,$ServiceStates)
    if([string]::IsNullOrWhiteSpace($SetupImage)){throw 'RECOVERY_REQUIRED'}
    Assert-RegularNonReparseFile -Path $SetupImage -Label 'Setup'
    Assert-ExistingPathChain $SetupImage
    if((Get-AuthenticodeSignature -LiteralPath $SetupImage).Status -ne 'Valid'){throw 'RECOVERY_REQUIRED'}
    $directory=Join-Path $CacheRoot ('msi-'+$Bridge.Capability.package.package_sha256)
    Assert-InstallerCacheProtection $directory
    $sources=@{'EndpointAgentSetup.exe'=$SetupImage;'EndpointAgent.release.json'=$ManifestPath;'Install-EndpointAgentCanary.ps1'=$WrapperPath}
    foreach($name in $sources.Keys){
        $source=$sources[$name];$destination=Join-Path $directory $name
        Assert-RegularNonReparseFile -Path $source -Label 'Recovery input'
        $digest=(Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
        if(Test-Path -LiteralPath $destination){
            Assert-CacheArtifactProtection $destination
            if((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash -cne $digest){throw 'PROVENANCE_CONFLICT'}
        }else{[EndpointInstallerBridge.PackageHelper]::CopyCacheArtifact($source,$destination);Set-CacheArtifactProtection $destination}
        if((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash -cne $digest){throw 'PROVENANCE_CONFLICT'}
    }
    $files=@{}
    foreach($name in @('EndpointAgentSetup.exe','EndpointAgent.msi','EndpointAgent.release.json','Install-EndpointAgentCanary.ps1')){
        $files[$name]=(Get-FileHash -LiteralPath (Join-Path $directory $name) -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $root=Join-Path $StateRoot 'staged-recovery'
    New-InstallerPublicStateRoot $root
    $root=Join-Path $root $Bridge.TransactionId
    New-InstallerPublicStateRoot $root
    $inputs=@{schema_version=1;operation_id=$Bridge.TransactionId;owner=$Bridge.Capability.owner;
        package_sha256=$Bridge.Capability.package.package_sha256;files=$files;service_states=$ServiceStates;task_sha256=$null;boot=[string](Get-WmiObject Win32_OperatingSystem).LastBootUpTime}
    $leaf=Join-Path $root 'inputs.json'
    if(Test-Path -LiteralPath $leaf){throw 'PROVENANCE_CONFLICT'}
    $executable=Join-Path $directory 'EndpointAgentSetup.exe'
    $name='EndpointStagedRecovery-'+$Bridge.TransactionId
    if(Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue){throw 'PROVENANCE_CONFLICT'}
    $action=New-ScheduledTaskAction -Execute $executable -Argument ('--recover-staged-update '+$Bridge.TransactionId)
    $trigger=New-ScheduledTaskTrigger -AtStartup
    $principal=New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
    $settings=New-StagedRecoverySettings
    Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null
    $scheduler=New-Object -ComObject Schedule.Service;$scheduler.Connect()
    $task=$scheduler.GetFolder('\').GetTask($name)
    $task.SetSecurityDescriptor('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)',0)
    $sha=[Security.Cryptography.SHA256]::Create()
    try{$inputs.task_sha256=[EndpointInstallerBridge.Policy]::Hex($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$task.Xml)))}finally{$sha.Dispose()}
    [EndpointInstallerBridge.PackageHelper]::WriteCapability($leaf,[Text.Encoding]::UTF8.GetBytes(($inputs|ConvertTo-Json -Depth 12 -Compress)))
    Start-ScheduledTask -TaskName $name
}

function Remove-StagedRecoveryTask {
    param([string]$OperationId,[string]$StateRoot)
    if($OperationId -cnotmatch '^[0-9a-f-]{36}$'){throw 'OWNER_AUTH_FAILED'}
    $record=Read-UpdateGateState -Path (Join-Path $StateRoot 'staged-update.json') -Limit 65536
    if($null -eq $record -or $record.Value.binding.operation_id -cne $OperationId -or $record.Value.phase -cnotin @('accepted','rolled-back')){throw 'RECOVERY_REQUIRED'}
    $name='EndpointStagedRecovery-'+$OperationId
    if(Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue){Unregister-ScheduledTask -TaskName $name -Confirm:$false}
}

function Complete-StagedTerminalCleanup {
    param($Bridge,$ServiceStates,[string]$StateRoot,[switch]$RequireServices)
    try {
        if($ServiceStates['EndpointBrowserPolicy'] -ceq 'Running'){Start-VerifiedBrowserPolicy}
        if($ServiceStates['EndpointAgent'] -ceq 'Running'){Start-ManagedEndpointAgent}
        $restored=Invoke-InstallerHelper -Bridge $Bridge -Phase 'restore-staged-companions'
        foreach($name in @('EndpointAgent','EndpointAgentUpdater','EndpointBrowserPolicy')){
            if($ServiceStates[$name] -ceq 'Running' -and $restored.services.$name -cne 'running'){throw 'RECOVERY_REQUIRED'}
        }
        if($restored.users -isnot [string] -or $restored.users -cnotin @('not-required','launch-requested','session-unavailable')){throw 'RECOVERY_REQUIRED'}
        Remove-StagedRecoveryTask $Bridge.TransactionId $StateRoot
    } catch {
        Write-Warning 'STAGED_TERMINAL_CLEANUP_DEFERRED'
        # Accepted health is durable; ordinary cleanup cannot undo it. A
        # recovery caller must retain its task and report unavailable services.
        if($RequireServices){throw 'RECOVERY_REQUIRED'}
    }
}

function ConvertTo-StagedServiceStates {
    param([Parameter(Mandatory)]$Value)
    $names=@('EndpointAgent','EndpointAgentUpdater','EndpointBrowserPolicy')
    $actual=if($Value -is [Collections.IDictionary]){@($Value.Keys)}else{@($Value.PSObject.Properties.Name)}
    if([string]::Join('|',@($actual|Sort-Object)) -cne [string]::Join('|',@($names|Sort-Object))){throw 'RECOVERY_REQUIRED'}
    $states=@{}
    foreach($name in $names){
        $item=if($Value -is [Collections.IDictionary]){$Value[$name]}else{$Value.$name}
        if($item -isnot [string] -or $item -cnotin @('Running','Stopped','Absent')){throw 'RECOVERY_REQUIRED'}
        $states[$name]=$item
    }
    return $states
}

function Get-StagedForwardRecoveryLocator {
    param([string]$Phase,$Fence,[string]$Root,$Manifest)
    if($Phase -cnotin @('preparing','prepared','switching','native-settled','trial','accepted','rolling-back','rolled-back','recovery-required')){throw 'RECOVERY_REQUIRED'}
    if($null -ne $Fence -and $Phase -cne 'switching'){throw 'RECOVERY_REQUIRED'}
    # Completed compound history deliberately remains on disk. After the
    # switching phase only the authenticated recovery helper may classify its
    # settlement; its exact marker and native barrier are still mandatory.
    if($Phase -ceq 'switching'){return Read-CompoundRecoveryLocator $Root $Manifest}
    return $null
}

function Invoke-StagedRecovery {
    param($Bridge,$Manifest,[string]$HelperPath,[string]$HelperHash,[string]$StateRoot,[string]$CacheRoot,
        [string]$OperationId,[string]$InstallRoot,$CandidateMedia)
    $observed=Invoke-InstallerHelper -Bridge $Bridge -Phase 'inspect-staged-recovery'
    if($observed.operation_id -cne $OperationId){throw 'OWNER_AUTH_FAILED'}
    $serviceStates=ConvertTo-StagedServiceStates $observed.service_states
    $proof=[EndpointInstallerBridge.NativeTransaction]::EstablishSettlement($Bridge.Owner)
    $Bridge.Policy.AuthorizeStagedRecovery($proof)
    $adopted=Invoke-InstallerHelper -Bridge $Bridge -Phase 'recover-staged-owner'
    if($adopted.operation_id -cne $OperationId){throw 'OWNER_AUTH_FAILED'}
    if($adopted.action -cin @('accepted','rolled-back','preparation-cancelled')){
        Complete-StagedTerminalCleanup $Bridge $serviceStates $StateRoot -RequireServices
        return $(if($adopted.action -ceq 'accepted'){0}else{67})
    }
    if($adopted.action -ceq 'reboot-required'){return 3010}
    if($adopted.action -cnotin @('trial-required','rollback-required')){throw 'RECOVERY_REQUIRED'}
    $stopped=@{}
    Stop-ManagedAgentServices -PreviousStates (Get-ManagedAgentServiceStates) -StoppedBySetup $stopped
    $Bridge.Policy.MarkQuiescent()
    if($adopted.action -ceq 'rollback-required' -or (Invoke-StagedHealthTrial -Bridge $Bridge -InstallRoot $InstallRoot) -cne 'accepted'){
        $result=Invoke-StagedFoundationRollback -Manifest $Manifest -HelperPath $HelperPath -HelperHash $HelperHash -StateRoot $StateRoot -CacheRoot $CacheRoot -ServiceStates $serviceStates -Selection ([pscustomobject]@{foundation_release=$observed.old_release}) -CandidateMedia $CandidateMedia -OperationId $OperationId -InstallRoot $InstallRoot
        if($result -cne 'rolled-back' -and $result -cne 'accepted'){throw 'RECOVERY_REQUIRED'}
        Complete-StagedTerminalCleanup $Bridge $serviceStates $StateRoot -RequireServices
        return $(if($result -ceq 'rolled-back'){67}else{0})
    }
    Complete-StagedTerminalCleanup $Bridge $serviceStates $StateRoot -RequireServices
    return 0
}

function Invoke-StagedOnlinePreparation {
    param([Parameter(Mandatory)]$Bridge,[Parameter(Mandatory)]$Manifest,
        [Parameter(Mandatory)][string]$HelperPath,[Parameter(Mandatory)][string]$HelperHash,
        [Parameter(Mandatory)][string]$StateRoot,[Parameter(Mandatory)]$ServiceStates,
        [Parameter(Mandatory)]$Selection,[Parameter(Mandatory)][string]$CacheRoot,[scriptblock]$PrepareRecovery)
    $observation=Get-StagedAgentObservation
    $next=New-InstallerBridge -Manifest $Manifest -HelperPath $HelperPath -HelperHash $HelperHash `
        -StateRoot $StateRoot -ServiceStates $ServiceStates -Intent 'install' `
        -TransactionId $Bridge.TransactionId -Selection $Selection
    try {
        if($null -ne $PrepareRecovery){& $PrepareRecovery $next}
        $prepared=Invoke-InstallerHelper -Bridge $next -Phase 'stage-online'
        if ($prepared.result -cne 'staged-prepared' -or $prepared.phase -cne 'prepared' -or
            $prepared.operation_id -cne $next.TransactionId) { throw 'PROVENANCE_CONFLICT' }
        if ($prepared.rollback_media.new.release.package_sha256 -cne $Manifest.package_sha256 -or
            $prepared.rollback_media.new.helper_sha256 -cne $HelperHash) { throw 'PROVENANCE_CONFLICT' }
        $next.RollbackMediaPath=Get-StagedRollbackMedia -Item $prepared.rollback_media.old -StateRoot $StateRoot -CacheRoot $CacheRoot
        if ($null -ne $prepared.PSObject.Properties['metrics']) {
            $metricsPath=Join-Path $StateRoot ('online-metrics-'+$next.TransactionId+'.json')
            [EndpointInstallerBridge.PackageHelper]::WriteCapability($metricsPath,[Text.Encoding]::UTF8.GetBytes(($prepared.metrics|ConvertTo-Json -Compress)))
        }
        if ((Get-StagedAgentObservation) -cne $observation) { throw 'UPDATE_IN_PROGRESS' }
    } catch {
        $next.Policy.OwnerLost();$next.Channel.Dispose()
        foreach($peer in $next.Peers){$peer.Dispose()}
        $next.Owner.Dispose()
        throw
    }
    $Bridge.Policy.OwnerLost();$Bridge.Channel.Dispose()
    foreach($peer in $Bridge.Peers){$peer.Dispose()}
    $Bridge.Owner.Dispose()
    return $next
}

function Invoke-CompoundNativePump {
    param([Parameter(Mandatory)]$Driver,[Parameter(Mandatory)][array]$Conversations,[ValidateSet(1,2)][int]$Channels=2)
    if ($Conversations.Count -ne $Channels -or $null -eq $Driver.PendingTask) { throw 'OWNER_AUTH_FAILED' }
    $timer=[Diagnostics.Stopwatch]::StartNew()
    do {
        if ($timer.Elapsed.TotalMinutes -gt 30) { throw 'RECOVERY_REQUIRED' }
        try { $Driver.CheckOwnership() }
        catch {
            # End may signal the event immediately before returning. All commit
            # callbacks have already acknowledged; do not issue any new grants
            # while awaiting the private native result within the existing bound.
            if ($Driver.IsNativeClosurePending()) {
                Start-Sleep -Milliseconds 1
                continue
            }
            # The task may have completed between the failed check and the
            # pending query. Require a fresh strict check before resuming.
            $Driver.CheckOwnership()
        }
        $worked=$false
        foreach ($state in $Conversations) {
            if (Invoke-InstallerConversationStep -State $state) { $worked=$true }
        }
        $pending=$false
        foreach ($state in $Conversations) {
            if ($null -ne $state.Challenge -or $null -ne $state.Acknowledgement -or
                @($state.Bridge.Peers | Where-Object { $_.Alive }).Count -gt 0) { $pending=$true }
        }
        if ($Driver.PendingTask.IsCompleted -and -not $pending) { break }
        if (-not $worked) {
            [EndpointInstallerBridge.Channel]::WaitForAnyActivity(
                [EndpointInstallerBridge.Channel[]]@($Conversations | ForEach-Object {$_.Bridge.Channel}),
                $Driver.PendingTask,10)
        }
    } while ($true)
}

function Get-InstallerReaderSids {
    return @('S-1-5-80-1102781572-1373263041-1070489469-7526906-1468061691',
        'S-1-5-80-327494974-20047353-929432329-1920152597-707704661')
}

function New-CompoundNativeDriver {
    param($Policy,$Owner,$OldMedia,$NewMedia,[string]$SuccessorProduct)
    return [EndpointInstallerBridge.NativeTransaction]::new($Policy,$Owner,$OldMedia,$NewMedia,$SuccessorProduct)
}

function Invoke-CompoundFoundationUpgrade {
    param($OldBridge,[Parameter(Mandatory)]$NewBridge,$PreparedOldBridge,
        $OldMedia,$NewMedia,[Parameter(Mandatory)][string]$SuccessorProduct,
        [ValidateSet('fresh','replace-foundation','repair-successor')][string]$Mode='fresh')
    $repair=$Mode -ceq 'repair-successor'
    $bridges=@($NewBridge)
    if ($Mode -cne 'fresh' -and ($NewBridge.Capability.recovery -ne $true -or $NewBridge.Capability.compound.recovery.mode -cne $Mode)) { throw 'OWNER_AUTH_FAILED' }
    if ($repair) {
        if ($null -ne $OldBridge -or $null -ne $PreparedOldBridge) { throw 'OWNER_AUTH_FAILED' }
        $oldHash=$NewBridge.Capability.compound.old.package.package_sha256
        $compound=[EndpointInstallerBridge.SuccessorRepairPolicy]::new($NewBridge.Policy,$oldHash)
    } else {
        if ($null -eq $OldBridge) { throw 'OWNER_AUTH_FAILED' }
        $bridges=@($OldBridge,$NewBridge);$oldHash=$OldBridge.Policy.PackageHash
        if ($Mode -ceq 'replace-foundation') {
            if ($null -ne $PreparedOldBridge) { throw 'OWNER_AUTH_FAILED' }
            $compound=[EndpointInstallerBridge.CompoundPolicy]::CreateRecovery($OldBridge.Policy,$NewBridge.Policy)
        }
        elseif ($null -ne $PreparedOldBridge) {
            if ($null -eq $NewBridge.Capability.compound.prepared_old -or
                $NewBridge.Capability.compound.prepared_old.source.session_id -cne $PreparedOldBridge.SessionId) { throw 'OWNER_AUTH_FAILED' }
            $compound=[EndpointInstallerBridge.CompoundPolicy]::CreatePreparedRemoval($PreparedOldBridge.Policy,$OldBridge.Policy,$NewBridge.Policy)
        }
        elseif ($NewBridge.Capability.compound.ContainsKey('prepared_old')) { throw 'OWNER_AUTH_FAILED' }
        else { $compound=[EndpointInstallerBridge.CompoundPolicy]::new($OldBridge.Policy,$NewBridge.Policy) }
    }
    $driver=$null
    try {
        $driver=New-CompoundNativeDriver $compound $NewBridge.Owner $OldMedia $NewMedia $SuccessorProduct
        foreach ($bridge in $bridges) { $bridge.NativeDriver=$driver }
        $conversations=@(foreach ($bridge in $bridges) { New-InstallerConversation $bridge $bridge.Owner 'native' $true })
        $driver.BeginNative()
        if (-not $repair) {
            $driver.StartOldScript()
            Invoke-CompoundNativePump $driver $conversations -Channels $bridges.Count
            if ($driver.CompleteOldScript() -ne 0) { throw 'RECOVERY_REQUIRED' }
            Invoke-InstallerHelper $NewBridge 'compound-old-returned' | Out-Null
        }
        $driver.StartNewScript()
        Invoke-CompoundNativePump $driver $conversations -Channels $bridges.Count
        if ($driver.CompleteNewScript() -ne 0) { throw 'RECOVERY_REQUIRED' }
        Invoke-InstallerHelper $NewBridge $(if($repair){'compound-repair-returned'}else{'compound-new-returned'}) | Out-Null
        $driver.StartEnd($true)
        Invoke-CompoundNativePump $driver $conversations -Channels $bridges.Count
        if ($driver.CompleteEnd() -ne 0) { throw 'RECOVERY_REQUIRED' }
        foreach ($phase in @($(if($repair){'compound-repair-commit'}else{'compound-commit'}),'compound-retire','reconcile','finish')) {
            Invoke-InstallerHelper $NewBridge $phase | Out-Null
        }
        $ready=Invoke-InstallerHelper $NewBridge 'compound-complete'
        if ($ready.result -cne 'compound-ready' -or $ready.marker.upgrade_id -cne $NewBridge.Capability.compound.upgrade_id -or
            $ready.marker.new_transaction_id -cne $NewBridge.TransactionId -or
            $ready.marker.old_package_sha256 -cne $oldHash -or
            $ready.marker.new_package_sha256 -cne $NewBridge.Policy.PackageHash -or
            $ready.marker.successor_product_code -cne $SuccessorProduct -or
            $ready.marker.source_revision -cne $NewBridge.Capability.package.source_revision -or
            @($bridges | ForEach-Object { $_.Peers } | Where-Object { $_.Alive }).Count -ne 0) { throw 'RECOVERY_REQUIRED' }
        $driver.PublishCompletion($ready.marker.upgrade_id,$ready.marker.source_revision,$ready.marker.ready_sha256)
    } catch {
        $compound.OwnerLost()
        # Closing both channels forces every outstanding helper to lose its
        # grants before a blocked native API can return to this owner thread.
        foreach ($bridge in $bridges) { $bridge.Channel.Dispose() }
        if ($null -ne $driver) {
            try {
                $timer=[Diagnostics.Stopwatch]::StartNew()
                while ($null -ne $driver.PendingTask -and -not $driver.PendingTask.IsCompleted) {
                    if ($timer.Elapsed.TotalMinutes -gt 30) { throw 'RECOVERY_REQUIRED' }
                    Start-Sleep -Milliseconds 20
                }
                if ($null -ne $driver.PendingTask) { $driver.DiscardInterruptedCall() | Out-Null }
                if ($driver.HasNativeTransaction) {
                    $driver.StartAbort()
                    while (-not $driver.PendingTask.IsCompleted) {
                        if ($timer.Elapsed.TotalMinutes -gt 30) { throw 'RECOVERY_REQUIRED' }
                        Start-Sleep -Milliseconds 20
                    }
                    if ($driver.CompleteAbort() -ne 0) { throw 'RECOVERY_REQUIRED' }
                }
            } catch { Write-Warning 'RECOVERY_REQUIRED: native settlement unavailable' }
        }
        throw
    } finally {
        foreach ($bridge in $bridges) { [void]$bridge.Remove('NativeDriver') }
        if ($null -ne $driver) {
            if ($driver.HasNativeTransaction -or $null -ne $driver.PendingTask) {
                Write-Warning 'RECOVERY_REQUIRED: native ownership remains unsettled'
            } else { $driver.Dispose() }
        }
    }
}

function Assert-InstallerPublicStateAcl {
    param([Parameter(Mandatory)][string]$Path)
    Initialize-InstallerBridgeTypes
    [EndpointInstallerBridge.LaunchDirectory]::ValidateAncestors($Path)
    $readers = Get-InstallerReaderSids
    Assert-ExistingPathChain -Path $Path
    Assert-ProtectedAcl -Path $Path -AllowedSids @($CacheSids + $readers) -RequiredSids @($CacheSids + $readers) -RequireProtected
    foreach ($rule in (Get-Acl -LiteralPath $Path).Access) {
        $sid = Get-SidValue -Identity $rule.IdentityReference
        if ($sid -in $readers -and ([int]$rule.FileSystemRights -band (-bnot 0x1200a9))) { throw 'UPDATE_STATE_INVALID' }
    }
}

function New-InstallerPublicStateRoot {
    param([Parameter(Mandatory)][string]$Path)
    if (Test-Path -LiteralPath $Path) { Assert-InstallerPublicStateAcl $Path; return }
    $security = New-InstallerCacheSecurity
    foreach ($sid in (Get-InstallerReaderSids)) {
        $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid), [Security.AccessControl.FileSystemRights]0x1200a9,
            ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),
            [Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))
    }
    [IO.Directory]::CreateDirectory($Path,$security) | Out-Null
    Assert-InstallerPublicStateAcl $Path
}

function Read-InstallerFence {
    param([Parameter(Mandatory)][string]$Root)
    if (-not (Test-Path -LiteralPath $Root)) { Assert-ExistingPathChain $Root; return $null }
    Assert-InstallerPublicStateAcl $Root
    $path = Join-Path $Root 'transaction.json'
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    Assert-InstallerPublicStateAcl $path
    $value = (Read-UpdateGateState -Path $path -Limit 16384).Value
    if ($value -isnot [Collections.IDictionary] -or [string]::Join('|',@($value.Keys | Sort-Object)) -ne 'helpers|operation|package|phase|previous|schema_version|selected|sequence|service_startup|service_states|startup_restored|transaction_id') { throw 'UPDATE_STATE_INVALID' }
    if ($value.schema_version -isnot [int] -or $value.schema_version -ne 1 -or $value.sequence -isnot [int] -or $value.sequence -lt 0 -or $value.sequence -gt 256 -or $value.transaction_id -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' -or $value.phase -notin @('prepared','msi-starting','msi-executing','msi-returned','reconciling','complete') -or $value.operation -notin @('install','retire-initial-runtime','uninstall')) { throw 'UPDATE_STATE_INVALID' }
    if ($value.package -isnot [Collections.IDictionary] -or [string]::Join('|',@($value.package.Keys | Sort-Object)) -ne 'package_code|product_code|sha256|source_revision|version' -or $value.package.sha256 -cnotmatch '^[0-9a-f]{64}$' -or $value.package.source_revision -cnotmatch '^[0-9a-f]{40}$' -or $value.package.version -cnotmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$') { throw 'UPDATE_STATE_INVALID' }
    foreach ($name in @('product_code','package_code')) { if ($value.package[$name] -cnotmatch '^\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}$') { throw 'UPDATE_STATE_INVALID' } }
    foreach ($name in @('selected','previous')) { if ($null -ne $value[$name] -and $value[$name] -cnotmatch '^[0-9a-f]{64}$') { throw 'UPDATE_STATE_INVALID' } }
    if ($value.service_states -isnot [Collections.IDictionary] -or [string]::Join('|',@($value.service_states.Keys | Sort-Object)) -ne 'EndpointAgent|EndpointAgentUpdater') { throw 'UPDATE_STATE_INVALID' }
    foreach ($state in $value.service_states.Values) { if ($state -notin @('running','stopped','absent')) { throw 'UPDATE_STATE_INVALID' } }
    if ($value.startup_restored -isnot [bool] -or $value.service_startup -isnot [Collections.IDictionary] -or [string]::Join('|',@($value.service_startup.Keys | Sort-Object)) -ne 'EndpointAgent|EndpointAgentUpdater') { throw 'UPDATE_STATE_INVALID' }
    foreach ($config in $value.service_startup.Values) {
        if ($null -ne $config -and ($config -isnot [Collections.IDictionary] -or [string]::Join('|',@($config.Keys | Sort-Object)) -ne 'delayed_auto|start_type' -or $config.start_type -isnot [int] -or $config.start_type -notin @(2,3,4) -or $config.delayed_auto -isnot [bool])) { throw 'UPDATE_STATE_INVALID' }
    }
    if ($value.helpers -isnot [array] -or $value.helpers.Count -gt 64) { throw 'UPDATE_STATE_INVALID' }
    foreach ($helper in $value.helpers) {
        if ($helper -isnot [Collections.IDictionary] -or [string]::Join('|',@($helper.Keys | Sort-Object)) -ne 'complete|creation_time|image_sha256|phase|pid' -or $helper.pid -isnot [int] -or $helper.pid -le 0 -or $helper.creation_time -le 0 -or $helper.image_sha256 -cnotmatch '^[0-9a-f]{64}$' -or $helper.complete -isnot [bool] -or $helper.phase -notin @('prepared','msi-starting','msi-executing','msi-returned','reconciling','complete')) { throw 'UPDATE_STATE_INVALID' }
    }
    return $value
}

function Save-InstallerCapability {
    param($Bridge)
    if (Test-Path -LiteralPath $Bridge.CapabilityPath) { throw 'OWNER_AUTH_FAILED' }
    $bytes = [Text.Encoding]::ASCII.GetBytes(($Bridge.Capability | ConvertTo-Json -Compress -Depth 10))
    [EndpointInstallerBridge.PackageHelper]::WriteCapability($Bridge.CapabilityPath,$bytes)
    Assert-CacheArtifactProtection $Bridge.CapabilityPath
}

function Save-PreparedOldRemoval {
    param([Parameter(Mandatory)]$Bridge,[Parameter(Mandatory)][string]$StateRoot)
    # Invoke-InstallerHelper has required the authenticated completion ACK,
    # actual helper exit0 and closed conversations. Revoke this policy/channel
    # before any grant is issued to the separate maintenance recovery session.
    $Bridge.Policy.SealPreparedRemoval()
    $Bridge.Channel.Dispose()
    $root=Join-Path $StateRoot 'prepared-old'
    if (-not (Test-Path -LiteralPath $root)) { New-ProtectedDirectory $root }
    Assert-InstallerCacheProtection $root
    $archive=Join-Path $root $Bridge.SessionId
    if (Test-Path -LiteralPath $archive) { throw 'OWNER_AUTH_FAILED' }
    New-ProtectedDirectory $archive
    $role=@{source=@{transaction_id=$Bridge.TransactionId;session_id=$Bridge.SessionId;
        package=$Bridge.Capability.package;helper_sha256=$Bridge.HelperHash};
        capability_sha256=(Get-FileHash -LiteralPath $Bridge.CapabilityPath -Algorithm SHA256).Hash.ToLowerInvariant()}
    $originals=@{fence=(Join-Path $StateRoot 'transaction.json');
        maintenance=(Join-Path $StateRoot ('transactions\'+$Bridge.TransactionId+'\maintenance.json'))}
    foreach ($name in @('fence','maintenance')) {
        $original=$originals[$name];Assert-InstallerPublicStateAcl $original
        $pin=[IO.File]::Open($original,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        try {
            if ($pin.Length -le 0 -or $pin.Length -gt 16384) { throw 'UPDATE_STATE_INVALID' }
            $bytes=[byte[]]::new([int]$pin.Length)
            $read=0;while ($read -lt $bytes.Length) {
                $count=$pin.Read($bytes,$read,$bytes.Length-$read)
                if ($count -le 0) { throw 'UPDATE_STATE_INVALID' };$read+=$count
            }
            $copy=Join-Path $archive ($name+'.json')
            [EndpointInstallerBridge.PackageHelper]::WriteCapability($copy,$bytes)
            Assert-CacheArtifactProtection $copy
            $role[$name+'_sha256']=(Get-FileHash -LiteralPath $copy -Algorithm SHA256).Hash.ToLowerInvariant()
        } finally { $pin.Dispose() }
    }
    return $role
}

function New-InstallerBridge {
    param($Manifest,[string]$HelperPath,[string]$HelperHash,[string]$StateRoot,[hashtable]$ServiceStates,$Fence,[string]$Intent,[string]$TransactionId,$Selection,$Compound,[string]$RecoveryParent,[string]$BoundSessionId,$StagedRollback)
    Initialize-InstallerBridgeTypes
    New-InstallerPublicStateRoot $StateRoot
    $capabilities = Join-Path $StateRoot 'capabilities'
    if (-not (Test-Path -LiteralPath $capabilities)) { New-ProtectedDirectory $capabilities }
    Assert-InstallerCacheProtection $capabilities
    if ($null -ne $Fence) { $transactionId = $Fence.transaction_id }
    elseif (-not $TransactionId) { $transactionId = [Guid]::NewGuid().ToString('D') }
    if ($BoundSessionId) {
        if ($BoundSessionId -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' -or $null -ne $Fence -or $null -ne $Compound -or $RecoveryParent) { throw 'OWNER_AUTH_FAILED' }
        $sessionId=$BoundSessionId
    } else { $sessionId = [Guid]::NewGuid().ToString('D') }
    # A fresh launch directory per owner session also keeps a recovered
    # transaction away from any directory still used by an earlier helper.
    $launchDirectory = Join-Path $StateRoot ('helper-' + $transactionId + '-' + [Guid]::NewGuid().ToString('N'))
    Assert-ExistingPathChain $launchDirectory
    [EndpointInstallerBridge.LaunchDirectory]::Create($launchDirectory)
    Assert-InstallerCacheProtection $launchDirectory
    $secret = [byte[]]::new(32)
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($secret) } finally { $rng.Dispose() }
    $owner = [EndpointInstallerBridge.NativeProcess]::new($PID)
    $policy = [EndpointInstallerBridge.Policy]::new($transactionId,$sessionId,$Manifest.package_sha256,$Intent,$owner.Identity,$HelperHash,$secret)
    $policy.Recovery = $null -ne $Fence
    $pipeName = 'EndpointInstaller-' + $sessionId + '-' + [Guid]::NewGuid().ToString('N')
    $channel = [EndpointInstallerBridge.Channel]::new($pipeName)
    $states = @{}
    foreach ($name in @('EndpointAgent','EndpointAgentUpdater')) { $states[$name] = $ServiceStates[$name].ToLowerInvariant() }
    $identity = $owner.Identity
    $capability = @{ schema_version=1; transaction_id=$transactionId; session_id=$sessionId; package=$Manifest; operation=$Intent;
        pipe_name=$pipeName; owner=@{pid=$identity.Pid;created=$identity.Created;hash=$identity.Hash;sid=$identity.Sid;elevated=$identity.Elevated};
        helper_sha256=$HelperHash; secret=[EndpointInstallerBridge.Policy]::Hex($secret); selected=$null;previous=$null;
        service_states=$states; recovery=($null -ne $Fence);uninstall_finalization=$false }
    if ($null -ne $Fence) {
        $capability.selected=$Fence.selected;$capability.previous=$Fence.previous;$capability.service_states=$Fence.service_states
    } elseif ($null -ne $Selection) {
        $capability.selected=$Selection.selected;$capability.previous=$Selection.previous
    }
    if ($null -ne $Selection -and $null -ne $Selection.PSObject.Properties['uninstall_finalization'] -and $Selection.uninstall_finalization -eq $true) {
        if ($Intent -cne 'uninstall' -or $null -eq $Fence) { throw 'OWNER_AUTH_FAILED' }
        $capability.uninstall_finalization=$true
        $policy.UninstallFinalization=$true
    }
    if ($null -ne $Compound) {
        if ($Intent -cne 'install' -or $null -ne $Fence -or $null -eq $Selection -or $RecoveryParent) { throw 'OWNER_AUTH_FAILED' }
        if ($Compound.ContainsKey('recovery')) {
            $capability.recovery=$true;$policy.Recovery=$true
            foreach ($name in @('EndpointAgent','EndpointAgentUpdater')) { $capability.service_states[$name]=$Selection.service_states.$name }
        }
        $capability.compound=$Compound
    }
    if ($RecoveryParent) {
        if ($Intent -cne 'install' -or $null -ne $Fence -or $null -ne $Compound -or $RecoveryParent -cnotmatch '^[0-9a-f-]{36}$') { throw 'OWNER_AUTH_FAILED' }
        $capability.recovery=$true;$policy.Recovery=$true;$capability.recovery_parent=$RecoveryParent
        $policy.MarkRecoveryLocator()
    }
    if ($null -ne $StagedRollback) {
        if ($null -ne $Fence -or $null -ne $Compound -or $RecoveryParent -or $capability.uninstall_finalization) { throw 'OWNER_AUTH_FAILED' }
        $capability.staged_rollback=$StagedRollback
    }
    $bridge = @{ Policy=$policy; Owner=$owner; Channel=$channel; Operation=$Intent; TransactionId=$transactionId; SessionId=$sessionId;
        HelperPath=$HelperPath;HelperHash=$HelperHash;Capability=$capability;LaunchDirectory=$launchDirectory;
        CapabilityPath=(Join-Path $capabilities ($sessionId+'.json')); Peers=[Collections.Generic.List[object]]::new() }
    try { Save-InstallerCapability $bridge } catch { $channel.Dispose();$owner.Dispose();throw }
    return $bridge
}

function Assert-ExistingPathChain {
    param([Parameter(Mandatory = $true)][string]$Path)
    $candidate = [IO.Path]::GetFullPath($Path)
    while (-not (Test-Path -LiteralPath $candidate)) {
        $parent = Split-Path -Parent $candidate
        if (-not $parent -or $parent -eq $candidate) { break }
        $candidate = $parent
    }
    while ($candidate) {
        $item = Get-Item -LiteralPath $candidate -Force
        if ([bool]($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Installer path contains a reparse point.'
        }
        $parent = Split-Path -Parent $candidate
        if (-not $parent -or $parent -eq $candidate) { break }
        $candidate = $parent
    }
}

function Get-SidValue {
    param([Parameter(Mandatory = $true)]$Identity)
    try {
        return $Identity.Translate([Security.Principal.SecurityIdentifier]).Value
    }
    catch {
        throw 'Installer path identity cannot be resolved to a SID.'
    }
}

function Assert-TrustedOwner {
    param([Parameter(Mandatory = $true)][string]$Path)
    $acl = Get-Acl -LiteralPath $Path
    $ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($ownerSid -notin $CacheSids) {
        throw 'Installer path owner is not trusted.'
    }
}

function Assert-ProtectedAcl {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string[]]$AllowedSids,
        [Parameter(Mandatory = $true)][string[]]$RequiredSids,
        [switch]$RequireProtected
    )
    $acl = Get-Acl -LiteralPath $Path
    if ($RequireProtected -and -not $acl.AreAccessRulesProtected) {
        throw 'Installer path DACL is not protected.'
    }
    Assert-TrustedOwner -Path $Path
    $actual = @()
    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
            throw 'Installer path contains a deny ACL rule.'
        }
        $sid = Get-SidValue -Identity $rule.IdentityReference
        if ($sid -notin $AllowedSids) {
            throw 'Installer path contains an untrusted ACL rule.'
        }
        $actual += $sid
    }
    if (@($RequiredSids | Where-Object { $_ -notin $actual }).Count -ne 0) {
        throw 'Installer path is missing a required ACL rule.'
    }
}

function New-InstallerCacheSecurity {
    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetAccessRuleProtection($true, $false)
    $security.SetOwner([Security.Principal.SecurityIdentifier]::new($AdministratorsSid))
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($sid in $CacheSids) {
        $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid),
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        ))
    }
    return $security
}

function New-ProtectedDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)
    Initialize-InstallerBridgeTypes
    [EndpointInstallerBridge.LaunchDirectory]::ValidateAncestors($Path)
    Assert-ExistingPathChain -Path (Split-Path -Parent $Path)
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    Set-Acl -LiteralPath $Path -AclObject (New-InstallerCacheSecurity)
    Assert-ExistingPathChain -Path $Path
    Assert-ProtectedAcl -Path $Path -AllowedSids $CacheSids -RequiredSids $CacheSids -RequireProtected
}

function Assert-InstallerCacheProtection {
    param([Parameter(Mandatory = $true)][string]$Path)
    Initialize-InstallerBridgeTypes
    [EndpointInstallerBridge.LaunchDirectory]::ValidateAncestors($Path)
    Assert-ExistingPathChain -Path $Path
    Assert-ProtectedAcl -Path $Path -AllowedSids $CacheSids -RequiredSids $CacheSids -RequireProtected
}

function Get-AgentServiceSids {
    $sids = @()
    foreach ($name in @('NT SERVICE\EndpointAgent', 'NT SERVICE\EndpointAgentUpdater')) {
        try {
            $sids += Get-SidValue -Identity ([Security.Principal.NTAccount]::new($name))
        }
        catch {
            continue
        }
    }
    return $sids
}

function Assert-InstalledDataProtection {
    param([Parameter(Mandatory = $true)][string]$Path)
    $serviceSids = Get-AgentServiceSids
    if ($serviceSids.Count -ne 2) { throw 'Installed service SIDs cannot be resolved.' }
    $allowed = @($CacheSids + $serviceSids)
    Assert-ProtectedAcl -Path $Path -AllowedSids $allowed -RequiredSids $allowed -RequireProtected
}

function Assert-CacheArtifactProtection {
    param([Parameter(Mandatory = $true)][string]$Path)
    Initialize-InstallerBridgeTypes
    [EndpointInstallerBridge.LaunchDirectory]::ValidateAncestors($Path)
    Assert-RegularNonReparseFile -Path $Path -Label 'Installer cache artifact'
    Assert-ProtectedAcl -Path $Path -AllowedSids $CacheSids -RequiredSids $CacheSids
}

function Set-CacheArtifactProtection {
    param([Parameter(Mandatory = $true)][string]$Path)
    Assert-RegularNonReparseFile -Path $Path -Label 'Installer cache artifact'
    $security = [Security.AccessControl.FileSecurity]::new()
    $security.SetAccessRuleProtection($true, $false)
    $security.SetOwner([Security.Principal.SecurityIdentifier]::new($AdministratorsSid))
    foreach ($sid in $CacheSids) {
        $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid),
            [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.AccessControlType]::Allow
        ))
    }
    Set-Acl -LiteralPath $Path -AclObject $security
    Assert-CacheArtifactProtection -Path $Path
}

function Get-ManagedAgentServiceStates {
    $previousStates = @{}
    foreach ($serviceName in @('EndpointAgent', 'EndpointAgentUpdater', 'EndpointBrowserPolicy')) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        $previousStates[$serviceName] = if ($null -eq $service) { 'Absent' } else { $service.Status.ToString() }
    }
    return $previousStates
}

function Stop-ManagedAgentServices {
    param([hashtable]$PreviousStates = (Get-ManagedAgentServiceStates),
        [Parameter(Mandatory)][hashtable]$StoppedBySetup, [scriptblock]$AfterAgentStopped = {})
    # Browser policy has no SCM dependency on Agent; its existing policy values
    # persist on service stop. Keep Agent online through that independent stop.
    # The late-update gate still runs after Agent stop and before Updater stop.
    foreach ($serviceName in @('EndpointBrowserPolicy', 'EndpointAgent', 'EndpointAgentUpdater')) {
        if ($serviceName -eq 'EndpointAgentUpdater') { & $AfterAgentStopped }
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($null -eq $service) { continue }
        if ($service.Status -eq [ServiceProcess.ServiceControllerStatus]::Stopped) {
            continue
        }
        # Record before SCM dispatch: a failed call can still have stopped the
        # service. A service already stopped by the worker is never ours to start.
        $StoppedBySetup[$serviceName] = $true
        Stop-Service -Name $serviceName -ErrorAction Stop
        $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, $ManagedServiceTimeout)
        $service.Refresh()
        if ($service.Status -ne [ServiceProcess.ServiceControllerStatus]::Stopped) {
            throw "Managed service $serviceName did not stop before MSI installation."
        }
    }
}

function Restore-ManagedAgentServices {
    param([Parameter(Mandatory)][hashtable]$PreviousStates,
        [Parameter(Mandatory)][hashtable]$StoppedBySetup,
        [switch]$RequireSettled, [scriptblock]$CanRestore,
        [TimeSpan]$RestorationTimeout = [TimeSpan]::FromSeconds(30))
    if ($RequireSettled) {
        if ($null -eq $CanRestore) { return 'deferred' }
        $deadline = [Diagnostics.Stopwatch]::StartNew()
        do {
            $settled = $false
            try { $settled = [bool](& $CanRestore) } catch { $settled = $false }
            if ($settled) { break }
            if ($deadline.Elapsed -ge $RestorationTimeout) { return 'deferred' }
            Start-Sleep -Milliseconds 200
        } while ($true)
    }
    $failures = @()
    foreach ($serviceName in @('EndpointAgent', 'EndpointAgentUpdater', 'EndpointBrowserPolicy')) {
        if ($PreviousStates[$serviceName] -ne 'Running' -or -not $StoppedBySetup.ContainsKey($serviceName)) { continue }
        try {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($null -eq $service) { throw 'Previously running managed service is absent.' }
            if ($service.Status -ne [ServiceProcess.ServiceControllerStatus]::Running) {
                Start-Service -Name $serviceName -ErrorAction Stop
                $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, $ManagedServiceTimeout)
                $service.Refresh()
            }
            if ($service.Status -ne [ServiceProcess.ServiceControllerStatus]::Running) { throw 'Managed service restoration failed.' }
        } catch { $failures += $serviceName }
    }
    if ($failures.Count) { throw 'MANAGED_SERVICE_RESTORATION_FAILED' }
    return 'restored'
}

function Start-ManagedEndpointAgent {
    $service = Get-Service -Name 'EndpointAgent' -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        return
    }
    if ($service.Status -ne [ServiceProcess.ServiceControllerStatus]::Running) {
        Start-Service -Name 'EndpointAgent' -ErrorAction Stop
        $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, $ManagedServiceTimeout)
        $service.Refresh()
    }
    if ($service.Status -ne [ServiceProcess.ServiceControllerStatus]::Running) {
        throw 'EndpointAgent did not start after MSI installation.'
    }
}

function Start-VerifiedBrowserPolicy {
    # Authenticated finish already verified native ownership/bytes and enabled
    # this registration. Neither service is started while an installer fence lives.
    $service=Get-Service -Name 'EndpointBrowserPolicy' -ErrorAction Stop
    if ($service.Status -ne [ServiceProcess.ServiceControllerStatus]::Running) {
        Start-Service -Name 'EndpointBrowserPolicy' -ErrorAction Stop
        $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running,$ManagedServiceTimeout)
        $service.Refresh()
    }
    if ($service.Status -ne [ServiceProcess.ServiceControllerStatus]::Running) { throw 'RECOVERY_REQUIRED' }
}

function Start-VerifiedTrialServices {
    # Authenticated finish and trial admission precede this call. Dispatch both
    # fixed independent registrations before waiting for either; acceptance
    # still requires both Running and the unchanged fresh WSS/policy proof.
    $controllers=[Collections.Generic.List[object]]::new()
    try {
        foreach ($name in @('EndpointAgent','EndpointBrowserPolicy')) {
            $controllers.Add((Get-Service -Name $name -ErrorAction Stop))
        }
        foreach ($service in $controllers) {
            if ($service.Status -eq [ServiceProcess.ServiceControllerStatus]::Stopped) { $service.Start() }
            elseif ($service.Status -notin @([ServiceProcess.ServiceControllerStatus]::Running,
                    [ServiceProcess.ServiceControllerStatus]::StartPending)) { throw 'RECOVERY_REQUIRED' }
        }
        foreach ($service in $controllers) {
            $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running,$ManagedServiceTimeout)
            $service.Refresh()
            if ($service.Status -ne [ServiceProcess.ServiceControllerStatus]::Running) { throw 'RECOVERY_REQUIRED' }
        }
    } finally { foreach ($service in $controllers) { $service.Dispose() } }
}

function Get-CompoundOldMedia {
    param([Parameter(Mandatory)]$Manifest,[Parameter(Mandatory)][string]$StateRoot,
        [Parameter(Mandatory)][string]$CacheRoot)
    $digest=[string]$Manifest.package_sha256
    if ($digest -cnotmatch '^[0-9a-f]{64}$') { throw 'PROVENANCE_CONFLICT' }
    $original=Join-Path $StateRoot ('packages\'+$digest+'\EndpointAgent.msi')
    Assert-InstallerPublicStateAcl $original
    $sourcePin=[IO.File]::Open($original,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        $sha=[Security.Cryptography.SHA256]::Create()
        try { if ([EndpointInstallerBridge.Policy]::Hex($sha.ComputeHash($sourcePin)) -cne $digest) { throw 'PROVENANCE_CONFLICT' } } finally { $sha.Dispose() }
        $directory=Join-Path $CacheRoot ('msi-'+$digest)
        if (-not (Test-Path -LiteralPath $directory)) { New-ProtectedDirectory $directory }
        Assert-InstallerCacheProtection $directory
        $path=Join-Path $directory 'EndpointAgent.msi'
        if (-not (Test-Path -LiteralPath $path)) {
            [EndpointInstallerBridge.PackageHelper]::CopyCacheArtifact($original,$path)
            Set-CacheArtifactProtection $path
        }
        Assert-CacheArtifactProtection $path
        if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $digest) { throw 'PROVENANCE_CONFLICT' }
        return $path
    } finally { $sourcePin.Dispose() }
}

function Open-StagedPredecessorMedia {
    param($Manifest,[string]$StateRoot,[string]$CacheRoot)
    $packagePin=$null;$helperPin=$null
    try {
        $path=Get-CompoundOldMedia $Manifest $StateRoot $CacheRoot
        $packagePin=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $helper=Join-Path (Split-Path $path -Parent) 'endpoint-installer-host.exe'
        if(Test-Path -LiteralPath $helper){Assert-CacheArtifactProtection $helper}
        $hash=[EndpointInstallerBridge.PackageHelper]::Extract($path,$helper)
        Assert-CacheArtifactProtection $helper
        $helperPin=[IO.File]::Open($helper,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        return @{PackageHash=[string]$Manifest.package_sha256;PackagePath=$path;PackagePin=$packagePin;
            HelperPath=$helper;HelperHash=$hash;HelperPin=$helperPin}
    } catch {
        if($null -ne $helperPin){$helperPin.Dispose()}
        if($null -ne $packagePin){$packagePin.Dispose()}
        throw
    }
}

function Start-WindowsInstaller {
    $service = Get-Service -Name $WindowsInstallerServiceName -ErrorAction Stop
    if ($service.Status -ne [ServiceProcess.ServiceControllerStatus]::Running) {
        Start-Service -Name $WindowsInstallerServiceName -ErrorAction Stop
        $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, $ManagedServiceTimeout)
        $service.Refresh()
    }
    if ($service.Status -ne [ServiceProcess.ServiceControllerStatus]::Running) {
        throw 'Windows Installer service did not start before MSI installation.'
    }
}

function Read-ReleaseManifest {
    param([Parameter(Mandatory = $true)][string]$Path)
    Assert-RegularNonReparseFile -Path $Path -Label 'Release manifest'
    try {
        $value = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    }
    catch {
        throw 'Release manifest is unreadable.'
    }
    $expected = @(
        'initial_runtime_tree_sha256', 'package_sha256', 'product_code',
        'schema_version', 'source_revision', 'version'
    )
    $actual = @($value.PSObject.Properties.Name | Sort-Object)
    if ([string]::Join('|', $actual) -ne [string]::Join('|', $expected)) {
        throw 'Release manifest schema is invalid.'
    }
    if (
        [string]$value.schema_version -ne 'endpoint_windows_release_v1' -or
        [string]$value.version -notmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' -or
        [string]$value.product_code -notmatch '^\{[0-9A-F-]{36}\}$' -or
        [string]$value.source_revision -notmatch '^[0-9a-f]{40}$' -or
        [string]$value.initial_runtime_tree_sha256 -notmatch '^[0-9a-f]{64}$' -or
        [string]$value.package_sha256 -notmatch '^[0-9a-f]{64}$'
    ) {
        throw 'Release manifest values are invalid.'
    }
    return $value
}

function Read-CompoundRecoveryLocator {
    param([string]$Root,$Manifest)
    $path=Join-Path $Root 'upgrade.json'
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    Assert-InstallerPublicStateAcl $path
    $state=Read-UpdateGateState -Path $path -Limit 4096
    $value=$state.Value
    if ($value -isnot [Collections.IDictionary] -or [string]::Join('|',@($value.Keys | Sort-Object)) -cne 'new_package_sha256|new_transaction_id|old_package_sha256|schema_version|upgrade_id' -or $value.schema_version -isnot [int] -or $value.schema_version -ne 1) { throw 'PROVENANCE_CONFLICT' }
    foreach ($name in @('upgrade_id','new_transaction_id')) {
        $parsed=[Guid]::Empty
        if ($value[$name] -isnot [string] -or -not [Guid]::TryParseExact($value[$name],'D',[ref]$parsed) -or $parsed.ToString('D') -cne $value[$name]) { throw 'PROVENANCE_CONFLICT' }
    }
    foreach ($name in @('old_package_sha256','new_package_sha256')) {
        if ($value[$name] -isnot [string] -or $value[$name] -cnotmatch '^[0-9a-f]{64}$') { throw 'PROVENANCE_CONFLICT' }
    }
    if ($value.new_package_sha256 -cne $Manifest.package_sha256 -or $value.old_package_sha256 -ceq $value.new_package_sha256) { throw 'PROVENANCE_CONFLICT' }
    return $value
}

function New-UpdateTransaction {
    $name = 'Global\EndpointPlatform.Agent.UpdateTransaction'
    $serviceSids = @('S-1-5-80-1102781572-1373263041-1070489469-7526906-1468061691', 'S-1-5-80-327494974-20047353-929432329-1920152597-707704661')
    $script:UpdateMutexRights = @{'S-1-5-18'=0x1f0001; 'S-1-5-32-544'=0x1f0001; 'S-1-3-4'=0x20000}
    foreach ($sid in $serviceSids) { $script:UpdateMutexRights[$sid] = 0x120001 }
    $script:UpdateTrustedOwners = @('S-1-5-18','S-1-5-32-544','S-1-5-19') + $serviceSids
    $sddl = 'D:P(A;;0x1f0001;;;S-1-5-18)(A;;0x1f0001;;;S-1-5-32-544)(A;;0x120001;;;S-1-5-80-1102781572-1373263041-1070489469-7526906-1468061691)(A;;0x120001;;;S-1-5-80-327494974-20047353-929432329-1920152597-707704661)(A;;0x20000;;;S-1-3-4)'
    $security = [Security.AccessControl.MutexSecurity]::new()
    $security.SetSecurityDescriptorSddlForm($sddl)
    $security.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    $created = $false
    return [Threading.Mutex]::new($false, $name, [ref]$created, $security)
}

function Assert-UpdateTransactionSecurity {
    param($Mutex)
    $security = $Mutex.GetAccessControl()
    $raw = [Security.AccessControl.RawSecurityDescriptor]::new($security.GetSecurityDescriptorBinaryForm(), 0)
    if ($raw.Owner.Value -notin $script:UpdateTrustedOwners -or -not $security.AreAccessRulesProtected -or $null -eq $raw.DiscretionaryAcl -or $raw.DiscretionaryAcl.Count -ne 5) { throw 'Invalid update mutex security.' }
    $seen = @{}
    foreach ($ace in $raw.DiscretionaryAcl) {
        $sid = $ace.SecurityIdentifier.Value
        if ($ace.AceType -ne [Security.AccessControl.AceType]::AccessAllowed -or $ace.AceFlags -ne 0 -or $seen.ContainsKey($sid) -or -not $script:UpdateMutexRights.ContainsKey($sid) -or $ace.AccessMask -ne $script:UpdateMutexRights[$sid]) { throw 'Invalid update mutex ACE.' }
        $seen[$sid] = $true
    }
}

function Assert-UpdateGateAcl {
    param([string]$Path, [switch]$ServicingInstallRoot)
    if ($ServicingInstallRoot) {
        $item = Get-Item -LiteralPath $Path -Force
        if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Invalid install directory.' }
        $created = $item.CreationTimeUtc
        try { Assert-UpdateGateAcl -Path $Path; return } catch { }
        # Only this fixed directory observer accepts privileged servicing ACLs.
        # State files and all data directories retain the strict branch below.
        Initialize-InstallerBridgeTypes
        [EndpointInstallerBridge.LaunchDirectory]::ValidateAncestors($Path)
        $trusted = @('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
        $acl = Get-Acl -LiteralPath $Path
        $raw = [Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(),0)
        if ($null -eq $raw.DiscretionaryAcl -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) { throw 'Invalid install directory security.' }
        foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { throw 'Invalid install directory ACE.' }
            if (($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
            if (([int64]$rule.FileSystemRights -band 0x500d0156) -ne 0 -and $rule.IdentityReference.Value -notin $trusted) { throw 'Invalid install directory writer.' }
        }
        [EndpointInstallerBridge.LaunchDirectory]::ValidateAncestors($Path)
        $after = Get-Item -LiteralPath $Path -Force
        if (-not $after.PSIsContainer -or ($after.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $after.CreationTimeUtc -ne $created) { throw 'Install directory changed.' }
        return
    }
    $acl = Get-Acl -LiteralPath $Path
    $raw = [Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(),0)
    if ($null -eq $raw.DiscretionaryAcl) { throw 'Update state has a null DACL.' }
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin $script:UpdateTrustedOwners) { throw 'Invalid update state owner.' }
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or (([int64]$rule.FileSystemRights -band 0x500d0156) -ne 0 -and $rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544','S-1-5-80-1102781572-1373263041-1070489469-7526906-1468061691','S-1-5-80-327494974-20047353-929432329-1920152597-707704661'))) { throw 'Invalid update state writer.' }
    }
}

function Read-UpdateGateState {
    param([string]$Path, [int]$Limit)
    Assert-ExistingPathChain -Path $Path
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    Assert-RegularNonReparseFile -Path $Path -Label 'Update state'
    Assert-UpdateGateAcl -Path $Path
    $stream = [IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if ($stream.Length -le 0 -or $stream.Length -gt $Limit) { throw 'Invalid update state length.' }
        $bytes = [byte[]]::new([int]$stream.Length)
        $count = 0
        while ($count -lt $bytes.Length) {
            $read = $stream.Read($bytes,$count,$bytes.Length-$count)
            if ($read -le 0) { throw 'Short update state read.' }
            $count += $read
        }
    } finally { $stream.Dispose() }
    # The XML JSON reader retains duplicate object keys, unlike ConvertFrom-Json.
    Add-Type -AssemblyName System.Runtime.Serialization
    Add-Type -AssemblyName System.Web.Extensions
    $reader = [Runtime.Serialization.Json.JsonReaderWriterFactory]::CreateJsonReader($bytes,[Xml.XmlDictionaryReaderQuotas]::Max)
    try {
        $document = [Xml.XmlDocument]::new()
        $document.Load($reader)
        foreach ($node in $document.SelectNodes('//*[@type="object"]')) {
            $keys = @{}
            foreach ($child in $node.ChildNodes) {
                if ($keys.ContainsKey($child.LocalName)) { throw 'Duplicate update state key.' }
                $keys[$child.LocalName] = $true
            }
        }
    } finally { $reader.Close() }
    $json = [Web.Script.Serialization.JavaScriptSerializer]::new()
    $json.MaxJsonLength = 4194304
    $json.RecursionLimit = 64
    return @{ Value = $json.DeserializeObject([Text.UTF8Encoding]::new($false,$true).GetString($bytes)) }
}

function Test-UpdateDeliveryTime {
    param($Value)
    if ($null -eq $Value) { return $true }
    $parsed = [DateTimeOffset]::MinValue
    return ($Value -is [string] -and $Value -match '(Z|[+-][0-9]{2}:[0-9]{2})$' -and [DateTimeOffset]::TryParse($Value,[ref]$parsed))
}

function Test-ActiveUpdateState {
    param([string]$InstallRoot,[string]$DataRoot)
    $updates = Join-Path $DataRoot 'updates'
    foreach ($root in @($InstallRoot,$DataRoot,$updates)) {
        Assert-ExistingPathChain -Path $root
        if (Test-Path -LiteralPath $root) { Assert-UpdateGateAcl -Path $root -ServicingInstallRoot:($root -eq $InstallRoot) }
    }
    $active = $false
    $versionPattern = '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:[-+][0-9A-Za-z.-]+)?$'
    $leaves = @(
        @((Join-Path $updates 'pending_update.json'),16384,@('operation_id','version')),
        @((Join-Path $updates 'startup-attempt.json'),4096,@('operation_id','version','attempt_id')),
        @((Join-Path $updates 'terminal-outcome.json'),4096,@('operation_id','reported_version','status','safe_code')),
        @((Join-Path $InstallRoot 'current-restore.json'),4096,@('version')),
        @((Join-Path $InstallRoot 'selector-transition.json'),16384,@('operation_id','attempt_id','candidate','previous_bytes','status'))
    )
    foreach ($leaf in $leaves) {
        $state = Read-UpdateGateState -Path $leaf[0] -Limit $leaf[1]
        if ($null -ne $state) {
            if ($state.Value -isnot [Collections.IDictionary]) { throw 'Invalid lifecycle state.' }
            foreach ($key in $leaf[2]) {
                if (-not $state.Value.ContainsKey($key) -or $null -eq $state.Value[$key] -or $state.Value[$key] -ceq '') { throw 'Invalid lifecycle identity.' }
            }
            foreach ($key in $leaf[2]) {
                $value = $state.Value[$key]
                if ($key -eq 'candidate') {
                    if ($value -isnot [Collections.IDictionary] -or -not $value.ContainsKey('version') -or $value.version -isnot [string] -or $value.version -cnotmatch $versionPattern) { throw 'Invalid candidate identity.' }
                } elseif ($value -isnot [string] -or $value.Length -lt 1 -or $value.Length -gt 8192) { throw 'Invalid lifecycle field.' }
            }
            foreach ($key in @('version','reported_version')) {
                if ($state.Value.ContainsKey($key) -and ($state.Value[$key] -isnot [string] -or $state.Value[$key] -cnotmatch $versionPattern)) { throw 'Invalid lifecycle version.' }
            }
            if ($state.Value.ContainsKey('status')) {
                $allowed = if ($leaf[0] -eq (Join-Path $InstallRoot 'selector-transition.json')) { @('prepared','accepted') } else { @('failed','rolled_back') }
                if ($state.Value.status -cnotin $allowed) { throw 'Invalid lifecycle status.' }
            }
            $active = $true
        }
    }
    $idPattern = '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    $versionPattern = '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:[-+][0-9A-Za-z.-]+)?$'
    $codes = @{failed='launcher_apply_failed'; rolled_back='launcher_rolled_back'; applied='post_restart_handshake_confirmed'}
    $delivered = @{}; $keys = @{}; $identities = @{}
    $state = Read-UpdateGateState -Path (Join-Path $updates 'endpoint_update_reports.json') -Limit 4194304
    if ($null -ne $state) {
        if ($state.Value -isnot [array]) { throw 'Invalid report journal.' }
        foreach ($record in $state.Value) {
            if ($record -isnot [Collections.IDictionary] -or [string]::Join('|',@($record.Keys | Sort-Object)) -ne 'delivered_at|operation_id|report_key|reported_version|safe_code|status') { throw 'Invalid report fields.' }
            $identity = [string]::Join('|',@($record.operation_id,$record.status,$record.reported_version,$record.safe_code))
            if ($record.operation_id -isnot [string] -or $record.operation_id -cnotmatch $idPattern -or $record.report_key -isnot [string] -or $record.report_key -cnotmatch '^[0-9a-f]{32}$' -or $record.reported_version -isnot [string] -or $record.reported_version -cnotmatch $versionPattern -or $record.status -isnot [string] -or -not $codes.ContainsKey($record.status) -or $record.safe_code -cne $codes[$record.status] -or -not (Test-UpdateDeliveryTime $record.delivered_at) -or $keys.ContainsKey($record.report_key) -or $identities.ContainsKey($identity)) { throw 'Invalid report identity.' }
            $keys[$record.report_key]=$true; $identities[$identity]=$true
            if ($null -eq $record.delivered_at) { $active=$true } else { $delivered[$record.operation_id]=$true }
        }
    }
    $seen = @{}
    $state = Read-UpdateGateState -Path (Join-Path $updates 'endpoint_update_state.json') -Limit 262144
    if ($null -ne $state) {
        if ($state.Value -isnot [array]) { throw 'Invalid handoff journal.' }
        foreach ($record in $state.Value) {
            if ($record -isnot [Collections.IDictionary] -or [string]::Join('|',@($record.Keys | Sort-Object)) -ne 'assigned_version|operation_id|rollback_version|scheduled_ack_delivered_at') { throw 'Invalid handoff fields.' }
            if ($record.operation_id -isnot [string] -or $record.operation_id -cnotmatch $idPattern -or $record.assigned_version -isnot [string] -or $record.assigned_version -cnotmatch $versionPattern -or $record.rollback_version -isnot [string] -or $record.rollback_version -cnotmatch $versionPattern -or -not (Test-UpdateDeliveryTime $record.scheduled_ack_delivered_at) -or $seen.ContainsKey($record.operation_id)) { throw 'Invalid handoff identity.' }
            $seen[$record.operation_id]=$true
            if (-not $delivered.ContainsKey($record.operation_id)) { $active=$true }
        }
    }
    return $active
}

$principal = [Security.Principal.WindowsPrincipal]([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Administrator rights are required.'
}

Assert-RegularNonReparseFile -Path $MsiPath -Label 'MSI'
Assert-ExistingPathChain -Path $MsiPath
Assert-ExistingPathChain -Path $ReleaseManifest
$manifest = Read-ReleaseManifest -Path $ReleaseManifest
$inputHash = (Get-FileHash -LiteralPath $MsiPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($inputHash -ne [string]$manifest.package_sha256) {
    throw 'MSI SHA-256 does not match release manifest.'
}

$updateMutex = $null
$transactionOwned = $false
try {
    try {
        $updateMutex = New-UpdateTransaction
        Assert-UpdateTransactionSecurity -Mutex $updateMutex
        try { $transactionOwned = $updateMutex.WaitOne(30000) }
        catch [Threading.AbandonedMutexException] { $transactionOwned = $true }
        if (-not $transactionOwned) { exit 61 }
        Assert-UpdateTransactionSecurity -Mutex $updateMutex
        $gateInstallRoot = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)) 'Endpoint Platform\Agent'
        $gateDataRoot = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'Endpoint Platform\Agent'
        if (Test-ActiveUpdateState -InstallRoot $gateInstallRoot -DataRoot $gateDataRoot) { exit 61 }
        $installerStateRoot = Join-Path (Split-Path -Parent $gateInstallRoot) 'installer-state'
        $interruptedFence = Read-InstallerFence -Root $installerStateRoot
        $recoveryLocator=$null
        if ($Operation -eq 'RecoverInterruptedInstall') { $recoveryLocator=Read-CompoundRecoveryLocator $installerStateRoot $manifest }
        if ($null -ne $interruptedFence -and $Operation -notin @('RecoverInterruptedInstall','RecoverStagedUpdate')) { exit 61 }
        if ($Operation -eq 'RecoverInterruptedInstall' -and $null -eq $interruptedFence -and $null -eq $recoveryLocator) { exit 61 }
        if($Operation -eq 'RecoverStagedUpdate'){
            if($StagedOperationId -cnotmatch '^[0-9a-f-]{36}$'){throw 'RECOVERY_REQUIRED'}
            $stage=Read-UpdateGateState -Path (Join-Path $installerStateRoot 'staged-update.json') -Limit 65536
            if($null -eq $stage -or $stage.Value.binding.operation_id -cne $StagedOperationId -or $stage.Value.binding.new_release.package_sha256 -cne $manifest.package_sha256){throw 'RECOVERY_REQUIRED'}
            $recoveryLocator=Get-StagedForwardRecoveryLocator -Phase $stage.Value.phase -Fence $interruptedFence -Root $installerStateRoot -Manifest $manifest
            if($null -ne $interruptedFence -or $null -ne $recoveryLocator){
                if($stage.Value.phase -cne 'switching'){throw 'RECOVERY_REQUIRED'}
                $Operation='RecoverInterruptedInstall'
            }
        }
        if ($null -eq $recoveryLocator -and $null -ne $interruptedFence -and ($interruptedFence.package.sha256 -cne $manifest.package_sha256 -or $interruptedFence.package.product_code -cne $manifest.product_code -or $interruptedFence.package.version -cne $manifest.version -or $interruptedFence.package.source_revision -cne $manifest.source_revision)) { throw 'PROVENANCE_CONFLICT' }
    } catch {
        if ($_.Exception.Message -eq 'PROVENANCE_CONFLICT') { exit 63 }
        Write-Error 'UPDATE_STATE_INVALID' -ErrorAction Continue; exit 62
    }

$programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
$packageRoot = Join-Path $programFiles 'Endpoint Platform'
$executionCacheRoot = Join-Path $packageRoot 'installer-cache'
$executionCacheDirectory = Join-Path $executionCacheRoot "msi-$($manifest.package_sha256)"
$executionCachePath = Join-Path $executionCacheDirectory 'EndpointAgent.msi'
Assert-ExistingPathChain -Path $programFiles
if (-not (Test-Path -LiteralPath $packageRoot)) {
    New-Item -ItemType Directory -Path $packageRoot -Force | Out-Null
}
Assert-ExistingPathChain -Path $packageRoot
if (-not (Test-Path -LiteralPath $executionCacheRoot)) {
    New-ProtectedDirectory -Path $executionCacheRoot
}
Assert-InstallerCacheProtection -Path $executionCacheRoot
if (-not (Test-Path -LiteralPath $executionCacheDirectory)) {
    New-ProtectedDirectory -Path $executionCacheDirectory
}
Assert-InstallerCacheProtection -Path $executionCacheDirectory

Initialize-InstallerBridgeTypes
if (Test-Path -LiteralPath $executionCachePath) {
    Assert-CacheArtifactProtection -Path $executionCachePath
    if ((Get-FileHash -LiteralPath $executionCachePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $inputHash) {
        throw 'Existing MSI cache does not match release manifest.'
    }
}
else {
    [EndpointInstallerBridge.PackageHelper]::CopyCacheArtifact($MsiPath,$executionCachePath)
    Set-CacheArtifactProtection -Path $executionCachePath
}
if ((Get-FileHash -LiteralPath $executionCachePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $inputHash) {
    throw 'MSI cache SHA-256 does not match release manifest.'
}
Assert-InstallerCacheProtection -Path $executionCacheRoot
Assert-InstallerCacheProtection -Path $executionCacheDirectory
Assert-CacheArtifactProtection -Path $executionCachePath

Initialize-InstallerBridgeTypes
$packagePin = [IO.File]::Open($executionCachePath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
$coreArchivePin = $null
$helperPin = $null
$bridge = $null
$trialBridge = $null
$stagedRecoveryBridge = $null
$stagedRecoveryObserved = $null
$oldBridge = $null
$preparedOldBridge = $null
$oldPackagePin = $null
$oldHelperPin = $null
$preloadedOldHash = $null
$previousServiceStates = Get-ManagedAgentServiceStates
$stoppedBySetup = @{}
$restorePolicy = @{ LateOperation = $false }
$installationCompleted = $false
$nativeStarted = $false
$nativeExit = 0
$stagedOnline = $false
$recoveredMustRollback = $false
try {
    if ($CoreArchivePath) {
        Assert-RegularNonReparseFile -Path $CoreArchivePath -Label 'Core archive'
        Assert-ExistingPathChain -Path $CoreArchivePath
        $archiveInputPin=[IO.File]::Open($CoreArchivePath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        try {
            if ($archiveInputPin.Length -le 0 -or $archiveInputPin.Length -gt 536870912) { throw 'PROVENANCE_CONFLICT' }
            $archiveHash=(Get-FileHash -LiteralPath $CoreArchivePath -Algorithm SHA256).Hash
            $archiveCachePath=Join-Path $executionCacheDirectory 'EndpointCore.zip'
            if (Test-Path -LiteralPath $archiveCachePath) {
                Assert-CacheArtifactProtection $archiveCachePath
                if ((Get-FileHash -LiteralPath $archiveCachePath -Algorithm SHA256).Hash -cne $archiveHash) { throw 'PROVENANCE_CONFLICT' }
            } else {
                [EndpointInstallerBridge.PackageHelper]::CopyCacheArtifact($CoreArchivePath,$archiveCachePath)
                Set-CacheArtifactProtection $archiveCachePath
            }
            Assert-CacheArtifactProtection $archiveCachePath
            $coreArchivePin=[IO.File]::Open($archiveCachePath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
            if ((Get-FileHash -LiteralPath $archiveCachePath -Algorithm SHA256).Hash -cne $archiveHash) { throw 'PROVENANCE_CONFLICT' }
        } finally { $archiveInputPin.Dispose() }
    }
    $helperPath = Join-Path $executionCacheDirectory 'endpoint-installer-host.exe'
    if (Test-Path -LiteralPath $helperPath) { Assert-CacheArtifactProtection $helperPath }
    $helperHash = [EndpointInstallerBridge.PackageHelper]::Extract($executionCachePath,$helperPath)
    Assert-CacheArtifactProtection $helperPath
    $helperPin = [IO.File]::Open($helperPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    if($StagedOperationId -cmatch '^[0-9a-f-]{36}$'){
        $stagedRecoveryBridge=New-InstallerBridge -Manifest $manifest -HelperPath $helperPath -HelperHash $helperHash -StateRoot $installerStateRoot -ServiceStates $previousServiceStates -Intent 'install' -TransactionId $StagedOperationId
        $stagedRecoveryObserved=Invoke-InstallerHelper -Bridge $stagedRecoveryBridge -Phase 'inspect-staged-recovery'
    }
    if($Operation -eq 'RecoverStagedUpdate'){
        $bridge=$stagedRecoveryBridge;$stagedRecoveryBridge=$null
        # The exact fresh bridge is retained for trial/terminal evidence.
        $nativeExit=Invoke-StagedRecovery -Bridge $bridge -Manifest $manifest -HelperPath $helperPath -HelperHash $helperHash -StateRoot $installerStateRoot -CacheRoot $executionCacheRoot -OperationId $StagedOperationId -InstallRoot $gateInstallRoot -CandidateMedia $packagePin
        $installationCompleted=$true;exit $nativeExit
    }
    $intent = switch ($Operation) {
        'RetireInitialRuntime' { 'retire-initial-runtime' }
        'Uninstall' { 'uninstall' }
        'RecoverInterruptedInstall' { if ($null -ne $recoveryLocator) { 'install' } else { $interruptedFence.operation } }
        default { 'install' }
    }
    if ($null -ne $recoveryLocator) {
        $bridge=New-InstallerBridge -Manifest $manifest -HelperPath $helperPath -HelperHash $helperHash -StateRoot $installerStateRoot -ServiceStates $previousServiceStates -Intent 'install' -TransactionId $recoveryLocator.new_transaction_id -RecoveryParent $recoveryLocator.upgrade_id
        $initial=Invoke-InstallerHelper -Bridge $bridge -Phase 'inspect-compound'
    } else {
        $bridge = New-InstallerBridge -Manifest $manifest -HelperPath $helperPath -HelperHash $helperHash -StateRoot $installerStateRoot -ServiceStates $previousServiceStates -Fence $interruptedFence -Intent $intent
        $initial = Invoke-InstallerHelper -Bridge $bridge -Phase 'inspect'
    }
    if ($intent -ceq 'install' -and $null -eq $recoveryLocator -and $null -eq $interruptedFence -and
        $null -ne $initial.PSObject.Properties['foundation_release'] -and
        $initial.selected -is [string] -and $initial.selected -cmatch '^[0-9a-f]{64}$' -and
        [Version]$initial.foundation_release.version -lt [Version]$manifest.version) {
        $bridge=Invoke-StagedOnlinePreparation -Bridge $bridge -Manifest $manifest -HelperPath $helperPath `
            -HelperHash $helperHash -StateRoot $installerStateRoot -ServiceStates $previousServiceStates -Selection $initial -CacheRoot $executionCacheRoot -PrepareRecovery {param($stagedBridge) Register-StagedRecoveryTask -Bridge $stagedBridge -SetupImage $SetupImagePath -WrapperPath $PSCommandPath -ManifestPath $ReleaseManifest -CacheRoot $executionCacheRoot -StateRoot $installerStateRoot -ServiceStates $previousServiceStates}
        $stagedOnline=$true
        $script:InstallerLaunchBroker=Start-InstallerLaunchBroker $bridge
        if ($null -eq $initial.PSObject.Properties['foundation_kind'] -or $initial.foundation_kind -cne 'canonical-legacy') {
            $oldMedia=Open-StagedPredecessorMedia $initial.foundation_release $installerStateRoot $executionCacheRoot
            $oldPath=$oldMedia.PackagePath;$oldPackagePin=$oldMedia.PackagePin
            $oldHelperPath=$oldMedia.HelperPath;$oldHelperHash=$oldMedia.HelperHash;$oldHelperPin=$oldMedia.HelperPin
            $preloadedOldHash=$oldMedia.PackageHash
        }
    }
    if ($intent -ne 'retire-initial-runtime') {
        Stop-ManagedAgentServices -PreviousStates $previousServiceStates -StoppedBySetup $stoppedBySetup -AfterAgentStopped {
            $restorePolicy.LateOperation = $true
            try { $active = Test-ActiveUpdateState -InstallRoot $gateInstallRoot -DataRoot $gateDataRoot }
            catch { throw 'UPDATE_STATE_INVALID' }
            if ($active) { throw 'UPDATE_IN_PROGRESS' }
            $settled = Invoke-InstallerHelper -Bridge $bridge -Phase $(if($null -ne $recoveryLocator){'inspect-compound'}else{'inspect'})
            if ($settled.selected -cne $initial.selected -or $settled.previous -cne $initial.previous) { throw 'PROVENANCE_CONFLICT' }
            $restorePolicy.LateOperation = $false
        }
    }
    try { $active = Test-ActiveUpdateState -InstallRoot $gateInstallRoot -DataRoot $gateDataRoot }
    catch { $restorePolicy.LateOperation = $true; throw 'UPDATE_STATE_INVALID' }
    if ($active) { $restorePolicy.LateOperation = $true; throw 'UPDATE_IN_PROGRESS' }
    if ($stagedOnline) {
        $bridge.Policy.MarkQuiescent()
        $sealed=Invoke-InstallerHelper -Bridge $bridge -Phase 'seal-staged-switch'
        if ($sealed.result -cne 'staged-switch-sealed' -or $sealed.phase -cne 'switching' -or
            $sealed.operation_id -cne $bridge.TransactionId) { throw 'PROVENANCE_CONFLICT' }
    }
    $bootstrapBridge = $bridge
    $compoundDetails=$null
    $compoundMode='fresh'
    if ($null -ne $recoveryLocator) {
        if ($initial.parent_upgrade_id -cne $recoveryLocator.upgrade_id -or $initial.transaction_id -cne $recoveryLocator.new_transaction_id -or $initial.mode -notin @('replace-foundation','repair-successor')) { throw 'PROVENANCE_CONFLICT' }
        $compoundMode=$initial.mode;$oldManifest=$initial.old.package
        $oldPath=Get-CompoundOldMedia $oldManifest $installerStateRoot $executionCacheRoot
        $oldPackagePin=[IO.File]::Open($oldPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $oldHelperPath=Join-Path (Split-Path $oldPath -Parent) 'endpoint-installer-host.exe'
        $oldHelperHash=[EndpointInstallerBridge.PackageHelper]::Extract($oldPath,$oldHelperPath)
        Assert-CacheArtifactProtection $oldHelperPath
        if ($oldHelperHash -cne $initial.old.helper_sha256) { throw 'PROVENANCE_CONFLICT' }
        $oldHelperPin=[IO.File]::Open($oldHelperPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $oldBinding=@{transaction_id=$initial.old.transaction_id;session_id=$initial.old.session_id;package=$oldManifest;helper_sha256=$oldHelperHash}
        if ($compoundMode -ceq 'replace-foundation') {
            if ($null -eq $interruptedFence -or $interruptedFence.transaction_id -cne $initial.old.transaction_id) { throw 'PROVENANCE_CONFLICT' }
            $oldBridge=New-InstallerBridge -Manifest $oldManifest -HelperPath $oldHelperPath -HelperHash $oldHelperHash -StateRoot $installerStateRoot -ServiceStates $previousServiceStates -Fence $interruptedFence -Intent 'uninstall'
            $oldBridge.Policy.MarkQuiescent();Invoke-InstallerHelper $oldBridge 'prepare' | Out-Null
            $oldBinding.session_id=$oldBridge.SessionId
        }
        $compoundDetails=@{upgrade_id=[Guid]::NewGuid().ToString('D');old=$oldBinding;recovery=@{
            original_upgrade_id=$initial.original_upgrade_id;original_plan_sha256=$initial.original_plan_sha256;
            predecessor_upgrade_id=$initial.parent_upgrade_id;predecessor_plan_sha256=$initial.predecessor_plan_sha256;mode=$compoundMode}}
        if ($null -ne $initial.PSObject.Properties['prepared_old']) { $compoundDetails.prepared_old=$initial.prepared_old }
    } elseif ($intent -eq 'install' -and $null -eq $interruptedFence -and $null -ne $initial.PSObject.Properties['foundation_release']) {
        $oldManifest=$initial.foundation_release
        if ($oldManifest.package_sha256 -cne $manifest.package_sha256) {
            if ([Version]$oldManifest.version -ge [Version]$manifest.version -or $oldManifest.product_code -ceq $manifest.product_code) { throw 'PROVENANCE_CONFLICT' }
            if ($null -eq $initial.PSObject.Properties['foundation_kind'] -or $initial.foundation_kind -cne 'canonical-legacy') {
            if ($null -ne $oldPackagePin) {
                if ($preloadedOldHash -cne $oldManifest.package_sha256 -or $null -eq $oldHelperPin) { throw 'PROVENANCE_CONFLICT' }
                # Exact paths/bytes remain pinned since online preparation.
                # Native driver and old helpers repeat their ordinary admission.
            } else {
            $oldPath=Get-CompoundOldMedia $oldManifest $installerStateRoot $executionCacheRoot
            $oldPackagePin=[IO.File]::Open($oldPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
            $oldHelperPath=Join-Path (Split-Path $oldPath -Parent) 'endpoint-installer-host.exe'
            if (Test-Path -LiteralPath $oldHelperPath) { Assert-CacheArtifactProtection $oldHelperPath }
            $oldHelperHash=[EndpointInstallerBridge.PackageHelper]::Extract($oldPath,$oldHelperPath)
            Assert-CacheArtifactProtection $oldHelperPath
            $oldHelperPin=[IO.File]::Open($oldHelperPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
            }
            $oldBridge=New-InstallerBridge -Manifest $oldManifest -HelperPath $oldHelperPath -HelperHash $oldHelperHash -StateRoot $installerStateRoot -ServiceStates $previousServiceStates -Intent 'uninstall' -Selection $initial
            $oldBridge.Policy.MarkQuiescent()
            Invoke-InstallerHelper $oldBridge 'prepare' | Out-Null
            $preparedOldBridge=$oldBridge
            $preparedRole=Save-PreparedOldRemoval $preparedOldBridge $installerStateRoot
            $oldPreparedFence=Read-InstallerFence $installerStateRoot
            if ($null -eq $oldPreparedFence -or $oldPreparedFence.transaction_id -cne $preparedOldBridge.TransactionId -or
                $oldPreparedFence.phase -cne 'msi-starting') { throw 'RECOVERY_REQUIRED' }
            $oldBridge=New-InstallerBridge -Manifest $oldManifest -HelperPath $oldHelperPath -HelperHash $oldHelperHash -StateRoot $installerStateRoot -ServiceStates $previousServiceStates -Fence $oldPreparedFence -Intent 'uninstall'
            $oldBridge.Policy.MarkQuiescent()
            Invoke-InstallerHelper $oldBridge 'prepare' | Out-Null
            $compoundDetails=@{upgrade_id=[Guid]::NewGuid().ToString('D');old=@{
                transaction_id=$oldBridge.TransactionId;session_id=$oldBridge.SessionId;
                package=$oldManifest;helper_sha256=$oldHelperHash};prepared_old=$preparedRole}
            }
        }
    }
    $newFence=$(if($null -ne $recoveryLocator){$null}else{$interruptedFence})
    $bridge = New-InstallerBridge -Manifest $manifest -HelperPath $helperPath -HelperHash $helperHash -StateRoot $installerStateRoot -ServiceStates $previousServiceStates -Fence $newFence -Intent $intent -TransactionId $bootstrapBridge.TransactionId -Selection $initial -Compound $compoundDetails
    $bootstrapBridge.Policy.OwnerLost()
    $bootstrapBridge.Channel.Dispose()
    foreach ($peer in $bootstrapBridge.Peers) { $peer.Dispose() }
    $bootstrapBridge.Owner.Dispose()
    $bridge.Policy.MarkQuiescent()
    if ($stagedOnline) {
        $adopted=Invoke-InstallerHelper -Bridge $bridge -Phase 'adopt-staged-switch'
        if ($adopted.result -cne 'staged-session-adopted' -or $adopted.phase -cne 'switching' -or
            $adopted.operation_id -cne $bridge.TransactionId) { throw 'OWNER_AUTH_FAILED' }
    }
    $preparation=Invoke-InstallerHelper -Bridge $bridge -Phase 'prepare'
    if ($null -ne $preparation.PSObject.Properties['legacy_archive_id']) {
        if ($null -ne $compoundDetails -or $null -ne $oldPackagePin -or
            $preparation.legacy_archive_id -cnotmatch '^[0-9a-f]{64}$' -or
            $preparation.legacy_release.package_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [Version]$preparation.legacy_release.version -ge [Version]$manifest.version) { throw 'PROVENANCE_CONFLICT' }
        $oldPath=Join-Path $installerStateRoot ('retained\'+$preparation.legacy_archive_id+'\package.msi')
        Assert-InstallerPublicStateAcl $oldPath
        $oldPackagePin=[IO.File]::Open($oldPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $sha=[Security.Cryptography.SHA256]::Create()
        try { if ([EndpointInstallerBridge.Policy]::Hex($sha.ComputeHash($oldPackagePin)) -cne $preparation.legacy_release.package_sha256) { throw 'PROVENANCE_CONFLICT' } }
        finally { $sha.Dispose() }
    }
    # Re-read the protected durable fence before the first native invocation.
    $preparedRoot=$installerStateRoot
    if ($null -ne $compoundDetails) { $preparedRoot=Join-Path $installerStateRoot ('children\'+$bridge.TransactionId) }
    if ($null -ne $recoveryLocator) { $preparedRoot=Join-Path $preparedRoot $compoundDetails.upgrade_id }
    $prepared = Read-InstallerFence -Root $preparedRoot
    if ($null -eq $prepared -or $prepared.transaction_id -cne $bridge.TransactionId -or $prepared.package.sha256 -cne $inputHash) { throw 'RECOVERY_REQUIRED' }
    Start-WindowsInstaller
    if ($null -ne $compoundDetails) {
        $nativeStarted=$true
        Invoke-CompoundFoundationUpgrade -OldBridge $oldBridge -NewBridge $bridge -PreparedOldBridge $preparedOldBridge -OldMedia $oldPackagePin -NewMedia $packagePin -SuccessorProduct $manifest.product_code -Mode $compoundMode
    } else {
    $msiArguments = @('/i', ('"{0}"' -f $executionCachePath), '/qn', '/norestart', ('ENDPOINT_INSTALLER_SESSION=' + $bridge.SessionId))
    if ($bridge.Capability.uninstall_finalization) {
        $msiArguments += 'ENDPOINT_UNINSTALL_FINALIZE=1'
    } elseif ($intent -eq 'retire-initial-runtime') {
        # REMOVE alone leaves the unchanged foundation action UNKNOWN (-1).
        # Cost it explicitly as LOCAL; the existing owner guard still requires
        # foundation LOCAL -> LOCAL and only the initial runtime ABSENT.
        $msiArguments += @('ADDLOCAL=EndpointAgentFeature','REMOVE=EndpointAgentInitialRuntimeFeature')
    } elseif ($intent -eq 'uninstall') {
        $msiArguments += 'REMOVE=ALL'
    } else {
        $msiArguments += 'ADDLOCAL=EndpointAgentFeature,EndpointAgentInitialRuntimeFeature'
        if ($null -ne $interruptedFence) {
            if ($preparation.new_product_state -notin @(-1,5)) { throw 'PROVENANCE_CONFLICT' }
            if ($preparation.new_product_state -eq 5) { $msiArguments += @('REINSTALL=ALL','REINSTALLMODE=amus') }
        }
    }
    $nativeStarted = $true
    $msiPath = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::System)) 'msiexec.exe'
    Assert-ExistingPathChain $bridge.LaunchDirectory
    Assert-InstallerCacheProtection $bridge.LaunchDirectory
    $nativeInfo = [EndpointInstallerBridge.LaunchDirectory]::StartInfo($msiPath, [string]::Join(' ', $msiArguments), $bridge.LaunchDirectory)
    $installer = [Diagnostics.Process]::Start($nativeInfo)
    Invoke-InstallerOwnerPump -Bridge $bridge -Process $installer -Phase 'native' -Msi | Out-Null
    $nativeExit = $installer.ExitCode
    if ($nativeExit -in @(3010,1641)) {
        if($stagedOnline){Invoke-InstallerHelper -Bridge $bridge -Phase ('record-staged-reboot-'+$nativeExit) | Out-Null}
        exit $nativeExit
    }
    Invoke-InstallerHelper -Bridge $bridge -Phase 'reconcile' | Out-Null
    Invoke-InstallerHelper -Bridge $bridge -Phase 'finish' | Out-Null
    }
    if ($null -ne (Read-InstallerFence -Root $installerStateRoot)) { throw 'RECOVERY_REQUIRED' }
    if ($intent -eq 'install' -and $null -eq $compoundDetails) { Invoke-InstallerHelper -Bridge $bridge -Phase 'verify-settled' | Out-Null }
    if($null -ne $stagedRecoveryBridge -and $nativeExit -eq 0){
        $proof=[EndpointInstallerBridge.NativeTransaction]::EstablishSettlement($stagedRecoveryBridge.Owner)
        $stagedRecoveryBridge.Policy.AuthorizeStagedRecovery($proof)
        $adopted=Invoke-InstallerHelper -Bridge $stagedRecoveryBridge -Phase 'recover-staged-owner'
        if($adopted.action -cnotin @('trial-required','rollback-required') -or $adopted.operation_id -cne $StagedOperationId){throw 'RECOVERY_REQUIRED'}
        $stagedOnline=$true
        $recoveredMustRollback=$adopted.action -ceq 'rollback-required'
        $previousServiceStates=ConvertTo-StagedServiceStates $stagedRecoveryObserved.service_states
        $initial=[pscustomobject]@{foundation_release=$stagedRecoveryObserved.old_release}
    }
    if ($stagedOnline -and $nativeExit -eq 0) {
        if($null -ne $stagedRecoveryBridge){$trialBridge=$stagedRecoveryBridge;$stagedRecoveryBridge=$null}
        else{$trialBridge=New-InstallerBridge -Manifest $manifest -HelperPath $helperPath -HelperHash $helperHash -StateRoot $installerStateRoot -ServiceStates $previousServiceStates -Intent 'install' -TransactionId $bridge.TransactionId -Selection $initial}
        $trialBridge.Policy.MarkQuiescent()
        if ($recoveredMustRollback -or (Invoke-StagedHealthTrial -Bridge $trialBridge -InstallRoot $gateInstallRoot) -cne 'accepted') {
            $rollback=Invoke-StagedFoundationRollback -Manifest $manifest -HelperPath $helperPath -HelperHash $helperHash -StateRoot $installerStateRoot -CacheRoot $executionCacheRoot -ServiceStates $previousServiceStates -Selection $initial -CandidateMedia $packagePin -OperationId $trialBridge.TransactionId -InstallRoot $gateInstallRoot
            if ($rollback -ceq 'rolled-back') { $nativeExit=67 }
            elseif ($rollback -cne 'accepted') { throw 'RECOVERY_REQUIRED' }
        }
    } elseif ($intent -eq 'install' -and $nativeExit -eq 0) { Start-VerifiedBrowserPolicy;Start-ManagedEndpointAgent }
    if($stagedOnline -and $nativeExit -in @(0,67)){Complete-StagedTerminalCleanup $trialBridge $previousServiceStates $installerStateRoot}
    $installationCompleted = $true
    if ($nativeExit -in @(67,3010,1641)) { exit $nativeExit }
}
catch {
    if ($_.Exception.Message -eq 'UPDATE_IN_PROGRESS') { exit 61 }
    if ($_.Exception.Message -eq 'UPDATE_STATE_INVALID') { exit 62 }
    if ($_.Exception.Message -eq 'PROVENANCE_CONFLICT') { exit 63 }
    throw
}
finally {
    try {
    if (-not $installationCompleted -and -not $nativeStarted -and $null -eq $interruptedFence -and $null -eq (Read-InstallerFence -Root $installerStateRoot)) {
        $canRestore = {
            $worker = Get-Service -Name 'EndpointAgentUpdater' -ErrorAction SilentlyContinue
            if ($null -ne $worker -and $worker.Status -ne [ServiceProcess.ServiceControllerStatus]::Stopped) { return $false }
            if (Test-ActiveUpdateState -InstallRoot $gateInstallRoot -DataRoot $gateDataRoot) { return $false }
            $verified = Invoke-InstallerHelper -Bridge $bridge -Phase 'verify-settled'
            return $verified.settled -eq $true
        }
        $restoration = Restore-ManagedAgentServices -PreviousStates $previousServiceStates -StoppedBySetup $stoppedBySetup -RequireSettled:$restorePolicy.LateOperation -CanRestore $canRestore
        if ($restoration -eq 'deferred') { Write-Warning 'MANAGED_SERVICE_RESTORATION_DEFERRED' }
    } elseif (-not $installationCompleted) {
        Write-Warning 'MANAGED_SERVICE_RESTORATION_DEFERRED: RECOVERY_REQUIRED'
    }
    } catch {
        # Restoration is best effort after an already classified failure.
        # Unavailable evidence must not erase UPDATE_IN_PROGRESS/invalid-state.
        Write-Warning 'MANAGED_SERVICE_RESTORATION_DEFERRED: EVIDENCE_OR_SERVICE_UNAVAILABLE'
    }
    if($null -ne $stagedRecoveryBridge){
        $stagedRecoveryBridge.Policy.OwnerLost();$stagedRecoveryBridge.Channel.Dispose()
        foreach($peer in $stagedRecoveryBridge.Peers){$peer.Dispose()}
        $stagedRecoveryBridge.Owner.Dispose()
    }
    if ($null -ne $trialBridge) {
        $trialBridge.Policy.OwnerLost()
        $trialBridge.Channel.Dispose()
        foreach ($peer in $trialBridge.Peers) { $peer.Dispose() }
        $trialBridge.Owner.Dispose()
    }
    if ($null -ne $bridge) {
        $bridge.Channel.Dispose()
        foreach ($peer in $bridge.Peers) { $peer.Dispose() }
        $bridge.Owner.Dispose()
    }
    if ($null -ne $oldBridge) {
        $oldBridge.Channel.Dispose()
        foreach ($peer in $oldBridge.Peers) { $peer.Dispose() }
        $oldBridge.Owner.Dispose()
    }
    if ($null -ne $preparedOldBridge) {
        $preparedOldBridge.Policy.OwnerLost()
        $preparedOldBridge.Channel.Dispose()
        foreach ($peer in $preparedOldBridge.Peers) { $peer.Dispose() }
        $preparedOldBridge.Owner.Dispose()
    }
    Stop-InstallerLaunchBroker $script:InstallerLaunchBroker
    $script:InstallerLaunchBroker=$null
    if ($null -ne $oldHelperPin) { $oldHelperPin.Dispose() }
    if ($null -ne $oldPackagePin) { $oldPackagePin.Dispose() }
    if ($null -ne $helperPin) { $helperPin.Dispose() }
    $packagePin.Dispose()
    if ($null -ne $coreArchivePin) { $coreArchivePin.Dispose() }
    try {
        if ($script:InstallerPhaseMetrics.Count -gt 0) {
            $metricsPath=Join-Path $installerStateRoot ('owner-phase-metrics-'+[Guid]::NewGuid().ToString('D')+'.json')
            [EndpointInstallerBridge.PackageHelper]::WriteCapability($metricsPath,
                [Text.Encoding]::UTF8.GetBytes((@($script:InstallerPhaseMetrics.ToArray())|ConvertTo-Json -Depth 4 -Compress)))
        }
    } catch { Write-Warning 'Installer timing diagnostics unavailable.' }
}

} finally {
    if ($transactionOwned) { $updateMutex.ReleaseMutex() }
    if ($null -ne $updateMutex) { $updateMutex.Dispose() }
}
