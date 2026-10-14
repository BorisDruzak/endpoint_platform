[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$MsiPath,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ReleaseManifest,
    [ValidateSet('Install','RetireInitialRuntime','RecoverInterruptedInstall','Uninstall')]
    [string]$Operation = 'Install'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$SystemSid = 'S-1-5-18'
$AdministratorsSid = 'S-1-5-32-544'
$CacheSids = @($SystemSid, $AdministratorsSid)
$ManagedServiceNames = @('EndpointAgent', 'EndpointAgentUpdater', 'EndpointBrowserPolicy')
$WindowsInstallerServiceName = 'msiserver'
$ManagedServiceTimeout = [TimeSpan]::FromSeconds(45)

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
            if(read==null) read=stream.BeginRead(input,offset,target-offset,null,null);
            if(!read.IsCompleted) return null;
            int count=stream.EndRead(read);read=null;
            if(count<=0) throw new IOException("OWNER_AUTH_FAILED");
            offset+=count;
            if(offset!=target) return null;
            if(header) {
                int length=BitConverter.ToInt32(input,0);
                if(length<=0 || length>32768) throw new IOException("OWNER_AUTH_FAILED");
                input=new byte[length];target=length;offset=0;header=false;return null;
            }
            var result=input;input=new byte[4];target=4;offset=0;header=true;return result;
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
        private int? nativeResult;
        private CompoundPolicy compound;
        private SuccessorRepairPolicy repair;
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
            if (!alive || preparedRemovalSealed || (compound!=null && !compound.OwnerActive) || (repair!=null && !repair.OwnerActive) || peer==null || !peer.Elevated || peer.Hash!=HelperHash ||
                (peer.Sid!=Owner.Sid && peer.Sid!="S-1-5-18")) Fail();
        }
        public void RegisterHelper(Identity peer,string phase) {
            CheckPeer(peer);
            if(recoveryLocator && phase!="inspect-compound") Fail();
            if(compound!=null && !compound.AllowsHelper(this,phase)) Fail();
            if(repair!=null && !repair.AllowsHelper(phase)) Fail();
            if (phase!="inspect" && phase!="inspect-compound" && phase!="prepare" && phase!="reconcile" && phase!="finish" && phase!="verify-settled" &&
                !(compound!=null && (phase=="compound-old-returned" || phase=="compound-new-returned" ||
                    phase=="compound-commit" || phase=="compound-retire" || phase=="compound-complete")) &&
                !(repair!=null && (phase=="compound-repair-returned" || phase=="compound-repair-commit" || phase=="compound-retire" || phase=="compound-complete"))) Fail();
            if (phase!="inspect" && phase!="inspect-compound" && phase!="verify-settled" && !quiescent) Fail();
            if ((phase=="reconcile" || phase=="finish") && (!nativeComplete || !nativeResult.HasValue ||
                nativeResult.Value!=0)) Fail();
            if (helpers.Count>=64 || helpers.ContainsKey(peer.Key)) Fail();
            helpers.Add(peer.Key,new Registration { Peer=peer, Phase=phase });
        }
        public void RegisterMsi(Identity peer,string operation) {
            if(preparedRemovalSealed || recoveryLocator) Fail();
            if(compound!=null && !compound.Registering) Fail();
            if(repair!=null && !repair.Registering) Fail();
            if (!alive || !quiescent || !preparedComplete || !AllHelpersComplete || msiAlive || peer==null || !peer.Elevated || operation!=Operation || nativeResult.HasValue) Fail();
            msiAlive=true;
        }
        public void MarkQuiescent() { if(!alive || !AllHelpersComplete) Fail(); quiescent=true; }
        public void MarkMsiExited(int code) {
            if(compound!=null && !compound.Settling) Fail();
            if(repair!=null && !repair.Settling) Fail();
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
                (action=="mutation" && (phase=="inspect" || phase.EndsWith("preflight",StringComparison.Ordinal) || phase=="verify-settled"))) Fail();
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
            if(value.Action=="complete" && compound!=null) compound.HelperComplete(this,value.Phase);
            if(value.Action=="complete" && repair!=null) repair.HelperComplete(value.Phase);
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
        private Policy NewPolicy { get { return policy!=null ? policy.NewPackage : repair.Package; } }
        private Identity OwnerIdentity { get { return NewPolicy.Owner; } }
        private bool AuthorityActive { get { return policy!=null ? policy.OwnerActive : repair.OwnerActive; } }
        private string OldHash { get { return policy!=null ? policy.OldPackage.PackageHash : repair.OldPackageHash; } }
        private void Revoke() { if(policy!=null)policy.OwnerLost();else repair.OwnerLost(); }
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
            : this(compound,null,retainedOwner,oldPin,newPin,successorProduct) {}
        public NativeTransaction(SuccessorRepairPolicy successorRepair,NativeProcess retainedOwner,FileStream oldPin,FileStream newPin,string successorProduct)
            : this(null,successorRepair,retainedOwner,oldPin,newPin,successorProduct) {}
        private NativeTransaction(CompoundPolicy compound,SuccessorRepairPolicy successorRepair,NativeProcess retainedOwner,FileStream oldPin,FileStream newPin,string successorProduct) {
            if((compound==null)==(successorRepair==null)) Fail();
            policy=compound;repair=successorRepair;
            string state=compound!=null ? compound.State : successorRepair.State;
            Guid parsed;
            if(retainedOwner==null || !retainedOwner.Alive || !OwnerIdentity.Same(retainedOwner.Identity) ||
                retainedOwner.Identity.Pid!=Process.GetCurrentProcess().Id || !AuthorityActive || state!="prepared" ||
                !Guid.TryParseExact(successorProduct,"B",out parsed) ||
                "{"+parsed.ToString("D").ToUpperInvariant()+"}"!=successorProduct) Fail();
            oldPath=MediaPath(oldPin,OldHash);
            newPath=MediaPath(newPin,NewPolicy.PackageHash);
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
                MediaPath(oldMedia,OldHash);MediaPath(newMedia,NewPolicy.PackageHash);
                if(PackageHelper.ProductCode(newPath)!=successor) Fail();
            } catch {
                if(oldMedia!=null) oldMedia.Dispose();if(newMedia!=null) newMedia.Dispose();
                if(module!=IntPtr.Zero) FreeLibrary(module);module=IntPtr.Zero;throw;
            }
        }
        private bool SuccessfulNativeClosure { get { return task!=null &&
            (taskKind=="end" || taskKind=="abort") && task.Status==TaskStatus.RanToCompletion && task.Result==0; } }
        private bool AuthenticatedClosure { get {
            if(taskKind!="end") return false;
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
            if(transactionOpen || task!=null || !(policy!=null ? policy.ReadyToPublish : repair.ReadyToPublish)) Fail();
            string root=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"Endpoint Platform","installer-state");
            TerminalPublication.PublishAt(root,upgradeId,NewPolicy.TransactionId,
                OldHash,NewPolicy.PackageHash,successor,sourceRevision,readyHash,CheckOwnership);
        }
        public void BeginNative() {
            CheckOwner(true);
            if(transactionOpen || task!=null || (policy!=null ? policy.State : repair.State)!="prepared") Fail();
            // Driver-owned pins remain open and unmodified until every native call,
            // delayed custom action and both bridge conversations have settled.
            MediaPath(oldMedia,OldHash);MediaPath(newMedia,NewPolicy.PackageHash);
            previousUi=MsiSetInternalUI(2,IntPtr.Zero);uiChanged=true;
            uint result=MsiBeginTransactionW("EndpointFoundation-"+NewPolicy.SessionId,0,out handle,out ownerEvent);
            if(result!=0) throw new InvalidOperationException(result==1618 ? "UPDATE_IN_PROGRESS" : "RECOVERY_REQUIRED");
            transactionOpen=true;
            if(policy!=null)policy.BeginNative();else repair.BeginNative();
        }
        private void Ready() { CheckOwner(true);if(!transactionOpen || task!=null) Fail(); }
        public void StartOldScript() {
            Ready();if(policy==null) Fail();policy.BeginOldScript();taskKind="old";
            string properties="REMOVE=ALL UPGRADINGPRODUCTCODE="+successor+" REBOOT=ReallySuppress ENDPOINT_INSTALLER_SESSION="+policy.OldPackage.SessionId;
            task=Task.Run(()=>MsiInstallProductW(oldPath,properties));
        }
        public void StartNewScript() {
            Ready();if(policy!=null)policy.BeginNewScript();else repair.BeginScript();taskKind="new";
            string properties=(repair!=null ? "REINSTALL=ALL REINSTALLMODE=amus " : "")+
                "ADDLOCAL=EndpointAgentFeature,EndpointAgentInitialRuntimeFeature REBOOT=ReallySuppress ENDPOINT_INSTALLER_SESSION="+NewPolicy.SessionId;
            task=Task.Run(()=>MsiInstallProductW(newPath,properties));
        }
        private int Result(string expected,bool authority=true) {
            CheckOwner(authority);
            if(task==null || taskKind!=expected || !task.IsCompleted) Fail();
            var completed=task;task=null;taskKind=null;
            return checked((int)completed.GetAwaiter().GetResult());
        }
        public int CompleteOldScript() { int code=Result("old");policy.OldScriptReturned(code);return code; }
        public int CompleteNewScript() { int code=Result("new");if(policy!=null)policy.NewScriptReturned(code);else repair.ScriptReturned(code);return code; }
        public void StartEnd(bool commit) {
            Ready();if(policy!=null)policy.BeginEnd(commit);else repair.BeginEnd(commit);taskKind="end";
            task=Task.Run(()=>MsiEndTransaction(commit ? 1u : 0u));
        }
        public int CompleteEnd() {
            if((policy!=null ? policy.State : repair.State)=="ending-rollback") {
                CheckPhysicalOwner(true);
                int rollback=Result("end",false);if(rollback==0) transactionOpen=false;
                // Match the abort route: consuming native rollback cannot leave
                // bridge authority active, even when the native result is zero.
                Revoke();return rollback;
            }
            int code=Result("end");if(code==0) transactionOpen=false;
            if(policy!=null)policy.EndReturned(code);else repair.EndReturned(code);return code;
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
    # Give only this pre-MSI helper a larger fixed bound; native MSI and every
    # other helper retain their existing deadline and live-owner conversation.
    $minutes = if (-not $Msi -and $Phase -ceq 'prepare') { 120 } else { 30 }
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
            $worked = Invoke-InstallerConversationStep -State $conversation
            $Process.Refresh()
            if ($Process.HasExited) {
                $activePeers = @($Bridge.Peers | Where-Object { $_.Alive })
                if ($activePeers.Count -eq 0 -and $null -eq $conversation.Acknowledgement -and $null -eq $conversation.Challenge) { break }
            }
            if (-not $worked) { Start-Sleep -Milliseconds 1 }
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

function Invoke-InstallerHelper {
    param([Parameter(Mandatory)]$Bridge,[Parameter(Mandatory)][string]$Phase)
    if ($Phase -notin @('inspect','inspect-compound','prepare','reconcile','finish','verify-settled','compound-old-returned','compound-new-returned','compound-commit','compound-retire','compound-complete','compound-repair-returned','compound-repair-commit') -or $Bridge.SessionId -cnotmatch '^[0-9a-f-]{36}$') { throw 'OWNER_AUTH_FAILED' }
    Assert-ExistingPathChain $Bridge.LaunchDirectory
    Assert-InstallerCacheProtection $Bridge.LaunchDirectory
    $info = [EndpointInstallerBridge.LaunchDirectory]::StartInfo($Bridge.HelperPath, ('--installer-phase ' + $Phase + ' --installer-session ' + $Bridge.SessionId), $Bridge.LaunchDirectory)
    $process = [Diagnostics.Process]::Start($info)
    return Invoke-InstallerOwnerPump -Bridge $Bridge -Process $process -Phase $Phase
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
        if (-not $worked) { Start-Sleep -Milliseconds 1 }
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
    param($Manifest,[string]$HelperPath,[string]$HelperHash,[string]$StateRoot,[hashtable]$ServiceStates,$Fence,[string]$Intent,[string]$TransactionId,$Selection,$Compound,[string]$RecoveryParent)
    Initialize-InstallerBridgeTypes
    New-InstallerPublicStateRoot $StateRoot
    $capabilities = Join-Path $StateRoot 'capabilities'
    if (-not (Test-Path -LiteralPath $capabilities)) { New-ProtectedDirectory $capabilities }
    Assert-InstallerCacheProtection $capabilities
    if ($null -ne $Fence) { $transactionId = $Fence.transaction_id }
    elseif (-not $TransactionId) { $transactionId = [Guid]::NewGuid().ToString('D') }
    $sessionId = [Guid]::NewGuid().ToString('D')
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
    foreach ($serviceName in @('EndpointAgent', 'EndpointAgentUpdater', 'EndpointBrowserPolicy')) {
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
            Copy-Item -LiteralPath $original -Destination $path
            Set-CacheArtifactProtection $path
        }
        Assert-CacheArtifactProtection $path
        if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $digest) { throw 'PROVENANCE_CONFLICT' }
        return $path
    } finally { $sourcePin.Dispose() }
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
        if ($null -ne $interruptedFence -and $Operation -ne 'RecoverInterruptedInstall') { exit 61 }
        if ($Operation -eq 'RecoverInterruptedInstall' -and $null -eq $interruptedFence -and $null -eq $recoveryLocator) { exit 61 }
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

if (Test-Path -LiteralPath $executionCachePath) {
    Assert-CacheArtifactProtection -Path $executionCachePath
    if ((Get-FileHash -LiteralPath $executionCachePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $inputHash) {
        throw 'Existing MSI cache does not match release manifest.'
    }
}
else {
    Copy-Item -LiteralPath $MsiPath -Destination $executionCachePath
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
$helperPin = $null
$bridge = $null
$oldBridge = $null
$preparedOldBridge = $null
$oldPackagePin = $null
$oldHelperPin = $null
$previousServiceStates = Get-ManagedAgentServiceStates
$stoppedBySetup = @{}
$restorePolicy = @{ LateOperation = $false }
$installationCompleted = $false
$nativeStarted = $false
$nativeExit = 0
try {
    $helperPath = Join-Path $executionCacheDirectory 'endpoint-installer-host.exe'
    if (Test-Path -LiteralPath $helperPath) { Assert-CacheArtifactProtection $helperPath }
    $helperHash = [EndpointInstallerBridge.PackageHelper]::Extract($executionCachePath,$helperPath)
    Assert-CacheArtifactProtection $helperPath
    $helperPin = [IO.File]::Open($helperPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
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
            $oldPath=Get-CompoundOldMedia $oldManifest $installerStateRoot $executionCacheRoot
            $oldPackagePin=[IO.File]::Open($oldPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
            $oldHelperPath=Join-Path (Split-Path $oldPath -Parent) 'endpoint-installer-host.exe'
            if (Test-Path -LiteralPath $oldHelperPath) { Assert-CacheArtifactProtection $oldHelperPath }
            $oldHelperHash=[EndpointInstallerBridge.PackageHelper]::Extract($oldPath,$oldHelperPath)
            Assert-CacheArtifactProtection $oldHelperPath
            $oldHelperPin=[IO.File]::Open($oldHelperPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
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
        $msiArguments += 'REMOVE=EndpointAgentInitialRuntimeFeature'
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
    if ($nativeExit -in @(3010,1641)) { exit $nativeExit }
    Invoke-InstallerHelper -Bridge $bridge -Phase 'reconcile' | Out-Null
    Invoke-InstallerHelper -Bridge $bridge -Phase 'finish' | Out-Null
    }
    if ($null -ne (Read-InstallerFence -Root $installerStateRoot)) { throw 'RECOVERY_REQUIRED' }
    if ($intent -eq 'install' -and $null -eq $compoundDetails) { Invoke-InstallerHelper -Bridge $bridge -Phase 'verify-settled' | Out-Null }
    $installationCompleted = $true
    if ($intent -eq 'install' -and $nativeExit -eq 0) { Start-VerifiedBrowserPolicy;Start-ManagedEndpointAgent }
    if ($nativeExit -in @(3010,1641)) { exit $nativeExit }
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
    if ($null -ne $oldHelperPin) { $oldHelperPin.Dispose() }
    if ($null -ne $oldPackagePin) { $oldPackagePin.Dispose() }
    if ($null -ne $helperPin) { $helperPin.Dispose() }
    $packagePin.Dispose()
}

} finally {
    if ($transactionOwned) { $updateMutex.ReleaseMutex() }
    if ($null -ne $updateMutex) { $updateMutex.Dispose() }
}
