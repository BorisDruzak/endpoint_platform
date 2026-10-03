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
$ManagedServiceNames = @('EndpointAgent', 'EndpointAgentUpdater')
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
        [DllImport("msi.dll")] static extern uint MsiCloseHandle(uint handle);
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
        public bool Begun, Complete;
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
        private void CheckPeer(Identity peer) {
            if (!alive || peer==null || !peer.Elevated || peer.Hash!=HelperHash ||
                (peer.Sid!=Owner.Sid && peer.Sid!="S-1-5-18")) Fail();
        }
        public void RegisterHelper(Identity peer,string phase) {
            CheckPeer(peer);
            if (phase!="inspect" && phase!="prepare" && phase!="reconcile" && phase!="finish" && phase!="verify-settled") Fail();
            if (phase!="inspect" && phase!="verify-settled" && !quiescent) Fail();
            if ((phase=="reconcile" || phase=="finish") && (!nativeComplete || !nativeResult.HasValue ||
                nativeResult.Value!=0)) Fail();
            if (helpers.Count>=64 || helpers.ContainsKey(peer.Key)) Fail();
            helpers.Add(peer.Key,new Registration { Peer=peer, Phase=phase });
        }
        public void RegisterMsi(Identity peer,string operation) {
            if (!alive || !quiescent || !preparedComplete || !AllHelpersComplete || msiAlive || peer==null || !peer.Elevated || operation!=Operation || nativeResult.HasValue) Fail();
            msiAlive=true;
        }
        public void MarkQuiescent() { if(!alive || !AllHelpersComplete) Fail(); quiescent=true; }
        public void MarkMsiExited(int code) { msiAlive=false; nativeResult=code; pending=null; }
        public void OwnerLost() { alive=false; pending=null; }
        public bool NativeEntered { get { return nativeEntered; } }
        public bool NativeComplete { get { return nativeComplete; } }
        public bool AllHelpersComplete { get { foreach(var item in helpers.Values) if(!item.Complete) return false; return true; } }
        public Challenge Issue(Identity peer,string phase,string action,string payloadHash,string sessionId) {
            CheckPeer(peer);
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
            return Sign("grant",value);
        }
        public static bool FixedEquals(string a,string b) {
            if(a==null || b==null || a.Length!=b.Length) return false;
            int difference=0; for(int i=0;i<a.Length;i++) difference|=a[i]^b[i]; return difference==0;
        }
        public static string Hex(byte[] bytes) { return BitConverter.ToString(bytes).Replace("-","").ToLowerInvariant(); }
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
            if ($timer.Elapsed.TotalMinutes -gt 30) { throw 'RECOVERY_REQUIRED' }
            $packetBytes = $Bridge.Channel.Poll()
            if ($null -ne $packetBytes) {
                if ($null -eq $peer) {
                    $peer = [EndpointInstallerBridge.NativeProcess]::new($Bridge.Channel.PeerPid())
                    if ($Msi) {
                        if (-not $launched.Alive) { throw 'OWNER_AUTH_FAILED' }
                    } else {
                        if (-not $peer.Identity.Same($launched.Identity) -and -not $peer.DirectChildOf($launched)) { throw 'OWNER_AUTH_FAILED' }
                        $Bridge.Policy.RegisterHelper($peer.Identity, $Phase)
                    }
                    $Bridge.Peers.Add($peer)
                }
                if (($null -eq $acknowledgement -and -not $peer.Alive) -or $Bridge.Channel.PeerPid() -ne $peer.Identity.Pid) { throw 'OWNER_AUTH_FAILED' }
                $packet = [Text.Encoding]::ASCII.GetString($packetBytes) | ConvertFrom-Json
                $keys = @($packet.PSObject.Properties.Name | Sort-Object)
                if ($null -ne $acknowledgement) {
                    if ([string]::Join('|', $keys) -ne 'received' -or $packet.received -ne $acknowledgement) { throw 'OWNER_AUTH_FAILED' }
                    $Bridge.Channel.Disconnect()
                    $acknowledgement = $null
                    $completed = $true
                    $peer = $null
                } elseif ($null -ne $challenge) {
                    if ([string]::Join('|', $keys) -ne 'proof') { throw 'OWNER_AUTH_FAILED' }
                    $signature = $Bridge.Policy.Accept($peer.Identity, $challenge, [string]$packet.proof)
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
                    $challenge = $Bridge.Policy.Issue($peer.Identity, $packet.phase, $packet.action, $payloadHash, $packet.session)
                    Send-InstallerBridgePacket $Bridge @{ sequence = $challenge.Sequence; nonce = $challenge.Nonce; proof = $Bridge.Policy.Sign('owner', $challenge) }
                }
            }
            $Process.Refresh()
            if ($Process.HasExited) {
                $activePeers = @($Bridge.Peers | Where-Object { $_.Alive })
                if ($activePeers.Count -eq 0 -and $null -eq $acknowledgement -and $null -eq $challenge) { break }
            }
            if ($null -eq $packetBytes) { Start-Sleep -Milliseconds 1 }
        } while ($true)
        if ($Msi) {
            $Bridge.Policy.MarkMsiExited($Process.ExitCode)
            if ($Process.ExitCode -eq 1618) { throw 'UPDATE_IN_PROGRESS' }
            if ($Process.ExitCode -notin @(0,3010,1641) -or -not $Bridge.Policy.NativeComplete -or -not $Bridge.Policy.AllHelpersComplete) { throw 'RECOVERY_REQUIRED' }
        } elseif ($Process.ExitCode -eq 61) {
            throw 'UPDATE_IN_PROGRESS'
        } elseif ($Process.ExitCode -eq 62) {
            throw 'UPDATE_STATE_INVALID'
        } elseif ($Process.ExitCode -ne 0 -or -not $completed -or -not $Bridge.Policy.AllHelpersComplete) {
            throw 'RECOVERY_REQUIRED'
        }
        return $result
    } catch {
        $Bridge.Policy.OwnerLost()
        throw
    } finally {
        $launched.Dispose()
    }
}

function Invoke-InstallerHelper {
    param([Parameter(Mandatory)]$Bridge,[Parameter(Mandatory)][string]$Phase)
    if ($Phase -notin @('inspect','prepare','reconcile','finish','verify-settled') -or $Bridge.SessionId -cnotmatch '^[0-9a-f-]{36}$') { throw 'OWNER_AUTH_FAILED' }
    Assert-ExistingPathChain $Bridge.LaunchDirectory
    Assert-InstallerCacheProtection $Bridge.LaunchDirectory
    $info = [EndpointInstallerBridge.LaunchDirectory]::StartInfo($Bridge.HelperPath, ('--installer-phase ' + $Phase + ' --installer-session ' + $Bridge.SessionId), $Bridge.LaunchDirectory)
    $process = [Diagnostics.Process]::Start($info)
    return Invoke-InstallerOwnerPump -Bridge $Bridge -Process $process -Phase $Phase
}

function Get-InstallerReaderSids {
    return @('S-1-5-80-1102781572-1373263041-1070489469-7526906-1468061691',
        'S-1-5-80-327494974-20047353-929432329-1920152597-707704661')
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

function New-InstallerBridge {
    param($Manifest,[string]$HelperPath,[string]$HelperHash,[string]$StateRoot,[hashtable]$ServiceStates,$Fence,[string]$Intent,[string]$TransactionId,$Selection)
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
    foreach ($serviceName in @('EndpointAgent', 'EndpointAgentUpdater')) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        $previousStates[$serviceName] = if ($null -eq $service) { 'Absent' } else { $service.Status.ToString() }
    }
    return $previousStates
}

function Stop-ManagedAgentServices {
    param([hashtable]$PreviousStates = (Get-ManagedAgentServiceStates),
        [Parameter(Mandatory)][hashtable]$StoppedBySetup, [scriptblock]$AfterAgentStopped = {})
    foreach ($serviceName in @('EndpointAgent', 'EndpointAgentUpdater')) {
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
    foreach ($serviceName in @('EndpointAgent', 'EndpointAgentUpdater')) {
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
    param([string]$Path)
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
        if (Test-Path -LiteralPath $root) { Assert-UpdateGateAcl -Path $root }
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
        if ($null -ne $interruptedFence -and $Operation -ne 'RecoverInterruptedInstall') { exit 61 }
        if ($Operation -eq 'RecoverInterruptedInstall' -and $null -eq $interruptedFence) { exit 61 }
        if ($null -ne $interruptedFence -and ($interruptedFence.package.sha256 -cne $manifest.package_sha256 -or $interruptedFence.package.product_code -cne $manifest.product_code -or $interruptedFence.package.version -cne $manifest.version -or $interruptedFence.package.source_revision -cne $manifest.source_revision)) { throw 'PROVENANCE_CONFLICT' }
    } catch { Write-Error 'UPDATE_STATE_INVALID' -ErrorAction Continue; exit 62 }

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
        'RecoverInterruptedInstall' { $interruptedFence.operation }
        default { 'install' }
    }
    $bridge = New-InstallerBridge -Manifest $manifest -HelperPath $helperPath -HelperHash $helperHash -StateRoot $installerStateRoot -ServiceStates $previousServiceStates -Fence $interruptedFence -Intent $intent
    $initial = Invoke-InstallerHelper -Bridge $bridge -Phase 'inspect'
    if ($intent -ne 'retire-initial-runtime') {
        Stop-ManagedAgentServices -PreviousStates $previousServiceStates -StoppedBySetup $stoppedBySetup -AfterAgentStopped {
            $restorePolicy.LateOperation = $true
            try { $active = Test-ActiveUpdateState -InstallRoot $gateInstallRoot -DataRoot $gateDataRoot }
            catch { throw 'UPDATE_STATE_INVALID' }
            if ($active) { throw 'UPDATE_IN_PROGRESS' }
            $settled = Invoke-InstallerHelper -Bridge $bridge -Phase 'inspect'
            if ($settled.selected -cne $initial.selected -or $settled.previous -cne $initial.previous) { throw 'PROVENANCE_CONFLICT' }
            $restorePolicy.LateOperation = $false
        }
    }
    try { $active = Test-ActiveUpdateState -InstallRoot $gateInstallRoot -DataRoot $gateDataRoot }
    catch { $restorePolicy.LateOperation = $true; throw 'UPDATE_STATE_INVALID' }
    if ($active) { $restorePolicy.LateOperation = $true; throw 'UPDATE_IN_PROGRESS' }
    $bootstrapBridge = $bridge
    $bridge = New-InstallerBridge -Manifest $manifest -HelperPath $helperPath -HelperHash $helperHash -StateRoot $installerStateRoot -ServiceStates $previousServiceStates -Fence $interruptedFence -Intent $intent -TransactionId $bootstrapBridge.TransactionId -Selection $initial
    $bootstrapBridge.Policy.OwnerLost()
    $bootstrapBridge.Channel.Dispose()
    foreach ($peer in $bootstrapBridge.Peers) { $peer.Dispose() }
    $bootstrapBridge.Owner.Dispose()
    $bridge.Policy.MarkQuiescent()
    Invoke-InstallerHelper -Bridge $bridge -Phase 'prepare' | Out-Null
    # Re-read the protected durable fence before the first native invocation.
    $prepared = Read-InstallerFence -Root $installerStateRoot
    if ($null -eq $prepared -or $prepared.transaction_id -cne $bridge.TransactionId -or $prepared.package.sha256 -cne $inputHash) { throw 'RECOVERY_REQUIRED' }
    Start-WindowsInstaller
    $msiArguments = @('/i', ('"{0}"' -f $executionCachePath), '/qn', '/norestart', ('ENDPOINT_INSTALLER_SESSION=' + $bridge.SessionId))
    if ($bridge.Capability.uninstall_finalization) {
        $msiArguments += 'ENDPOINT_UNINSTALL_FINALIZE=1'
    } elseif ($intent -eq 'retire-initial-runtime') {
        $msiArguments += 'REMOVE=EndpointAgentInitialRuntimeFeature'
    } elseif ($intent -eq 'uninstall') {
        $msiArguments += 'REMOVE=ALL'
    } else {
        $msiArguments += 'ADDLOCAL=EndpointAgentFeature,EndpointAgentInitialRuntimeFeature'
        if ($null -ne $interruptedFence) { $msiArguments += @('REINSTALL=ALL','REINSTALLMODE=amus') }
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
    if ($null -ne (Read-InstallerFence -Root $installerStateRoot)) { throw 'RECOVERY_REQUIRED' }
    $installationCompleted = $true
    if ($intent -eq 'install' -and $nativeExit -eq 0) { Start-ManagedEndpointAgent }
    if ($nativeExit -in @(3010,1641)) { exit $nativeExit }
}
catch {
    if ($_.Exception.Message -eq 'UPDATE_IN_PROGRESS') { exit 61 }
    if ($_.Exception.Message -eq 'UPDATE_STATE_INVALID') { exit 62 }
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
    if ($null -ne $helperPin) { $helperPin.Dispose() }
    $packagePin.Dispose()
}

} finally {
    if ($transactionOwned) { $updateMutex.ReleaseMutex() }
    if ($null -ne $updateMutex) { $updateMutex.Dispose() }
}
