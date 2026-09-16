$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

# Use WinINet's documented per-connection API, not registry mutations.
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class ProxykingWinInet {
    [StructLayout(LayoutKind.Explicit)]
    public struct Value {
        [FieldOffset(0)] public uint Number;
        [FieldOffset(0)] public IntPtr Text;
        [FieldOffset(0)] public System.Runtime.InteropServices.ComTypes.FILETIME Time;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct Option { public uint Id; public Value Value; }
    [StructLayout(LayoutKind.Sequential)]
    public struct OptionList {
        public uint Size;
        public IntPtr Connection;
        public uint Count;
        public uint Error;
        public IntPtr Options;
    }
    public class Settings {
        public uint flags;
        public string server;
        public string bypass;
        public string autoConfigUrl;
    }
    [DllImport("wininet.dll", EntryPoint="InternetQueryOptionW", SetLastError=true)]
    static extern bool Query(IntPtr handle, uint option, ref OptionList buffer, ref uint length);
    [DllImport("wininet.dll", EntryPoint="InternetSetOptionW", SetLastError=true)]
    static extern bool Set(IntPtr handle, uint option, ref OptionList buffer, uint length);
    [DllImport("wininet.dll", EntryPoint="InternetSetOptionW", SetLastError=true)]
    static extern bool Notify(IntPtr handle, uint option, IntPtr buffer, uint length);
    [DllImport("kernel32.dll")] static extern IntPtr GlobalFree(IntPtr memory);

    public static Settings Read() {
        int size = Marshal.SizeOf(typeof(Option));
        IntPtr memory = Marshal.AllocHGlobal(size * 4);
        // FLAGS_UI preserves the configured auto-detection preference, rather
        // than the transient result of a previous discovery attempt.
        uint[] ids = new uint[] { 10, 2, 3, 4 };
        bool queried = false;
        try {
            for (int i = 0; i < ids.Length; i++) {
                Option option = new Option(); option.Id = ids[i];
                Marshal.StructureToPtr(option, IntPtr.Add(memory, i * size), false);
            }
            OptionList list = new OptionList();
            list.Size = (uint)Marshal.SizeOf(typeof(OptionList)); list.Count = 4; list.Options = memory;
            uint length = list.Size;
            if (!Query(IntPtr.Zero, 75, ref list, ref length)) throw new Win32Exception(Marshal.GetLastWin32Error());
            queried = true;
            Settings result = new Settings();
            result.flags = ((Option)Marshal.PtrToStructure(memory, typeof(Option))).Value.Number;
            result.server = ReadText(memory, size, 1);
            result.bypass = ReadText(memory, size, 2);
            result.autoConfigUrl = ReadText(memory, size, 3);
            return result;
        } finally {
            if (queried) for (int i = 1; i < 4; i++) {
                IntPtr text = ((Option)Marshal.PtrToStructure(IntPtr.Add(memory, i * size), typeof(Option))).Value.Text;
                if (text != IntPtr.Zero) GlobalFree(text);
            }
            Marshal.FreeHGlobal(memory);
        }
    }
    static string ReadText(IntPtr memory, int size, int index) {
        IntPtr text = ((Option)Marshal.PtrToStructure(IntPtr.Add(memory, index * size), typeof(Option))).Value.Text;
        return text == IntPtr.Zero ? "" : Marshal.PtrToStringUni(text);
    }
    public static void Write(Settings settings) {
        int size = Marshal.SizeOf(typeof(Option));
        IntPtr memory = Marshal.AllocHGlobal(size * 4);
        IntPtr[] strings = new IntPtr[3];
        try {
            string[] values = new string[] { settings.server, settings.bypass, settings.autoConfigUrl };
            for (int i = 0; i < 4; i++) {
                Option option = new Option(); option.Id = (uint)(i + 1);
                if (i == 0) option.Value.Number = settings.flags;
                else { strings[i - 1] = Marshal.StringToHGlobalUni(values[i - 1] ?? ""); option.Value.Text = strings[i - 1]; }
                Marshal.StructureToPtr(option, IntPtr.Add(memory, i * size), false);
            }
            OptionList list = new OptionList();
            list.Size = (uint)Marshal.SizeOf(typeof(OptionList)); list.Count = 4; list.Options = memory;
            if (!Set(IntPtr.Zero, 75, ref list, list.Size)) throw new Win32Exception(Marshal.GetLastWin32Error());
            if (!Notify(IntPtr.Zero, 39, IntPtr.Zero, 0)) throw new Win32Exception(Marshal.GetLastWin32Error());
            if (!Notify(IntPtr.Zero, 37, IntPtr.Zero, 0)) throw new Win32Exception(Marshal.GetLastWin32Error());
        } finally {
            foreach (IntPtr text in strings) if (text != IntPtr.Zero) Marshal.FreeHGlobal(text);
            Marshal.FreeHGlobal(memory);
        }
    }
}
'@

$request = [Console]::In.ReadToEnd() | ConvertFrom-Json
if ($request.action -eq 'read') {
    [ProxykingWinInet]::Read() | ConvertTo-Json -Compress
} elseif ($request.action -eq 'write') {
    $settings = New-Object ProxykingWinInet+Settings
    $settings.flags = [uint32]$request.settings.flags
    $settings.server = [string]$request.settings.server
    $settings.bypass = [string]$request.settings.bypass
    $settings.autoConfigUrl = [string]$request.settings.autoConfigUrl
    [ProxykingWinInet]::Write($settings)
    [ProxykingWinInet]::Read() | ConvertTo-Json -Compress
} else { throw 'Unknown proxy action.' }
