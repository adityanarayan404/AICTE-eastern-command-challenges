# Challenge 1 - parse Windows 10/11 prefetch (.pf) files: what ran, how often, when, and which files it touched
# Prefetch files are records written by Windows, not executables - safe to read on the host.
# Run from inside "challenge 1":  python parse_prefetch.py > prefetch_report.txt
import ctypes, struct, glob, os, datetime, sys

sys.stdout.reconfigure(encoding='utf-8')   # some file names contain non-ASCII characters

ntdll = ctypes.WinDLL('ntdll')
COMPRESSION_FORMAT_XPRESS_HUFF = 4

def decompress(raw):
    # Win10+ prefetch = "MAM\x04" + uncompressed size + XPRESS-Huffman data; Windows has the decompressor built in
    size = struct.unpack_from('<I', raw, 4)[0]
    ws_comp, ws_frag = ctypes.c_ulong(), ctypes.c_ulong()
    ntdll.RtlGetCompressionWorkSpaceSize(COMPRESSION_FORMAT_XPRESS_HUFF, ctypes.byref(ws_comp), ctypes.byref(ws_frag))
    workspace = ctypes.create_string_buffer(ws_comp.value)
    out, final = ctypes.create_string_buffer(size), ctypes.c_ulong()
    status = ntdll.RtlDecompressBufferEx(COMPRESSION_FORMAT_XPRESS_HUFF, out, size, ctypes.c_char_p(raw[8:]),
                                         len(raw) - 8, ctypes.byref(final), workspace)
    if status != 0:
        raise OSError(f'decompression failed: 0x{status & 0xFFFFFFFF:08x}')
    return out.raw[:final.value]

def filetime(ft):
    if ft == 0: return None
    return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ft // 10)

for path in sorted(glob.glob('prefetch/**/*.pf', recursive=True)):
    raw = open(path, 'rb').read()
    d = decompress(raw) if raw[:3] == b'MAM' else raw
    version, sig = struct.unpack_from('<I4s', d, 0)
    exe = d[0x10:0x10 + 60].decode('utf-16-le').split('\x00')[0]
    pf_hash = struct.unpack_from('<I', d, 0x4C)[0]
    metrics_off, _, _, _, strings_off, strings_size, vol_off, vol_count = struct.unpack_from('<8I', d, 0x54)
    # version 30/31: 8 last-run FILETIMEs at 0x80; run count at 0xD0 (variant 1) or 0xC8 (variant 2)
    runs = [t for t in (filetime(x) for x in struct.unpack_from('<8Q', d, 0x80)) if t]
    run_count = struct.unpack_from('<I', d, 0xC8 if metrics_off == 0x128 else 0xD0)[0]
    files = d[strings_off:strings_off + strings_size].decode('utf-16-le', 'ignore').split('\x00')
    files = [f for f in files if f]

    print('=' * 100)
    print(f'{os.path.basename(path)}')
    print(f'  executable : {exe}   (prefetch version {version}, signature {sig.decode()}, hash {pf_hash:08X})')
    print(f'  run count  : {run_count}')
    print(f'  last runs (UTC, newest first):')
    for t in runs: print(f'      {t:%Y-%m-%d %H:%M:%S}')
    # volumes: device path, serial number, creation time
    for i in range(vol_count):
        o = vol_off + i * 96
        dev_off, dev_chars, vol_ctime, serial = struct.unpack_from('<IIQI', d, o)
        dev = d[vol_off + dev_off:vol_off + dev_off + dev_chars * 2].decode('utf-16-le', 'ignore')
        print(f'  volume     : {dev}  serial {serial:08X}  created {filetime(vol_ctime)}')
    print(f'  files referenced ({len(files)}), notable:')
    skip = ('\\WINDOWS\\SYSTEM32\\', '\\WINDOWS\\SYSWOW64\\', '\\WINDOWS\\WINSXS\\', '\\WINDOWS\\GLOBALIZATION\\')
    for f in files:
        if not any(s in f.upper() for s in skip):
            print(f'      {f}')
