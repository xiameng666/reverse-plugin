"""
IDA Pro Full Export - One-shot complete analysis dump
Usage: idat.exe -A -S"ida_full_export.py <output_dir>" target.so

Exports:
  output_dir/
    meta.json           - binary metadata
    functions.json      - all functions list
    strings.json        - all strings + xrefs
    imports.json        - imported functions
    exports.json        - exported functions
    segments.json       - memory segments
    callgraph.json      - full call graph (caller -> callee)
    xrefs.json          - cross-reference map
    disasm/
      sub_XXXXX.asm     - per-function disassembly
    decompiled/
      sub_XXXXX.c       - per-function Hex-Rays pseudocode
"""

import idc
import idaapi
import idautils
import ida_auto
import ida_hexrays
import ida_funcs
import ida_name
import ida_bytes
import ida_segment
import ida_nalt
import ida_entry
import json
import os
import sys
import time

# ---- Config ----
MAX_DECOMPILE_SIZE = 0x50000   # skip functions > 320KB (likely data)
BATCH_LOG_INTERVAL = 100       # progress log every N functions

def get_output_dir():
    args = idc.ARGV[1:] if hasattr(idc, 'ARGV') and len(idc.ARGV) > 1 else []
    if args:
        return args[0]
    return os.path.join(os.path.dirname(idc.get_input_file_path()), "ida_export")

def ensure_dirs(base):
    for sub in ["disasm", "decompiled"]:
        d = os.path.join(base, sub)
        if not os.path.exists(d):
            os.makedirs(d)

def log(msg):
    ts = time.strftime("%H:%M:%S")
    print(f"[IDA-Export {ts}] {msg}")

# ---- Exporters ----

def export_meta(out_dir):
    """Binary metadata"""
    # IDA 9.x compatible meta extraction using idc/idaapi
    bitness = 64 if idaapi.get_imagebase() >= 0x100000000 or idc.__EA64__ else 32
    try:
        import ida_ida
        procname = ida_ida.inf_get_procname()
        bitness = 64 if ida_ida.inf_is_64bit() else 32
    except:
        procname = "unknown"
        # Detect from segment
        seg = ida_segment.get_first_seg()
        if seg:
            bitness = 64 if seg.bitness == 2 else 32
    try:
        md5 = ida_nalt.retrieve_input_file_md5()
        md5_hex = md5.hex() if md5 else ""
    except:
        md5_hex = ""

    meta = {
        "input_file": idc.get_input_file_path(),
        "md5": md5_hex,
        "processor": procname,
        "bits": bitness,
        "base_address": hex(idaapi.get_imagebase()),
    }
    with open(os.path.join(out_dir, "meta.json"), 'w') as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)
    log(f"meta.json - {meta['processor']} {meta['bits']}bit base={meta['base_address']}")
    return meta

def export_segments(out_dir):
    """Memory segments"""
    segs = []
    seg = ida_segment.get_first_seg()
    while seg:
        segs.append({
            "name": ida_segment.get_segm_name(seg),
            "start": hex(seg.start_ea),
            "end": hex(seg.end_ea),
            "size": seg.end_ea - seg.start_ea,
            "perm": "%s%s%s" % (
                "R" if seg.perm & 4 else "-",
                "W" if seg.perm & 2 else "-",
                "X" if seg.perm & 1 else "-"
            ),
            "type": ida_segment.get_segm_class(seg),
        })
        seg = ida_segment.get_next_seg(seg.start_ea)
    with open(os.path.join(out_dir, "segments.json"), 'w') as f:
        json.dump(segs, f, indent=2, ensure_ascii=False)
    log(f"segments.json - {len(segs)} segments")
    return segs

def export_functions(out_dir):
    """All functions with basic info"""
    funcs = []
    for ea in idautils.Functions():
        func = ida_funcs.get_func(ea)
        if not func:
            continue
        name = ida_name.get_name(ea) or f"sub_{ea:X}"
        funcs.append({
            "addr": hex(ea),
            "name": name,
            "size": func.end_ea - ea,
            "end": hex(func.end_ea),
        })
    with open(os.path.join(out_dir, "functions.json"), 'w') as f:
        json.dump({"total": len(funcs), "functions": funcs}, f, indent=2, ensure_ascii=False)
    log(f"functions.json - {len(funcs)} functions")
    return funcs

def export_strings(out_dir):
    """All strings with cross-references"""
    strs = []
    sc = idautils.Strings()
    for s in sc:
        val = str(s)
        refs = []
        for xref in idautils.XrefsTo(s.ea, 0):
            fname = idc.get_func_name(xref.frm) or ""
            refs.append({"from": hex(xref.frm), "func": fname})
        strs.append({
            "addr": hex(s.ea),
            "value": val,
            "length": s.length,
            "xrefs": refs
        })
    with open(os.path.join(out_dir, "strings.json"), 'w') as f:
        json.dump({"total": len(strs), "strings": strs}, f, indent=2, ensure_ascii=False)
    log(f"strings.json - {len(strs)} strings")
    return strs

def export_imports(out_dir):
    """Imported functions"""
    imports = []
    nimps = idaapi.get_import_module_qty()
    for i in range(nimps):
        module = idaapi.get_import_module_name(i)
        entries = []
        def imp_cb(ea, name, ordinal):
            entries.append({
                "addr": hex(ea) if ea else "0",
                "name": name or f"ordinal_{ordinal}",
                "ordinal": ordinal
            })
            return True
        idaapi.enum_import_names(i, imp_cb)
        imports.append({"module": module or "unknown", "functions": entries})
    with open(os.path.join(out_dir, "imports.json"), 'w') as f:
        json.dump(imports, f, indent=2, ensure_ascii=False)
    total = sum(len(m["functions"]) for m in imports)
    log(f"imports.json - {total} imports from {len(imports)} modules")

def export_exports(out_dir):
    """Exported functions"""
    exports = []
    for i in range(ida_entry.get_entry_qty()):
        ordinal = ida_entry.get_entry_ordinal(i)
        ea = ida_entry.get_entry(ordinal)
        name = ida_entry.get_entry_name(ordinal) or f"export_{ordinal}"
        exports.append({
            "ordinal": ordinal,
            "addr": hex(ea),
            "name": name
        })
    with open(os.path.join(out_dir, "exports.json"), 'w') as f:
        json.dump({"total": len(exports), "exports": exports}, f, indent=2, ensure_ascii=False)
    log(f"exports.json - {len(exports)} exports")

def export_callgraph(out_dir):
    """Full call graph: for each function, list callees and callers"""
    graph = {}
    func_list = list(idautils.Functions())

    for idx, ea in enumerate(func_list):
        func = ida_funcs.get_func(ea)
        if not func:
            continue
        name = ida_name.get_name(ea) or f"sub_{ea:X}"

        # Callees: functions called FROM this function
        callees = set()
        for head in idautils.Heads(func.start_ea, func.end_ea):
            for xref in idautils.XrefsFrom(head, 0):
                # Code xref types: fl_CF=16, fl_CN=17, fl_JF=18, fl_JN=19
                if xref.type in (16, 17, 18, 19):
                    target_func = ida_funcs.get_func(xref.to)
                    if target_func and target_func.start_ea != ea:
                        tname = ida_name.get_name(target_func.start_ea) or f"sub_{target_func.start_ea:X}"
                        callees.add((hex(target_func.start_ea), tname))

        # Callers: functions that call THIS function
        callers = set()
        for xref in idautils.XrefsTo(ea, 0):
            caller_func = ida_funcs.get_func(xref.frm)
            if caller_func and caller_func.start_ea != ea:
                cname = ida_name.get_name(caller_func.start_ea) or f"sub_{caller_func.start_ea:X}"
                callers.add((hex(caller_func.start_ea), cname))

        graph[name] = {
            "addr": hex(ea),
            "callees": [{"addr": a, "name": n} for a, n in sorted(callees)],
            "callers": [{"addr": a, "name": n} for a, n in sorted(callers)],
        }

        if (idx + 1) % BATCH_LOG_INTERVAL == 0:
            log(f"callgraph... {idx+1}/{len(func_list)}")

    with open(os.path.join(out_dir, "callgraph.json"), 'w') as f:
        json.dump(graph, f, indent=2, ensure_ascii=False)
    log(f"callgraph.json - {len(graph)} nodes")

def export_disasm_and_decompile(out_dir, func_list):
    """Per-function disassembly (.asm) and decompiled pseudocode (.c)"""
    disasm_dir = os.path.join(out_dir, "disasm")
    decomp_dir = os.path.join(out_dir, "decompiled")

    has_hexrays = False
    try:
        has_hexrays = ida_hexrays.init_hexrays_plugin()
    except:
        pass

    success_count = 0
    fail_count = 0
    total = len(func_list)

    for idx, finfo in enumerate(func_list):
        ea = int(finfo["addr"], 16)
        func = ida_funcs.get_func(ea)
        if not func:
            continue

        name = finfo["name"]
        safe_name = name.replace(".", "_")  # sanitize filename
        size = func.end_ea - ea

        # --- Disassembly ---
        asm_lines = []
        curr = func.start_ea
        while curr < func.end_ea and curr != idaapi.BADADDR:
            disasm = idc.generate_disasm_line(curr, 0)
            raw = ida_bytes.get_bytes(curr, idc.get_item_size(curr))
            hex_bytes = raw.hex() if raw else ""
            asm_lines.append(f"{curr:08X}  {hex_bytes:<20s}  {disasm}")
            curr = idc.next_head(curr, func.end_ea)

        asm_path = os.path.join(disasm_dir, f"{safe_name}.asm")
        with open(asm_path, 'w', encoding='utf-8') as f:
            f.write(f"; Function: {name}\n")
            f.write(f"; Address:  {finfo['addr']} - {finfo['end']}\n")
            f.write(f"; Size:     {size} bytes\n")
            f.write(f"; ==========================================\n\n")
            f.write("\n".join(asm_lines))

        # --- Decompile ---
        if has_hexrays and size <= MAX_DECOMPILE_SIZE:
            try:
                cfunc = ida_hexrays.decompile(ea)
                if cfunc:
                    pseudocode = str(cfunc)
                    c_path = os.path.join(decomp_dir, f"{safe_name}.c")
                    with open(c_path, 'w', encoding='utf-8') as f:
                        f.write(f"// Function: {name}\n")
                        f.write(f"// Address:  {finfo['addr']} - {finfo['end']}\n")
                        f.write(f"// Size:     {size} bytes\n\n")
                        f.write(pseudocode)
                    success_count += 1
            except:
                fail_count += 1

        if (idx + 1) % BATCH_LOG_INTERVAL == 0:
            log(f"disasm+decompile... {idx+1}/{total} (decompiled: {success_count}, failed: {fail_count})")

    log(f"disasm/ - {total} .asm files")
    log(f"decompiled/ - {success_count} .c files ({fail_count} failed)")
    return success_count, fail_count

def export_xrefs_summary(out_dir):
    """Compact xref summary: data references (strings, globals)"""
    xrefs = {}
    for ea in idautils.Functions():
        func = ida_funcs.get_func(ea)
        if not func:
            continue
        name = ida_name.get_name(ea) or f"sub_{ea:X}"
        data_refs = []
        for head in idautils.Heads(func.start_ea, func.end_ea):
            for xref in idautils.XrefsFrom(head, 0):
                # Data xref types: dr_O=1, dr_W=2, dr_R=3
                if xref.type in (1, 2, 3):
                    target_name = ida_name.get_name(xref.to) or ""
                    str_type = idc.get_str_type(xref.to)
                    str_val = ""
                    if str_type is not None and str_type >= 0:
                        s = idc.get_strlit_contents(xref.to, -1, str_type)
                        if s:
                            str_val = s.decode('utf-8', errors='replace')
                    data_refs.append({
                        "from": hex(head),
                        "to": hex(xref.to),
                        "name": target_name,
                        "string": str_val
                    })
        if data_refs:
            xrefs[name] = {"addr": hex(ea), "data_refs": data_refs}

    with open(os.path.join(out_dir, "xrefs.json"), 'w') as f:
        json.dump(xrefs, f, indent=2, ensure_ascii=False)
    log(f"xrefs.json - {len(xrefs)} functions with data refs")

# ---- Main ----

def main():
    start_time = time.time()
    out_dir = get_output_dir()
    ensure_dirs(out_dir)

    log(f"=== IDA Full Export Start ===")
    log(f"Output: {out_dir}")

    ida_auto.auto_wait()
    log("Auto-analysis complete")

    # Phase 1: Metadata
    meta = export_meta(out_dir)
    export_segments(out_dir)

    # Phase 2: Symbols
    funcs = export_functions(out_dir)
    export_strings(out_dir)
    export_imports(out_dir)
    export_exports(out_dir)

    # Phase 3: Call graph
    export_callgraph(out_dir)

    # Phase 4: Per-function disasm + decompile (heaviest)
    export_disasm_and_decompile(out_dir, funcs)

    # Phase 5: Data xrefs
    export_xrefs_summary(out_dir)

    elapsed = time.time() - start_time
    log(f"=== Export Complete in {elapsed:.1f}s ===")
    log(f"Output directory: {out_dir}")

    # Write summary
    summary = {
        "elapsed_seconds": round(elapsed, 1),
        "output_dir": out_dir,
        "files": [
            "meta.json", "segments.json", "functions.json",
            "strings.json", "imports.json", "exports.json",
            "callgraph.json", "xrefs.json",
            "disasm/*.asm", "decompiled/*.c"
        ]
    }
    with open(os.path.join(out_dir, "summary.json"), 'w') as f:
        json.dump(summary, f, indent=2)

main()
idc.qexit(0)
