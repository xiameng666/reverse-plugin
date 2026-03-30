#!/usr/bin/env python3
"""
static_analyze.py — idat 导出数据静态分析
分析 SVC 调用模式、字符串解密点、保护方案特征

输入: idat export 目录 (包含 functions.json, strings.json, callgraph.json, xrefs.json, disasm/, decompiled/)
输出: JSON 报告 + Markdown 报告
"""

import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path


def load_json(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def scan_svc_in_disasm(disasm_dir):
    """扫描所有 .asm 文件中的 SVC 指令，支持 MBA 混淆的 syscall number"""
    svc_calls = []
    for asm_file in Path(disasm_dir).glob('*.asm'):
        func_name = asm_file.stem
        with open(asm_file, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        for i, line in enumerate(lines):
            line_stripped = line.strip()
            # 匹配 SVC #0 / SVC 0 / svc #0x0 等
            if re.search(r'\bSVC\b\s+#?0x?0*\b', line_stripped, re.IGNORECASE):
                addr_match = re.match(r'^([0-9a-fA-F]+)', line_stripped)
                addr = addr_match.group(1) if addr_match else 'unknown'

                # 向上回溯找 syscall number (X8)
                syscall_nr = None
                x8_obfuscated = False
                setup_instrs = []
                x8_chain = []  # X8 赋值链

                lookback = min(30, i)  # 扩大回溯到30行
                for j in range(max(0, i - lookback), i):
                    prev = lines[j].strip()

                    # 简单模式: MOV X8, #NR / MOV W8, #NR
                    nr_match = re.search(
                        r'MOV\s+[WX]8,\s+#(0x[0-9a-fA-F]+|\d+)',
                        prev, re.IGNORECASE
                    )
                    if nr_match:
                        val = nr_match.group(1)
                        syscall_nr = int(val, 16) if val.startswith('0x') else int(val)

                    # 检测 X8 被 MBA 混淆操作 (ADD/SUB/EOR/ORR/AND + X8)
                    if re.search(r'(ADD|SUB|EOR|ORR|AND|NEG|LSL|LSR|ASR)\s+X8,', prev, re.IGNORECASE):
                        x8_chain.append(prev)

                    # 收集参数设置 (X0-X5)
                    arg_match = re.search(
                        r'(MOV|LDR|ADRP|ADD|SUB)\s+[WX][0-5],',
                        prev, re.IGNORECASE
                    )
                    if arg_match:
                        setup_instrs.append(prev)

                # 如果没找到简单的 MOV X8 但有 X8 操作链，标记为混淆
                if syscall_nr is None and len(x8_chain) >= 2:
                    x8_obfuscated = True

                svc_calls.append({
                    'func': func_name,
                    'addr': f'0x{addr}',
                    'syscall_nr': syscall_nr,
                    'x8_obfuscated': x8_obfuscated,
                    'x8_chain': x8_chain[-5:] if x8_chain else [],
                    'setup_instrs': setup_instrs[-6:],
                    'context_before': [l.strip() for l in lines[max(0, i-5):i]],
                    'context_after': [l.strip() for l in lines[i+1:min(len(lines), i+3)]],
                })
    return svc_calls


def classify_svc_patterns(svc_calls, callgraph):
    """分类 SVC 调用模式: direct / wrapper / library"""
    patterns = {
        'direct': [],      # 函数内直接 SVC，函数自身有多个 caller
        'wrapper': [],      # 专门的 SVC 包装函数（少量指令，被多处调用）
        'inline': [],       # 内联 SVC，函数较大，SVC 只是其中一部分
    }

    # 按函数分组
    func_svcs = defaultdict(list)
    for svc in svc_calls:
        func_svcs[svc['func']].append(svc)

    for func_name, svcs in func_svcs.items():
        callers = []
        if func_name in callgraph:
            callers = callgraph[func_name].get('callers', [])

        caller_count = len(callers)
        svc_count = len(svcs)

        # 判断是否是 wrapper: 被多处调用 + SVC 数量少
        if caller_count >= 2 and svc_count <= 2:
            for svc in svcs:
                svc['callers'] = callers
                svc['pattern'] = 'wrapper'
                patterns['wrapper'].append(svc)
        elif caller_count <= 1 and svc_count == 1:
            for svc in svcs:
                svc['callers'] = callers
                svc['pattern'] = 'inline'
                patterns['inline'].append(svc)
        else:
            for svc in svcs:
                svc['callers'] = callers
                svc['pattern'] = 'direct'
                patterns['direct'].append(svc)

    return patterns


def analyze_string_origins(svc_calls, xrefs, strings_data):
    """追踪 SVC 参数中字符串的来源"""
    string_map = {}
    for s in strings_data.get('strings', []):
        string_map[s['addr']] = s

    string_refs = []
    # 对每个 SVC 调用，检查其函数的 xrefs 是否引用了字符串
    func_names = set(svc['func'] for svc in svc_calls)
    for func_name in func_names:
        if func_name not in xrefs:
            continue
        data_refs = xrefs[func_name].get('data_refs', [])
        for ref in data_refs:
            target = ref.get('to', '')
            if ref.get('string'):
                string_refs.append({
                    'func': func_name,
                    'ref_from': ref.get('from', ''),
                    'ref_to': target,
                    'string': ref['string'],
                })
            elif target in string_map:
                string_refs.append({
                    'func': func_name,
                    'ref_from': ref.get('from', ''),
                    'ref_to': target,
                    'string': string_map[target]['value'],
                })

    return string_refs


def detect_string_decrypt_points(callgraph, functions, decompiled_dir):
    """检测统一的字符串解密函数 — 宽松策略，适应混淆 SO"""
    candidates = []

    for func_name, info in callgraph.items():
        callers = info.get('callers', [])
        callees = info.get('callees', [])

        # 基本过滤: 被多处调用的未命名函数
        if len(callers) < 3:
            continue
        if not func_name.startswith('sub_'):
            continue

        # 尝试读取反编译代码
        decompiled_file = decompiled_dir / f'{func_name}.c'
        decrypt_indicators = 0
        func_type = 'unknown'
        code_snippet = ''
        code_size = 0

        if decompiled_file.exists():
            with open(decompiled_file, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
                code_snippet = code[:800]
                code_size = len(code)

                # === 解密特征 (经典) ===
                if re.search(r'\^', code):
                    decrypt_indicators += 1
                if re.search(r'for\s*\(', code) or re.search(r'while\s*\(', code):
                    decrypt_indicators += 1
                if re.search(r'\[.*\+.*\]', code):  # 数组索引+偏移
                    decrypt_indicators += 1
                if re.search(r'[>|<]{2}|&\s*0x', code):
                    decrypt_indicators += 1
                if re.search(r'mem(cpy|set|move)|malloc|calloc', code):
                    decrypt_indicators += 1

                # === 间接调用 / 函数指针特征 ===
                if re.search(r'\(\*.*\)\s*\(', code):  # 函数指针调用
                    decrypt_indicators += 1
                if re.search(r'__int64.*\(\)', code):   # 间接调用
                    decrypt_indicators += 1

                # === 常量/魔数特征 (MBA 混淆) ===
                hex_constants = re.findall(r'0x[0-9A-Fa-f]{8,}', code)
                if len(hex_constants) >= 2:
                    decrypt_indicators += 1

                # === 分类函数类型 ===
                if re.search(r'(atomic_store|__ldaxr|__stlxr)', code):
                    func_type = 'atomic_guard'
                elif re.search(r'qword_.*=\s*0x[0-9A-Fa-f]+LL', code):
                    func_type = 'const_init'
                elif re.search(r'(p_sub_|sub_)\w+\s*=\s*sub_', code):
                    func_type = 'func_ptr_init'
                elif decrypt_indicators >= 2:
                    func_type = 'likely_decrypt'
                elif len(callers) >= 10 and code_size < 500:
                    func_type = 'dispatcher'

        candidates.append({
            'func': func_name,
            'addr': info['addr'],
            'caller_count': len(callers),
            'callee_count': len(callees),
            'callers_sample': [c['name'] for c in callers[:10]],
            'callees': [c['name'] for c in callees],
            'decrypt_score': decrypt_indicators,
            'func_type': func_type,
            'code_size': code_size,
            'code_preview': code_snippet,
        })

    # 排序: decrypt_score * caller_count, 其次单看 caller_count
    candidates.sort(
        key=lambda x: (x['decrypt_score'] * x['caller_count'], x['caller_count']),
        reverse=True
    )
    return candidates[:30]


def detect_anti_features(svc_calls, strings_data, callgraph):
    """从静态数据检测反调试/反注入特征"""
    features = {
        'anti_debug': [],
        'anti_inject': [],
        'anti_root': [],
        'anti_vm': [],
        'anti_frida': [],
        'integrity_check': [],
    }

    # 关键词匹配
    keywords = {
        'anti_debug': [
            'ptrace', 'TracerPid', '/proc/self/status',
            'PR_SET_DUMPABLE', 'PTRACE_TRACEME',
        ],
        'anti_inject': [
            '/proc/self/maps', '/proc/self/mem',
            'linker', 'dlopen', 'dl_iterate_phdr',
        ],
        'anti_root': [
            '/system/bin/su', '/system/xbin/su', 'magisk',
            'supersu', 'busybox', '/sbin/su',
        ],
        'anti_vm': [
            'goldfish', 'generic', 'vbox', 'genymotion',
            'ro.hardware', 'ro.product.model',
        ],
        'anti_frida': [
            'frida', 'gum-js-loop', 'gmain',
            'linjector', 're.frida.server', '27042',
        ],
        'integrity_check': [
            'classes.dex', 'META-INF', '.RSA', 'CERT',
            'getPackageInfo', 'signatures',
        ],
    }

    for s in strings_data.get('strings', []):
        val = s['value'].lower()
        for category, kws in keywords.items():
            for kw in kws:
                if kw.lower() in val:
                    features[category].append({
                        'string': s['value'],
                        'addr': s['addr'],
                        'keyword': kw,
                        'xrefs': s.get('xrefs', []),
                    })

    # SVC syscall 号匹配
    syscall_map = {
        117: ('ptrace', 'anti_debug'),
        167: ('prctl', 'anti_debug'),
        56: ('openat', 'anti_inject'),   # 用于打开 /proc/self/maps
        48: ('faccessat', 'anti_root'),   # 检测 su 路径
    }
    for svc in svc_calls:
        nr = svc.get('syscall_nr')
        if nr in syscall_map:
            name, cat = syscall_map[nr]
            features[cat].append({
                'type': 'syscall',
                'syscall': name,
                'nr': nr,
                'func': svc['func'],
                'addr': svc['addr'],
            })

    return features


def generate_hookgen_suggestions(decrypt_candidates, svc_patterns):
    """生成 rustFrida hook 建议"""
    suggestions = []

    # 字符串解密函数 hook
    for cand in decrypt_candidates[:5]:
        if cand['decrypt_score'] >= 2:
            suggestions.append({
                'type': 'string_decrypt',
                'target': cand['func'],
                'addr': cand['addr'],
                'reason': f"被 {cand['caller_count']} 处调用, 解密特征分 {cand['decrypt_score']}/5",
                'hook_strategy': 'onLeave 读取返回值(解密后字符串) + LR(调用点)',
                'priority': 'HIGH',
            })

    # SVC wrapper 函数 hook
    for svc in svc_patterns.get('wrapper', []):
        suggestions.append({
            'type': 'svc_wrapper',
            'target': svc['func'],
            'addr': svc['addr'],
            'syscall_nr': svc.get('syscall_nr'),
            'reason': f"SVC wrapper, 被 {len(svc.get('callers', []))} 处调用",
            'hook_strategy': 'onEnter 读参数 + onLeave 修改返回值',
            'priority': 'MEDIUM',
        })

    return suggestions


def generate_report(export_dir, output_dir):
    """主分析流程"""
    export_path = Path(export_dir)
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # 加载数据
    meta = load_json(export_path / 'meta.json')
    functions = load_json(export_path / 'functions.json')
    strings_data = load_json(export_path / 'strings.json')
    callgraph = load_json(export_path / 'callgraph.json')
    xrefs = load_json(export_path / 'xrefs.json')

    disasm_dir = export_path / 'disasm'
    decompiled_dir = export_path / 'decompiled'

    print(f"STATUS=ANALYZING")
    print(f"BINARY={meta.get('input_file', 'unknown')}")
    print(f"FUNCTIONS={functions.get('total', 0)}")
    print(f"STRINGS={strings_data.get('total', 0)}")

    # 1. 扫描 SVC
    print("PHASE=svc_scan")
    svc_calls = scan_svc_in_disasm(disasm_dir)
    print(f"SVC_COUNT={len(svc_calls)}")

    # 1b. MBA 混淆统计
    obfuscated_count = sum(1 for s in svc_calls if s.get('x8_obfuscated'))
    plain_count = sum(1 for s in svc_calls if s.get('syscall_nr') is not None)
    unknown_count = len(svc_calls) - obfuscated_count - plain_count
    print(f"SVC_PLAIN_NR={plain_count}")
    print(f"SVC_MBA_OBFUSCATED={obfuscated_count}")
    print(f"SVC_NR_UNKNOWN={unknown_count}")

    # 2. 分类 SVC 模式
    print("PHASE=svc_classify")
    svc_patterns = classify_svc_patterns(svc_calls, callgraph)
    print(f"WRAPPER={len(svc_patterns['wrapper'])}")
    print(f"DIRECT={len(svc_patterns['direct'])}")
    print(f"INLINE={len(svc_patterns['inline'])}")

    # 3. 字符串来源追踪
    print("PHASE=string_trace")
    string_refs = analyze_string_origins(svc_calls, xrefs, strings_data)
    print(f"STRING_REFS={len(string_refs)}")

    # 4. 字符串解密点检测
    print("PHASE=decrypt_detect")
    decrypt_candidates = detect_string_decrypt_points(
        callgraph, functions, decompiled_dir
    )
    print(f"DECRYPT_CANDIDATES={len(decrypt_candidates)}")

    # 5. 安全特征检测
    print("PHASE=anti_feature_detect")
    anti_features = detect_anti_features(svc_calls, strings_data, callgraph)
    total_features = sum(len(v) for v in anti_features.values())
    print(f"ANTI_FEATURES={total_features}")

    # 6. Hook 建议
    print("PHASE=hookgen")
    hook_suggestions = generate_hookgen_suggestions(decrypt_candidates, svc_patterns)
    print(f"HOOK_SUGGESTIONS={len(hook_suggestions)}")

    # 输出 JSON 报告
    report = {
        'meta': meta,
        'summary': {
            'total_functions': functions.get('total', 0),
            'total_strings': strings_data.get('total', 0),
            'svc_count': len(svc_calls),
            'svc_plain_nr': plain_count,
            'svc_mba_obfuscated': obfuscated_count,
            'svc_nr_unknown': unknown_count,
            'svc_wrapper_count': len(svc_patterns['wrapper']),
            'svc_direct_count': len(svc_patterns['direct']),
            'svc_inline_count': len(svc_patterns['inline']),
            'decrypt_candidates': len(decrypt_candidates),
            'anti_features': total_features,
        },
        'svc_patterns': {
            k: [{kk: vv for kk, vv in s.items() if kk != 'context_before'}
                for s in v]
            for k, v in svc_patterns.items()
        },
        'string_refs': string_refs[:50],
        'decrypt_candidates': decrypt_candidates,
        'anti_features': anti_features,
        'hook_suggestions': hook_suggestions,
    }

    json_path = output_path / 'static_report.json'
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"STATUS=OK")
    print(f"REPORT={json_path}")
    print(f"OUTPUT_DIR={output_path}")
    return report


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: static_analyze.py <idat_export_dir> [output_dir]")
        print("  idat_export_dir: idat 导出目录 (含 functions.json, disasm/ 等)")
        print("  output_dir: 报告输出目录 (默认: export_dir 同级)")
        sys.exit(1)

    export_dir = sys.argv[1]
    if len(sys.argv) >= 3:
        output_dir = sys.argv[2]
    else:
        output_dir = str(Path(export_dir).parent / f'static_report_{Path(export_dir).name}')

    generate_report(export_dir, output_dir)
