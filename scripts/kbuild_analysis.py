#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""
Kernel Build Configuration Analyzer
====================================
Analyzes the kernel build system (defconfig, Kconfig, Makefiles) to produce a
comprehensive report of which source files, directories, and modules will be
compiled under a given configuration.

Usage:
    python3 scripts/kbuild_analysis.py [OPTIONS]

Options:
    -k, --kernel-dir DIR      Kernel source root (default: script's parent dir)
    -d, --defconfig FILE      Path to defconfig (relative to arch/arm64/configs/)
                              or absolute path. Default: vendor/lahaina-qgki_defconfig
    -o, --output FILE         Output report path (default: build_analysis_report.txt)
    -f, --format FORMAT       Output format: txt, md (default: md)
    -s, --subsystem NAME      Only analyze a specific subsystem (e.g. drivers/soc/qcom)
    -v, --verbose             Show extra debug info during analysis
    --list-defconfigs         List available defconfig files and exit

Example:
    # Analyze default OnePlus SM8350 QGKI config
    python3 scripts/kbuild_analysis.py

    # Analyze GKI config, output markdown
    python3 scripts/kbuild_analysis.py -d vendor/lahaina-gki_defconfig -f md

    # Analyze only the Qualcomm SoC subsystem
    python3 scripts/kbuild_analysis.py -s drivers/soc/qcom
"""

import argparse
import os
import re
import sys
from collections import defaultdict, OrderedDict
from pathlib import Path
from datetime import datetime


# ---------------------------------------------------------------------------
# Defconfig Parser
# ---------------------------------------------------------------------------
class DefconfigParser:
    """Parse a kernel defconfig / .config file into a dict of CONFIG symbols."""

    def __init__(self, filepath):
        self.filepath = filepath
        self.configs = OrderedDict()       # CONFIG_XXX -> 'y' | 'm' | value
        self.disabled = OrderedDict()      # CONFIG_XXX -> True  (explicitly not set)

    def parse(self):
        with open(self.filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    # Check for "# CONFIG_XXX is not set"
                    m = re.match(r'^#\s*(CONFIG_\w+)\s+is not set', line)
                    if m:
                        self.disabled[m.group(1)] = True
                    continue
                # CONFIG_XXX=y / CONFIG_XXX=m / CONFIG_XXX="string" / CONFIG_XXX=123
                m = re.match(r'^(CONFIG_\w+)=(.+)$', line)
                if m:
                    key, val = m.group(1), m.group(2)
                    self.configs[key] = val
        return self

    def is_enabled(self, symbol):
        """Return True if CONFIG_<symbol> = y or m (i.e. will be compiled)."""
        key = symbol if symbol.startswith('CONFIG_') else f'CONFIG_{symbol}'
        return key in self.configs

    def get_value(self, symbol):
        key = symbol if symbol.startswith('CONFIG_') else f'CONFIG_{symbol}'
        return self.configs.get(key)

    def is_builtin(self, symbol):
        key = symbol if symbol.startswith('CONFIG_') else f'CONFIG_{symbol}'
        return self.configs.get(key) == 'y'

    def is_module(self, symbol):
        key = symbol if symbol.startswith('CONFIG_') else f'CONFIG_{symbol}'
        return self.configs.get(key) == 'm'

    @property
    def enabled_count(self):
        return len(self.configs)

    @property
    def disabled_count(self):
        return len(self.disabled)

    def summary(self):
        builtin = sum(1 for v in self.configs.values() if v == 'y')
        modules = sum(1 for v in self.configs.values() if v == 'm')
        strings = sum(1 for v in self.configs.values() if v not in ('y', 'm'))
        return {
            'total_enabled': self.enabled_count,
            'builtin': builtin,
            'modules': modules,
            'string_or_int': strings,
            'disabled': self.disabled_count,
        }


# ---------------------------------------------------------------------------
# Makefile Parser
# ---------------------------------------------------------------------------
class MakefileParser:
    """
    Parse kernel Makefiles to extract obj-y / obj-m / obj-$(CONFIG_XXX)
    conditional compilation rules.
    """

    # Patterns to match in Makefile lines
    RE_OBJ_CONFIG = re.compile(
        r'obj-\$\((CONFIG_\w+)\)\s*[\+:]?=\s*(.+)')
    RE_OBJ_Y = re.compile(
        r'obj-y\s*[\+:]?=\s*(.+)')
    RE_OBJ_M = re.compile(
        r'obj-m\s*[\+:]?=\s*(.+)')
    RE_SUBDIR_CONFIG = re.compile(
        r'subdir-\$\((CONFIG_\w+)\)\s*[\+:]?=\s*(.+)')
    RE_SUBDIR_Y = re.compile(
        r'subdir-y\s*[\+:]?=\s*(.+)')
    RE_COMPOSITE = re.compile(
        r'(\w[\w-]*)-(?:y|objs)\s*[\+:]?=\s*(.+)')
    RE_CCFLAGS = re.compile(
        r'(ccflags-y|CFLAGS_\w+|subdir-ccflags-y|asflags-y)\s*[\+:]?=\s*(.+)')
    RE_IFDEF = re.compile(
        r'^\s*(?:ifdef|ifeq)\s+.*?(CONFIG_\w+)')
    RE_DTBO_CONFIG = re.compile(
        r'dtbo-\$\((CONFIG_\w+)\)\s*[\+:]?=\s*(.+)')

    def __init__(self, kernel_dir):
        self.kernel_dir = Path(kernel_dir)

    def parse_makefile(self, makefile_path):
        """Parse a single Makefile. Returns a list of rule dicts."""
        rules = []
        if not os.path.isfile(makefile_path):
            return rules

        # Read and join continuation lines
        lines = self._read_and_join_lines(makefile_path)

        in_ifdef = None  # Track ifdef CONFIG_XXX blocks

        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue

            # Track ifdef blocks
            m_ifdef = self.RE_IFDEF.match(stripped)
            if m_ifdef:
                in_ifdef = m_ifdef.group(1)
                continue
            if stripped.startswith('endif'):
                in_ifdef = None
                continue

            # obj-$(CONFIG_XXX) += file.o dir/
            m = self.RE_OBJ_CONFIG.match(stripped)
            if m:
                config_sym = m.group(1)
                targets = self._split_targets(m.group(2))
                for t in targets:
                    rules.append({
                        'type': 'obj-config',
                        'config': config_sym,
                        'target': t,
                        'is_dir': t.endswith('/'),
                        'extra_ifdef': in_ifdef,
                    })
                continue

            # obj-y += file.o dir/
            m = self.RE_OBJ_Y.match(stripped)
            if m:
                targets = self._split_targets(m.group(1))
                for t in targets:
                    rules.append({
                        'type': 'obj-y',
                        'config': None,
                        'target': t,
                        'is_dir': t.endswith('/'),
                        'extra_ifdef': in_ifdef,
                    })
                continue

            # obj-m += file.o
            m = self.RE_OBJ_M.match(stripped)
            if m:
                targets = self._split_targets(m.group(1))
                for t in targets:
                    rules.append({
                        'type': 'obj-m',
                        'config': None,
                        'target': t,
                        'is_dir': t.endswith('/'),
                        'extra_ifdef': in_ifdef,
                    })
                continue

            # subdir-$(CONFIG_XXX) += dir
            m = self.RE_SUBDIR_CONFIG.match(stripped)
            if m:
                config_sym = m.group(1)
                targets = self._split_targets(m.group(2))
                for t in targets:
                    rules.append({
                        'type': 'subdir-config',
                        'config': config_sym,
                        'target': t.rstrip('/') + '/',
                        'is_dir': True,
                        'extra_ifdef': in_ifdef,
                    })
                continue

            # subdir-y += dir
            m = self.RE_SUBDIR_Y.match(stripped)
            if m:
                targets = self._split_targets(m.group(1))
                for t in targets:
                    rules.append({
                        'type': 'subdir-y',
                        'config': None,
                        'target': t.rstrip('/') + '/',
                        'is_dir': True,
                        'extra_ifdef': in_ifdef,
                    })
                continue

            # composite object: foo-y += bar.o baz.o
            m = self.RE_COMPOSITE.match(stripped)
            if m:
                obj_name = m.group(1)
                parts = self._split_targets(m.group(2))
                rules.append({
                    'type': 'composite',
                    'target': obj_name,
                    'parts': parts,
                    'extra_ifdef': in_ifdef,
                })
                continue

            # dtbo-$(CONFIG_XXX) += file.dtbo
            m = self.RE_DTBO_CONFIG.match(stripped)
            if m:
                config_sym = m.group(1)
                targets = self._split_targets(m.group(2))
                for t in targets:
                    rules.append({
                        'type': 'dtbo-config',
                        'config': config_sym,
                        'target': t,
                        'is_dir': False,
                        'extra_ifdef': in_ifdef,
                    })
                continue

            # ccflags / CFLAGS
            m = self.RE_CCFLAGS.match(stripped)
            if m:
                rules.append({
                    'type': 'cflags',
                    'flag_var': m.group(1),
                    'value': m.group(2).strip(),
                    'extra_ifdef': in_ifdef,
                })
                continue

        return rules

    def _read_and_join_lines(self, filepath):
        """Read file and join backslash-continued lines."""
        result = []
        current = ''
        with open(filepath, 'r', errors='replace') as f:
            for raw_line in f:
                raw_line = raw_line.rstrip('\n')
                if raw_line.endswith('\\'):
                    current += raw_line[:-1] + ' '
                else:
                    current += raw_line
                    result.append(current)
                    current = ''
        if current:
            result.append(current)
        return result

    def _split_targets(self, text):
        """Split a Makefile target list, handling comments."""
        text = re.sub(r'#.*', '', text)  # Remove trailing comments
        parts = text.split()
        return [p for p in parts if p]


# ---------------------------------------------------------------------------
# Kconfig Parser (lightweight)
# ---------------------------------------------------------------------------
class KconfigParser:
    """Lightweight parser to extract config symbol metadata from Kconfig files."""

    RE_CONFIG = re.compile(r'^\s*(?:config|menuconfig)\s+(\w+)')
    RE_DEPENDS = re.compile(r'^\s*depends on\s+(.+)')
    RE_SELECT = re.compile(r'^\s*select\s+(\w+)')
    RE_HELP = re.compile(r'^\s*help\s*$')
    RE_TRISTATE = re.compile(r'^\s*tristate\s+"(.+)"')
    RE_BOOL = re.compile(r'^\s*bool\s+"(.+)"')
    RE_SOURCE = re.compile(r'^\s*source\s+"(.+)"')

    def __init__(self, kernel_dir):
        self.kernel_dir = Path(kernel_dir)
        self.symbols = {}  # symbol -> { description, type, depends, selects }

    def parse_file(self, kconfig_path):
        """Parse a single Kconfig file."""
        if not os.path.isfile(kconfig_path):
            return
        current_sym = None
        with open(kconfig_path, 'r', errors='replace') as f:
            for line in f:
                m = self.RE_CONFIG.match(line)
                if m:
                    current_sym = m.group(1)
                    self.symbols[current_sym] = {
                        'description': '',
                        'type': 'unknown',
                        'depends': [],
                        'selects': [],
                        'file': str(kconfig_path),
                    }
                    continue

                if current_sym:
                    m = self.RE_TRISTATE.match(line)
                    if m:
                        self.symbols[current_sym]['description'] = m.group(1)
                        self.symbols[current_sym]['type'] = 'tristate'
                        continue
                    m = self.RE_BOOL.match(line)
                    if m:
                        self.symbols[current_sym]['description'] = m.group(1)
                        self.symbols[current_sym]['type'] = 'bool'
                        continue
                    m = self.RE_DEPENDS.match(line)
                    if m:
                        self.symbols[current_sym]['depends'].append(m.group(1).strip())
                        continue
                    m = self.RE_SELECT.match(line)
                    if m:
                        self.symbols[current_sym]['selects'].append(m.group(1))
                        continue

    def parse_recursive(self, start_path=None):
        """Parse Kconfig files recursively from the kernel root."""
        if start_path is None:
            start_path = self.kernel_dir / 'Kconfig'
        self._parse_with_sources(str(start_path), set())

    def _parse_with_sources(self, kconfig_path, visited):
        kconfig_path = str(kconfig_path)
        if kconfig_path in visited:
            return
        visited.add(kconfig_path)
        if not os.path.isfile(kconfig_path):
            return
        self.parse_file(kconfig_path)
        # Follow source directives
        with open(kconfig_path, 'r', errors='replace') as f:
            for line in f:
                m = self.RE_SOURCE.match(line)
                if m:
                    ref = m.group(1)
                    full_path = os.path.join(self.kernel_dir, ref)
                    self._parse_with_sources(full_path, visited)


# ---------------------------------------------------------------------------
# Build Analyzer (main engine)
# ---------------------------------------------------------------------------
class BuildAnalyzer:
    """
    Combines defconfig, Kconfig, and Makefile information to determine
    what gets compiled under a given configuration.
    """

    # Core directories from the top-level Makefile
    CORE_DIRS = ['init/', 'kernel/', 'certs/', 'mm/', 'fs/', 'ipc/',
                 'security/', 'crypto/', 'block/']
    DRIVER_DIRS = ['drivers/']
    NET_DIRS = ['net/']
    LIB_DIRS = ['lib/']
    VIRT_DIRS = ['virt/']
    ARCH_DIR = 'arch/arm64/'

    def __init__(self, kernel_dir, defconfig_path, subsystem=None, verbose=False):
        self.kernel_dir = Path(kernel_dir)
        self.defconfig_path = defconfig_path
        self.subsystem = subsystem
        self.verbose = verbose

        self.defconfig = DefconfigParser(defconfig_path).parse()
        self.makefile_parser = MakefileParser(kernel_dir)
        self.kconfig_parser = KconfigParser(kernel_dir)

        # Results
        self.builtin_files = []       # (relative_dir, file.o, config_symbol)
        self.module_files = []        # (relative_dir, file.o, config_symbol)
        self.skipped_files = []       # (relative_dir, file.o, config_symbol, reason)
        self.always_compiled = []     # (relative_dir, file.o)
        self.composite_objects = {}   # obj_name -> [parts]
        self.cflags_entries = []      # (dir, flag_var, value, config)
        self.dtbo_targets = []        # (dir, target, config)
        self.dir_stack = []           # directories analyzed
        self.config_to_files = defaultdict(list)  # CONFIG_XXX -> [(dir, file)]
        self.unresolved_configs = set()  # CONFIG symbols found in Makefile but not in defconfig

    def analyze(self):
        """Run the full analysis."""
        if self.verbose:
            print(f"[*] Parsing Kconfig tree...")
        self.kconfig_parser.parse_recursive()

        if self.subsystem:
            # Analyze only one subsystem directory
            target_dir = self.kernel_dir / self.subsystem
            if target_dir.is_dir():
                self._analyze_dir(self.subsystem)
            else:
                print(f"[!] Subsystem directory not found: {self.subsystem}")
                sys.exit(1)
        else:
            # Analyze all standard kernel directories
            all_dirs = (self.CORE_DIRS + self.DRIVER_DIRS + self.NET_DIRS +
                        self.LIB_DIRS + self.VIRT_DIRS + [self.ARCH_DIR])
            for d in all_dirs:
                self._analyze_dir(d)

        return self

    def _analyze_dir(self, rel_dir):
        """Recursively analyze a directory's Makefile."""
        rel_dir = rel_dir.rstrip('/') + '/'
        if rel_dir in self.dir_stack:
            return
        self.dir_stack.append(rel_dir)

        makefile = self.kernel_dir / rel_dir / 'Makefile'
        kbuild = self.kernel_dir / rel_dir / 'Kbuild'

        target_file = None
        if makefile.is_file():
            target_file = makefile
        elif kbuild.is_file():
            target_file = kbuild

        if target_file is None:
            return

        if self.verbose:
            print(f"  [+] Analyzing {target_file.relative_to(self.kernel_dir)}")

        rules = self.makefile_parser.parse_makefile(str(target_file))

        for rule in rules:
            rtype = rule['type']
            ifdef_ctx = rule.get('extra_ifdef')

            if rtype == 'obj-config':
                config = rule['config']
                target = rule['target']
                # Check if there's an enclosing ifdef that's not met
                if ifdef_ctx and not self.defconfig.is_enabled(ifdef_ctx):
                    self.skipped_files.append((rel_dir, target, config,
                                               f'ifdef {ifdef_ctx} not met'))
                    continue

                if self.defconfig.is_builtin(config):
                    if rule['is_dir']:
                        self.builtin_files.append((rel_dir, target, config))
                        self.config_to_files[config].append((rel_dir, target))
                        self._analyze_dir(rel_dir + target)
                    else:
                        self.builtin_files.append((rel_dir, target, config))
                        self.config_to_files[config].append((rel_dir, target))
                elif self.defconfig.is_module(config):
                    if rule['is_dir']:
                        self.module_files.append((rel_dir, target, config))
                        self.config_to_files[config].append((rel_dir, target))
                        self._analyze_dir(rel_dir + target)
                    else:
                        self.module_files.append((rel_dir, target, config))
                        self.config_to_files[config].append((rel_dir, target))
                else:
                    self.skipped_files.append((rel_dir, target, config,
                                               'config not enabled'))
                    if not self.defconfig.is_enabled(config):
                        self.unresolved_configs.add(config)

            elif rtype == 'obj-y':
                target = rule['target']
                if ifdef_ctx and not self.defconfig.is_enabled(ifdef_ctx):
                    self.skipped_files.append((rel_dir, target, None,
                                               f'ifdef {ifdef_ctx} not met'))
                    continue
                self.always_compiled.append((rel_dir, target))
                if rule['is_dir']:
                    self._analyze_dir(rel_dir + target)

            elif rtype == 'obj-m':
                target = rule['target']
                if ifdef_ctx and not self.defconfig.is_enabled(ifdef_ctx):
                    continue
                self.module_files.append((rel_dir, target, '(obj-m always)'))

            elif rtype in ('subdir-config', 'subdir-y'):
                target = rule['target']
                config = rule.get('config')
                if config:
                    if self.defconfig.is_enabled(config):
                        self._analyze_dir(rel_dir + target)
                else:
                    self._analyze_dir(rel_dir + target)

            elif rtype == 'composite':
                self.composite_objects[rule['target']] = rule['parts']

            elif rtype == 'cflags':
                self.cflags_entries.append(
                    (rel_dir, rule['flag_var'], rule['value'], ifdef_ctx))

            elif rtype == 'dtbo-config':
                config = rule['config']
                target = rule['target']
                if self.defconfig.is_enabled(config):
                    self.dtbo_targets.append((rel_dir, target, config))

    def get_source_file(self, directory, obj_target):
        """Try to find the actual .c / .S source file for a .o target."""
        if obj_target.endswith('/'):
            return None
        base = obj_target.replace('.o', '')
        for ext in ['.c', '.S', '.s']:
            candidate = self.kernel_dir / directory / (base + ext)
            if candidate.is_file():
                return str(candidate.relative_to(self.kernel_dir))
        return None


# ---------------------------------------------------------------------------
# Report Generator
# ---------------------------------------------------------------------------
class ReportGenerator:
    """Generate the final build analysis report."""

    def __init__(self, analyzer, output_format='md'):
        self.analyzer = analyzer
        self.fmt = output_format

    def generate(self):
        a = self.analyzer
        lines = []

        if self.fmt == 'md':
            lines += self._md_report(a)
        else:
            lines += self._txt_report(a)

        return '\n'.join(lines)

    # -- Markdown Report ---------------------------------------------------
    def _md_report(self, a):
        L = []
        L.append('# Kernel Build Configuration Analysis Report')
        L.append('')
        L.append(f'**Generated**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}  ')
        L.append(f'**Kernel source**: `{a.kernel_dir}`  ')
        L.append(f'**Defconfig**: `{a.defconfig_path}`  ')
        if a.subsystem:
            L.append(f'**Subsystem filter**: `{a.subsystem}`  ')
        L.append('')

        # ---- Config summary ----
        summary = a.defconfig.summary()
        L.append('## 1. Defconfig Summary')
        L.append('')
        L.append(f'| Category | Count |')
        L.append(f'|----------|-------|')
        L.append(f'| Built-in (=y) | {summary["builtin"]} |')
        L.append(f'| Module (=m) | {summary["modules"]} |')
        L.append(f'| String/Int values | {summary["string_or_int"]} |')
        L.append(f'| Explicitly disabled | {summary["disabled"]} |')
        L.append(f'| **Total enabled** | **{summary["total_enabled"]}** |')
        L.append('')

        # ---- Built-in object files ----
        L.append('## 2. Built-in Object Files (obj-y / CONFIG=y)')
        L.append('')
        L.append('These files are compiled directly into vmlinux (the kernel image).')
        L.append('')
        L.append(f'Total: **{len(a.builtin_files) + len(a.always_compiled)}** entries')
        L.append('')

        # Group by directory
        builtin_by_dir = defaultdict(list)
        for d, t, cfg in a.builtin_files:
            builtin_by_dir[d].append((t, cfg))
        for d, t in a.always_compiled:
            builtin_by_dir[d].append((t, '(always)'))

        for d in sorted(builtin_by_dir.keys()):
            items = builtin_by_dir[d]
            L.append(f'### `{d}`')
            L.append('')
            L.append(f'| Object / Directory | CONFIG Symbol | Source File |')
            L.append(f'|-------------------|---------------|-------------|')
            for target, cfg in sorted(items, key=lambda x: x[0]):
                src = a.get_source_file(d, target) or ''
                cfg_display = f'`{cfg}`' if cfg and cfg != '(always)' else cfg
                L.append(f'| `{target}` | {cfg_display} | `{src}` |')
            L.append('')

        # ---- Module object files ----
        L.append('## 3. Module Object Files (CONFIG=m)')
        L.append('')
        L.append('These files are compiled as loadable kernel modules (.ko).')
        L.append('')
        L.append(f'Total: **{len(a.module_files)}** entries')
        L.append('')

        mod_by_dir = defaultdict(list)
        for d, t, cfg in a.module_files:
            mod_by_dir[d].append((t, cfg))

        for d in sorted(mod_by_dir.keys()):
            items = mod_by_dir[d]
            L.append(f'### `{d}`')
            L.append('')
            L.append(f'| Object / Directory | CONFIG Symbol | Source File |')
            L.append(f'|-------------------|---------------|-------------|')
            for target, cfg in sorted(items, key=lambda x: x[0]):
                src = a.get_source_file(d, target) or ''
                cfg_display = f'`{cfg}`' if cfg else ''
                L.append(f'| `{target}` | {cfg_display} | `{src}` |')
            L.append('')

        # ---- Skipped (not compiled) ----
        L.append('## 4. Skipped / Not Compiled Files')
        L.append('')
        L.append('These entries exist in Makefiles but will NOT be compiled ')
        L.append('because their CONFIG option is disabled or unset.')
        L.append('')
        L.append(f'Total: **{len(a.skipped_files)}** entries')
        L.append('')
        L.append('<details>')
        L.append('<summary>Click to expand full list</summary>')
        L.append('')
        L.append(f'| Directory | Object | CONFIG Symbol | Reason |')
        L.append(f'|-----------|--------|---------------|--------|')
        for d, t, cfg, reason in sorted(a.skipped_files, key=lambda x: x[0]):
            cfg_display = f'`{cfg}`' if cfg else ''
            L.append(f'| `{d}` | `{t}` | {cfg_display} | {reason} |')
        L.append('')
        L.append('</details>')
        L.append('')

        # ---- Composite objects ----
        if a.composite_objects:
            L.append('## 5. Composite Objects (multi-file modules)')
            L.append('')
            L.append('These objects are built from multiple source files.')
            L.append('')
            for name, parts in sorted(a.composite_objects.items()):
                L.append(f'- **{name}.o** = {", ".join(f"`{p}`" for p in parts)}')
            L.append('')

        # ---- Device Tree Overlays ----
        if a.dtbo_targets:
            L.append('## 6. Device Tree Blob Overlays (DTBO)')
            L.append('')
            L.append(f'| Directory | DTBO Target | CONFIG Symbol |')
            L.append(f'|-----------|-------------|---------------|')
            for d, t, cfg in sorted(a.dtbo_targets):
                L.append(f'| `{d}` | `{t}` | `{cfg}` |')
            L.append('')

        # ---- CONFIG -> Files mapping ----
        L.append('## 7. CONFIG Symbol to Files Mapping')
        L.append('')
        L.append('Quick lookup: which files does each CONFIG symbol control?')
        L.append('')
        L.append('<details>')
        L.append('<summary>Click to expand full mapping</summary>')
        L.append('')
        for cfg in sorted(a.config_to_files.keys()):
            files = a.config_to_files[cfg]
            val = a.defconfig.get_value(cfg) or 'n'
            L.append(f'### `{cfg}` = {val}')
            L.append('')
            # Kconfig info
            sym_name = cfg.replace('CONFIG_', '')
            if sym_name in a.kconfig_parser.symbols:
                info = a.kconfig_parser.symbols[sym_name]
                if info['description']:
                    L.append(f'> {info["description"]}')
                if info['depends']:
                    L.append(f'> Depends on: {", ".join(info["depends"])}')
                if info['selects']:
                    L.append(f'> Selects: {", ".join(info["selects"])}')
                L.append('')
            for d, f in files:
                src = a.get_source_file(d, f) or ''
                L.append(f'- `{d}{f}`' + (f' -> `{src}`' if src else ''))
            L.append('')
        L.append('</details>')
        L.append('')

        # ---- Compiler flags ----
        if a.cflags_entries:
            L.append('## 8. Compiler Flags (ccflags / CFLAGS)')
            L.append('')
            L.append(f'| Directory | Variable | Value | Condition |')
            L.append(f'|-----------|----------|-------|-----------|')
            for d, var, val, cond in sorted(a.cflags_entries):
                cond_str = f'`{cond}`' if cond else ''
                L.append(f'| `{d}` | `{var}` | `{val}` | {cond_str} |')
            L.append('')

        # ---- Directories analyzed ----
        L.append('## 9. Analyzed Directories')
        L.append('')
        L.append(f'Total directories scanned: **{len(a.dir_stack)}**')
        L.append('')
        L.append('<details>')
        L.append('<summary>Click to expand</summary>')
        L.append('')
        for d in sorted(a.dir_stack):
            L.append(f'- `{d}`')
        L.append('')
        L.append('</details>')
        L.append('')

        # ---- Build verification checklist ----
        L.append('## 10. Build Verification Checklist')
        L.append('')
        L.append('Use this section to verify your build matches your expectations.')
        L.append('')
        L.append('### Key Platform Configs')
        L.append('')
        key_configs = [
            'CONFIG_ARCH_QCOM', 'CONFIG_ARCH_LAHAINA',
            'CONFIG_QCOM_LAHAINA_LLCC', 'CONFIG_BUILD_ARM64_DT_OVERLAY',
            'CONFIG_LTO_CLANG', 'CONFIG_CFI_CLANG',
            'CONFIG_OPLUS_SYSTEM_KERNEL', 'CONFIG_OPLUS_CHG',
            'CONFIG_OPLUS_SM8350_CHARGER', 'CONFIG_MODULES',
            'CONFIG_OPLUS_DEVICE_IFNO', 'CONFIG_OPLUS_FINGERPRINT',
            'CONFIG_TOUCHPANEL_OPLUS',
        ]
        L.append(f'| CONFIG Symbol | Expected | Actual | Match |')
        L.append(f'|--------------|----------|--------|-------|')
        for cfg in key_configs:
            actual = a.defconfig.get_value(cfg)
            if actual is None:
                actual_str = 'not set'
            else:
                actual_str = actual
            L.append(f'| `{cfg}` | y | {actual_str} | '
                     f'{"YES" if actual_str == "y" else "**NO**"} |')
        L.append('')

        L.append('### How to Use This Report')
        L.append('')
        L.append('1. **Check your defconfig**: Compare the CONFIG values in Section 1 ')
        L.append('   with your `.config` or defconfig to ensure they match.')
        L.append('2. **Verify compiled files**: Section 2 lists all files compiled into ')
        L.append('   the kernel. If a driver you need is missing, check its CONFIG symbol ')
        L.append('   in Section 4 (skipped files).')
        L.append('3. **Module verification**: Section 3 lists modules. Ensure the modules ')
        L.append('   you need are being built (CONFIG=m).')
        L.append('4. **Find a CONFIG**: Use Section 7 to look up which files are controlled ')
        L.append('   by a specific CONFIG symbol and its Kconfig description.')
        L.append('5. **Cross-reference**: If a file is in Section 4 but you want it ')
        L.append('   compiled, enable its CONFIG symbol in your defconfig and rebuild.')
        L.append('')

        # ---- Full enabled config list ----
        L.append('## Appendix A: Full Enabled CONFIG List')
        L.append('')
        L.append('<details>')
        L.append('<summary>Click to expand (all enabled symbols)</summary>')
        L.append('')
        L.append('```')
        for key, val in a.defconfig.configs.items():
            L.append(f'{key}={val}')
        L.append('```')
        L.append('')
        L.append('</details>')
        L.append('')

        L.append('---')
        L.append('*Generated by `scripts/kbuild_analysis.py`*')

        return L

    # -- Plain text report -------------------------------------------------
    def _txt_report(self, a):
        L = []
        L.append('=' * 72)
        L.append(' Kernel Build Configuration Analysis Report')
        L.append('=' * 72)
        L.append(f'Generated:     {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
        L.append(f'Kernel source: {a.kernel_dir}')
        L.append(f'Defconfig:     {a.defconfig_path}')
        if a.subsystem:
            L.append(f'Subsystem:     {a.subsystem}')
        L.append('')

        summary = a.defconfig.summary()
        L.append('-' * 40)
        L.append(' DEFCONFIG SUMMARY')
        L.append('-' * 40)
        L.append(f'  Built-in (=y):      {summary["builtin"]}')
        L.append(f'  Module (=m):        {summary["modules"]}')
        L.append(f'  String/Int values:  {summary["string_or_int"]}')
        L.append(f'  Explicitly disabled:{summary["disabled"]}')
        L.append(f'  Total enabled:      {summary["total_enabled"]}')
        L.append('')

        L.append('-' * 40)
        L.append(' BUILT-IN FILES (compiled into vmlinux)')
        L.append('-' * 40)
        L.append(f'  Total: {len(a.builtin_files) + len(a.always_compiled)} entries')
        L.append('')

        builtin_by_dir = defaultdict(list)
        for d, t, cfg in a.builtin_files:
            builtin_by_dir[d].append((t, cfg))
        for d, t in a.always_compiled:
            builtin_by_dir[d].append((t, '(always)'))

        for d in sorted(builtin_by_dir.keys()):
            L.append(f'  [{d}]')
            for target, cfg in sorted(builtin_by_dir[d], key=lambda x: x[0]):
                src = a.get_source_file(d, target) or ''
                L.append(f'    {target:<40} {cfg:<35} {src}')
            L.append('')

        L.append('-' * 40)
        L.append(' MODULE FILES (compiled as .ko)')
        L.append('-' * 40)
        L.append(f'  Total: {len(a.module_files)} entries')
        L.append('')

        mod_by_dir = defaultdict(list)
        for d, t, cfg in a.module_files:
            mod_by_dir[d].append((t, cfg))

        for d in sorted(mod_by_dir.keys()):
            L.append(f'  [{d}]')
            for target, cfg in sorted(mod_by_dir[d], key=lambda x: x[0]):
                src = a.get_source_file(d, target) or ''
                L.append(f'    {target:<40} {cfg:<35} {src}')
            L.append('')

        L.append('-' * 40)
        L.append(' SKIPPED / NOT COMPILED')
        L.append('-' * 40)
        L.append(f'  Total: {len(a.skipped_files)} entries')
        L.append('')
        for d, t, cfg, reason in sorted(a.skipped_files, key=lambda x: x[0]):
            cfg_str = cfg or ''
            L.append(f'    {d}{t:<35} {cfg_str:<35} [{reason}]')
        L.append('')

        if a.composite_objects:
            L.append('-' * 40)
            L.append(' COMPOSITE OBJECTS')
            L.append('-' * 40)
            for name, parts in sorted(a.composite_objects.items()):
                L.append(f'  {name}.o = {", ".join(parts)}')
            L.append('')

        L.append('-' * 40)
        L.append(' DIRECTORIES ANALYZED')
        L.append('-' * 40)
        L.append(f'  Total: {len(a.dir_stack)}')
        for d in sorted(a.dir_stack):
            L.append(f'    {d}')
        L.append('')

        L.append('-' * 40)
        L.append(' KEY PLATFORM CONFIG CHECK')
        L.append('-' * 40)
        key_configs = [
            'CONFIG_ARCH_QCOM', 'CONFIG_ARCH_LAHAINA',
            'CONFIG_QCOM_LAHAINA_LLCC', 'CONFIG_BUILD_ARM64_DT_OVERLAY',
            'CONFIG_LTO_CLANG', 'CONFIG_CFI_CLANG',
            'CONFIG_OPLUS_SYSTEM_KERNEL', 'CONFIG_OPLUS_CHG',
            'CONFIG_OPLUS_SM8350_CHARGER', 'CONFIG_MODULES',
        ]
        for cfg in key_configs:
            actual = a.defconfig.get_value(cfg) or 'not set'
            match = 'OK' if actual == 'y' else 'MISSING'
            L.append(f'  {cfg:<45} = {actual:<10} [{match}]')
        L.append('')

        L.append('=' * 72)
        L.append(' Generated by scripts/kbuild_analysis.py')
        L.append('=' * 72)

        return L


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
def find_defconfigs(kernel_dir):
    """List all defconfig files under arch/arm64/configs/."""
    configs_dir = Path(kernel_dir) / 'arch' / 'arm64' / 'configs'
    defconfigs = []
    for root, dirs, files in os.walk(configs_dir):
        for f in files:
            if f.endswith('_defconfig') or f.endswith('.config'):
                rel = os.path.relpath(os.path.join(root, f), configs_dir)
                defconfigs.append(rel)
    return sorted(defconfigs)


def main():
    parser = argparse.ArgumentParser(
        description='Kernel Build Configuration Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)

    parser.add_argument('-k', '--kernel-dir', default=None,
                        help='Kernel source root directory')
    parser.add_argument('-d', '--defconfig',
                        default='vendor/lahaina-qgki_defconfig',
                        help='Defconfig file (relative to arch/arm64/configs/ or absolute)')
    parser.add_argument('-o', '--output', default=None,
                        help='Output report file path')
    parser.add_argument('-f', '--format', choices=['txt', 'md'], default='md',
                        help='Report format: txt or md (default: md)')
    parser.add_argument('-s', '--subsystem', default=None,
                        help='Only analyze a specific subsystem directory')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose output during analysis')
    parser.add_argument('--list-defconfigs', action='store_true',
                        help='List available defconfig files')

    args = parser.parse_args()

    # Determine kernel directory
    if args.kernel_dir:
        kernel_dir = os.path.abspath(args.kernel_dir)
    else:
        # Default: parent of scripts/ directory
        kernel_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    if not os.path.isfile(os.path.join(kernel_dir, 'Makefile')):
        print(f'Error: {kernel_dir} does not look like a kernel source tree.')
        sys.exit(1)

    # List defconfigs and exit
    if args.list_defconfigs:
        print('Available defconfig files:')
        for dc in find_defconfigs(kernel_dir):
            print(f'  {dc}')
        sys.exit(0)

    # Resolve defconfig path
    if os.path.isabs(args.defconfig):
        defconfig_path = args.defconfig
    else:
        defconfig_path = os.path.join(
            kernel_dir, 'arch', 'arm64', 'configs', args.defconfig)

    if not os.path.isfile(defconfig_path):
        print(f'Error: defconfig not found: {defconfig_path}')
        print('Available defconfigs:')
        for dc in find_defconfigs(kernel_dir):
            print(f'  {dc}')
        sys.exit(1)

    # Default output path
    if args.output:
        output_path = args.output
    else:
        ext = 'md' if args.format == 'md' else 'txt'
        output_path = os.path.join(kernel_dir, f'build_analysis_report.{ext}')

    print(f'Kernel Build Configuration Analyzer')
    print(f'===================================')
    print(f'Kernel dir:  {kernel_dir}')
    print(f'Defconfig:   {defconfig_path}')
    print(f'Output:      {output_path}')
    print(f'Format:      {args.format}')
    if args.subsystem:
        print(f'Subsystem:   {args.subsystem}')
    print()

    # Run analysis
    print('[1/3] Parsing defconfig and Kconfig...')
    analyzer = BuildAnalyzer(
        kernel_dir, defconfig_path,
        subsystem=args.subsystem, verbose=args.verbose)

    print('[2/3] Analyzing Makefiles...')
    analyzer.analyze()

    print('[3/3] Generating report...')
    report = ReportGenerator(analyzer, output_format=args.format)
    content = report.generate()

    with open(output_path, 'w') as f:
        f.write(content)

    # Print summary
    n_builtin = len(analyzer.builtin_files) + len(analyzer.always_compiled)
    n_module = len(analyzer.module_files)
    n_skipped = len(analyzer.skipped_files)
    n_dirs = len(analyzer.dir_stack)
    summary = analyzer.defconfig.summary()

    print()
    print(f'Analysis complete!')
    print(f'  Config symbols enabled: {summary["total_enabled"]}')
    print(f'    - Built-in (=y):      {summary["builtin"]}')
    print(f'    - Module (=m):        {summary["modules"]}')
    print(f'  Files compiled (built-in): {n_builtin}')
    print(f'  Files compiled (module):   {n_module}')
    print(f'  Files skipped:             {n_skipped}')
    print(f'  Directories scanned:       {n_dirs}')
    print(f'  Composite objects:         {len(analyzer.composite_objects)}')
    print()
    print(f'Report written to: {output_path}')


if __name__ == '__main__':
    main()
