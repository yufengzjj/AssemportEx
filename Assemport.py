import os
import re
import sys
import traceback
import unicodedata

import ida_bytes
import ida_fpro
import ida_funcs
import ida_ida
import ida_idaapi
import ida_idp
import ida_kernwin
import ida_lines
import ida_loader
import ida_name
import ida_range
import ida_segment
import ida_ua
import ida_xref
import idaapi
import idautils

_WIN_ILLEGAL_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f\x7f]')

_WIN_RESERVED_NAMES = (
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{i}" for i in range(1, 10)}
    | {f"LPT{i}" for i in range(1, 10)}
    | {
        "COM\u00b9",
        "COM\u00b2",
        "COM\u00b3",  # 上标 1/2/3,Win11 也保留
        "LPT\u00b9",
        "LPT\u00b2",
        "LPT\u00b3",
    }
)
_POSIX_ILLEGAL_CHARS = re.compile(r"[/\x00]")


def sanitize_path(path, replacement="_", max_component_bytes=255):
    path = os.fspath(path)
    path = unicodedata.normalize("NFC", path)
    if _WIN_ILLEGAL_CHARS.search(replacement) or _POSIX_ILLEGAL_CHARS.search(replacement):
        raise ValueError(f"replacement {replacement!r} illegal")
    drive, rest = os.path.splitdrive(path)
    is_absolute = rest.startswith(("/", "\\"))
    components = re.split(r"[/\\]+", rest)
    cleaned_components = []
    for comp in components:
        if not comp:
            continue
        cleaned = _sanitize_component(comp, replacement, max_component_bytes)
        if cleaned:
            cleaned_components.append(cleaned)
    sep = os.sep
    body = sep.join(cleaned_components)

    if drive:
        result = drive + sep + body if body else drive + sep
    elif is_absolute:
        result = sep + body
    else:
        result = body

    return _safe_path(result)


def _safe_path(path):
    path = os.fspath(path)
    if sys.platform == "win32":
        path = os.path.abspath(path)
        if not path.startswith("\\\\?\\"):
            if path.startswith("\\\\"):
                path = "\\\\?\\UNC\\" + path[2:]
            else:
                path = "\\\\?\\" + path
    return path


def _sanitize_component(name, replacement, max_bytes):
    name = _WIN_ILLEGAL_CHARS.sub(replacement, name)
    name = _POSIX_ILLEGAL_CHARS.sub(replacement, name)
    if name in (".", ".."):
        return replacement * len(name)  # '.' -> '_', '..' -> '__'
    name = name.rstrip(" .")
    if not name:
        return replacement
    stem = name.split(".", 1)[0].upper()
    if stem in _WIN_RESERVED_NAMES:
        name = replacement + name  # 加前缀避开保留名
    name = _truncate_to_bytes(name, max_bytes)
    return name


def _truncate_to_bytes(name, max_bytes, encoding="utf-8"):
    if len(name.encode(encoding)) <= max_bytes:
        return name
    if "." in name:
        stem, ext = name.rsplit(".", 1)
        ext = "." + ext
        ext_bytes = ext.encode(encoding)
        if len(ext_bytes) > 32:
            stem, ext = name, ""
            ext_bytes = b""
    else:
        stem, ext = name, ""
        ext_bytes = b""
    budget = max_bytes - len(ext_bytes)
    if budget <= 0:
        return _truncate_bytes_safe(name, max_bytes, encoding)
    stem_truncated = _truncate_bytes_safe(stem, budget, encoding)
    return stem_truncated + ext


def _truncate_bytes_safe(s, max_bytes, encoding="utf-8"):
    encoded = s.encode(encoding)
    if len(encoded) <= max_bytes:
        return s
    truncated = encoded[:max_bytes]
    # 'ignore' 会丢弃末尾不完整的多字节序列
    return truncated.decode(encoding, errors="ignore")


# Action handlers for context menu
class ExportSingleFunctionHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        # Get the current function at cursor position
        if hasattr(ctx, "cur_ea"):
            ea = ctx.cur_ea
        else:
            ea = ida_kernwin.get_screen_ea()

        # Fall back to a synthetic function when IDA hasn't defined one here;
        # unhide_func_and_export_asm reconstructs the range from control flow.
        func = ida_funcs.get_func(ea) or _NoFunc(ea)

        # Export just this function
        export_single_function(func)
        return 1

    def update(self, ctx):
        # Always available in the disassembly view; works on undefined code too.
        return ida_kernwin.AST_ENABLE


def is_functions_window(ctx):
    """Check if the context is from the Functions window (handles IDA 9.0 BWN_CHOOSER)"""
    if not ctx:
        return False

    widget_type = getattr(ctx, "widget_type", -1)
    widget_title = ""
    if hasattr(ctx, "widget"):
        widget_title = ida_kernwin.get_widget_title(ctx.widget) or ""

    # Debug: Uncomment to see all widget types/titles
    # print(f"[Assemport] is_functions_window: type={widget_type}, title='{widget_title}'")

    if widget_type == ida_kernwin.BWN_FUNCS:
        return True
    # IDA 9.0 Functions window is often a chooser with "Functions" in title
    return widget_type == ida_kernwin.BWN_CHOOSER and "Functions" in widget_title


class ExportSelectedFunctionsHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        # Get selected functions from Functions window if it's active
        if is_functions_window(ctx):
            # Get selection from the Functions window
            selection = ctx.chooser_selection if hasattr(ctx, "chooser_selection") else []
            if not selection:
                ida_kernwin.warning("No functions selected")
                return 1

            # Export selected functions
            export_selected_functions(selection)
        else:
            ida_kernwin.warning("This action is only available in the Functions window")
        return 1

    def update(self, ctx):
        # Enable only in Functions window with selection
        if is_functions_window(ctx):
            return ida_kernwin.AST_ENABLE if hasattr(ctx, "chooser_selection") and ctx.chooser_selection else ida_kernwin.AST_DISABLE
        return ida_kernwin.AST_DISABLE


class ExportRecursiveFunctionHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        # Get the current function at cursor position
        if hasattr(ctx, "cur_ea"):
            ea = ctx.cur_ea
        else:
            ea = ida_kernwin.get_screen_ea()

        # Fall back to the raw address when IDA hasn't defined a function here;
        # the recursive walk reconstructs undefined code from control flow.
        func = ida_funcs.get_func(ea)
        start_ea = func.start_ea if func else ea

        # Export this function and all sub-calls recursively
        export_recursive_functions(start_ea)
        return 1

    def update(self, ctx):
        # Always available in the disassembly view; works on undefined code too.
        return ida_kernwin.AST_ENABLE


# UI Hooks for context menu
class AssemportUIHooks(ida_kernwin.UI_Hooks):
    def __init__(self):
        ida_kernwin.UI_Hooks.__init__(self)

    def populating_widget_popup(self, widget, popup_handle, ctx):  # ty:ignore[invalid-method-override]
        # Add context menu items based on widget type
        if ctx is None:
            return

        # For any disassembly view - add single function export
        widget_type = ida_kernwin.get_widget_type(widget)
        if widget_type in [ida_kernwin.BWN_DISASM, ida_kernwin.BWN_PSEUDOCODE]:
            # ASM export works on any address: when IDA hasn't defined a
            # function here, the export falls back to reconstruct_func_range,
            # so always offer it in the disassembly view.
            ida_kernwin.attach_action_to_popup(widget, popup_handle, "assemport:export_single", None)  # ty:ignore[invalid-argument-type]
            # Add recursive export action
            ida_kernwin.attach_action_to_popup(widget, popup_handle, "assemport:export_recursive", None)  # ty:ignore[invalid-argument-type]

        # For Functions window - add selected functions export
        elif widget_type == ida_kernwin.BWN_FUNCS or (
            widget_type == ida_kernwin.BWN_CHOOSER and "Functions" in (ida_kernwin.get_widget_title(widget) or "")
        ):
            if hasattr(ctx, "chooser_selection"):
                ida_kernwin.attach_action_to_popup(widget, popup_handle, "assemport:export_selected", None)  # ty:ignore[invalid-argument-type]


def get_loose_data_range(ea, max_explore_len=0):
    end_ea = ea
    while True:
        if end_ea == idaapi.BADADDR or not ida_bytes.is_mapped(end_ea):
            break
        name = ida_name.get_name(end_ea)
        if end_ea != ea and name:
            break
        next_ea = ida_bytes.get_item_end(end_ea)
        if next_ea <= end_ea or next_ea == idaapi.BADADDR:
            break
        end_ea = next_ea
        if max_explore_len <= 0 or end_ea - ea >= max_explore_len:
            break
    return ida_range.range_t(ea, end_ea)


def _is_range_covered(existing, new_start: int, new_end: int) -> bool:
    """True if any (start, end) pair in `existing` fully covers
    [new_start, new_end) -- i.e. start <= new_start and new_end <= end."""
    for s, e in existing:
        if s <= new_start and new_end <= e:
            return True
    return False


def check_func_range(ranges: list, ref: int, cur_func: ida_funcs.func_t, funcs_to_export: list | None, processed_ranges: set):
    """check the possible func range(or just a commom code chunk)"""
    func = ida_funcs.get_func(ref)
    if func and func.start_ea != cur_func.start_ea:
        if ref == func.start_ea:
            if funcs_to_export is not None:
                funcs_to_export.extend(get_recursive_functions(func.start_ea, False))
        else:
            if func.start_ea <= ref < func.end_ea:
                r = ida_range.range_t(ref, func.end_ea)
                if not _is_range_covered(processed_ranges, r.start_ea, r.end_ea):
                    ranges.append(r)
            else:
                for s, e in reconstruct_func_range(ref):
                    r = ida_range.range_t(s, e)
                    if not _is_range_covered(processed_ranges, s, e):
                        ranges.append(r)
    elif not func:
        for s, e in reconstruct_func_range(ref):
            r = ida_range.range_t(s, e)
            if not _is_range_covered(processed_ranges, s, e):
                ranges.append(r)


def check_c_ref_range(
    ranges: list, addr: int, cur_range: tuple[int, int], cur_func: ida_funcs.func_t, funcs_to_export: list | None, processed_ranges: set
):
    """check code ref at addr"""
    for ref in idautils.XrefsFrom(addr, ida_xref.XREF_FAR):
        if cur_range[0] <= ref.to < cur_range[1]:
            continue
        if ref.type in (ida_xref.fl_CN, ida_xref.fl_CF):
            if funcs_to_export is not None:
                funcs_to_export.extend(get_recursive_functions(ref.to))
            continue
        check_func_range(ranges, ref.to, cur_func, funcs_to_export, processed_ranges)


def get_ref_from_insn(ea):
    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, ea) == 0:
        return None

    mn = insn.get_canon_mnem()
    if mn not in ("ADR", "ADRL", "ADRP", "LDR"):
        return None
    if mn in ("ADRP", "LDR"):
        for xref in idautils.XrefsFrom(ea, idaapi.XREF_DATA):
            return xref.to
    for op in insn.ops:
        if op.type in (idaapi.o_mem, idaapi.o_imm, idaapi.o_far, idaapi.o_near):
            if op.addr != 0 and op.addr != idaapi.BADADDR:
                return op.addr
            if op.value != 0 and op.value != idaapi.BADADDR:
                return op.value
    return None


def check_o_ref_range(
    ranges: list,
    cur_range: tuple[int, int],
    cur_func: ida_funcs.func_t,
    funcs_to_export: list | None,
    processed_ranges: set,
    skip_named_data: bool = False,
    max_explore_len: int = 0,
):
    """check code opraand ref in cur_range"""
    for head in idautils.Heads(*cur_range):
        o_ref = get_ref_from_insn(head)
        if o_ref is None:
            continue
        if cur_range[0] <= o_ref < cur_range[1]:
            continue
        if o_ref == idaapi.BADADDR or not ida_bytes.is_mapped(o_ref):
            continue
        o_flags = ida_bytes.get_flags(o_ref)
        if ida_bytes.is_code(o_flags):
            if funcs_to_export is not None:
                funcs_to_export.extend(get_recursive_functions(o_ref))
        elif ida_bytes.is_data(o_flags):
            if skip_named_data and ida_bytes.has_name(o_flags):
                continue
            r = ida_range.range_t(o_ref, o_ref + ida_bytes.get_item_size(o_ref))
            if not _is_range_covered(processed_ranges, r.start_ea, r.end_ea):
                ranges.append(r)
        else:
            if skip_named_data and ida_bytes.has_name(o_flags):
                continue
            r = get_loose_data_range(o_ref, max_explore_len)
            if not _is_range_covered(processed_ranges, r.start_ea, r.end_ea):
                ranges.append(r)


def check_d_ref_range(
    ranges: list,
    cur_range: tuple[int, int],
    cur_func: ida_funcs.func_t,
    funcs_to_export: list | None,
    processed_ranges: set,
    skip_named_data: bool = False,
    max_explore_len: int = 0,
):
    """check data ref"""
    ea = cur_range[0]
    ptr_size = ida_ida.inf_get_app_bitness() // 8
    while ea < cur_range[1]:
        next_ea = ida_bytes.get_item_end(ea)
        if next_ea <= ea or next_ea == idaapi.BADADDR:
            break
        if ida_bytes.get_item_size(ea) == ptr_size:
            data = ida_bytes.get_bytes(ea, ptr_size)
            if data is not None and len(data) == ptr_size:
                ptr = int.from_bytes(data, "big" if ida_ida.inf_is_be() else "little")
                if (
                    not (cur_range[0] <= ptr < cur_range[1])
                    and ptr != 0
                    and ptr != idaapi.BADADDR
                    and ida_bytes.is_mapped(ptr)
                    and ida_segment.segtype(ptr) != ida_segment.SEG_XTRN
                ):
                    flags = ida_bytes.get_flags(ptr)
                    if ida_bytes.is_code(flags):
                        if funcs_to_export is not None:
                            funcs_to_export.extend(get_recursive_functions(ptr))
                    elif not (skip_named_data and ida_bytes.has_name(flags)):
                        r = get_loose_data_range(ptr, max_explore_len)
                        if not _is_range_covered(processed_ranges, r.start_ea, r.end_ea):
                            ranges.append(r)
        ea = next_ea


def check_hidden_range(start: int, end: int, hidden_ranges: list):
    curr_ea = start
    while curr_ea < end:
        hr = ida_bytes.get_hidden_range(curr_ea)
        if not hr:
            hr = ida_bytes.get_next_hidden_range(curr_ea)
            if not hr or hr.start_ea >= end:
                break
        hidden_ranges.append(
            (
                hr.start_ea,
                hr.end_ea,
                hr.description,
                hr.header,
                hr.footer,
                hr.color,
            )
        )
        ida_bytes.del_hidden_range(hr.start_ea)
        curr_ea = hr.end_ea  # Move to end of deleted range


def unhide_func_and_export_asm(func, file, funcs_to_export: list | None = None, processed_ranges: set | None = None):
    """Temporarily unhide function and its chunks, then export to ASM"""
    hidden_funcs = []
    if func.flags & ida_funcs.FUNC_HIDDEN:
        hidden_funcs.append(func)
        func.flags &= ~ida_funcs.FUNC_HIDDEN
        ida_funcs.update_func(func)
    skip_code_refs = get_skip_code_refs_setting()
    skip_data_refs = get_skip_data_refs_setting()
    skip_named_data = get_skip_named_data_setting()
    max_explore_len = get_loose_data_len_setting()
    processed_ranges = set() if processed_ranges is None else processed_ranges
    try:
        all_ranges = []
        if func.end_ea == ida_idaapi.BADADDR:
            for s, e in reconstruct_func_range(func.start_ea):
                if not _is_range_covered(processed_ranges, s, e):
                    all_ranges.append(ida_range.range_t(s, e))
        else:
            ranges = ida_range.rangeset_t()
            ida_funcs.get_func_ranges(ranges, func)
            all_ranges = [ranges.getrange(i) for i in range(ranges.nranges())]
        all_ranges.sort(key=lambda r: (0 if r.start_ea == func.start_ea else 1, r.start_ea))
        data_ranges = []
        hidden_ranges = []
        while len(all_ranges) > 0:
            r = all_ranges.pop(0)
            start, end = r.start_ea, r.end_ea
            if _is_range_covered(processed_ranges, start, end):
                continue
            if start >= end:
                continue
            check_hidden_range(start, end, hidden_ranges)
            f = ida_funcs.get_func(start)
            if f and f.start_ea != func.start_ea and f.flags & ida_funcs.FUNC_HIDDEN:
                hidden_funcs.append(f)
                f.flags &= ~ida_funcs.FUNC_HIDDEN  # ty:ignore[invalid-assignment]
                ida_funcs.update_func(f)
            flags = ida_bytes.get_flags(start)
            if ida_bytes.is_code(flags):
                if start >= func.start_ea and end <= func.end_ea and func.end_ea != idaapi.BADADDR:
                    ida_loader.gen_file(ida_loader.OFILE_ASM, file.get_fp(), start, end, 0)
                    check_c_ref_range(all_ranges, ida_bytes.prev_head(end, start), (start, end), func, funcs_to_export, processed_ranges)
                else:
                    for head in idautils.Heads(start, end):
                        r_name = ida_name.get_name(head)
                        if r_name:
                            ida_fpro._ida_fpro.qfile_t_write(file, f"{r_name}\n")  # ty:ignore[unresolved-attribute]
                        disasm = ida_lines.generate_disasm_line(head, ida_lines.GENDSM_REMOVE_TAGS | ida_lines.GENDSM_MULTI_LINE)
                        ida_fpro._ida_fpro.qfile_t_write(file, f"{ida_lines.tag_remove(disasm)}\n")  # ty:ignore[unresolved-attribute]
                        check_c_ref_range(all_ranges, head, (start, end), func, funcs_to_export, processed_ranges)
                    ida_fpro._ida_fpro.qfile_t_write(file, "\n")  # ty:ignore[unresolved-attribute]
                if not skip_code_refs:
                    check_o_ref_range(all_ranges, (start, end), func, funcs_to_export, processed_ranges, skip_named_data, max_explore_len)
            else:
                data_ranges.append(r)
                if not skip_data_refs:
                    check_d_ref_range(all_ranges, (start, end), func, funcs_to_export, processed_ranges, skip_named_data, max_explore_len)
            processed_ranges.add((start, end))
        while len(data_ranges) > 0:
            r = data_ranges.pop(0)
            start, end = r.start_ea, r.end_ea
            flags = ida_bytes.get_flags(start)
            r_name = ida_name.get_name(start)
            if ida_bytes.is_data(flags) or ida_segment.segtype(start) == ida_segment.SEG_BSS:
                disasm = ida_lines.generate_disasm_line(start, ida_lines.GENDSM_REMOVE_TAGS | ida_lines.GENDSM_MULTI_LINE)
                ida_fpro._ida_fpro.qfile_t_write(file, f"{r_name} {ida_lines.tag_remove(disasm)}\n")  # ty:ignore[unresolved-attribute]
            else:
                ida_fpro._ida_fpro.qfile_t_write(file, f"{r_name}\n")  # ty:ignore[unresolved-attribute]
                ea = start
                while ea < end:
                    disasm = ida_lines.generate_disasm_line(ea, ida_lines.GENDSM_REMOVE_TAGS | ida_lines.GENDSM_MULTI_LINE)
                    ida_fpro._ida_fpro.qfile_t_write(file, f"{ida_lines.tag_remove(disasm)}\n")  # ty:ignore[unresolved-attribute]
                    ea = ida_bytes.get_item_end(ea)

    finally:
        for f in hidden_funcs:
            f.flags |= ida_funcs.FUNC_HIDDEN  # ty:ignore[invalid-assignment]
            ida_funcs.update_func(f)
        for hr in hidden_ranges:
            ida_bytes.add_hidden_range(*hr)


def get_export_name(ea):
    """Name used for the output file/title. Falls back to the address label or
    a synthetic loc_XXXX when IDA has no function/name at `ea`."""
    name = ida_funcs.get_func_name(ea) or ida_name.get_name(ea)
    if not name:
        name = f"loc_{ea:X}"
    return name


def export_single_function(func):
    """Export a single function to assembly file"""
    ida_kernwin.show_wait_box("Exporting function...")

    try:
        # Get Working-Path
        path = os.path.dirname(ida_loader.get_path(ida_loader.PATH_TYPE_CMD))
        output = sanitize_path(os.path.join(path, "Assemport"))

        # Create Output-Directory
        try:
            os.mkdir(output)
        except FileExistsError:
            pass
        except PermissionError:
            print(f"[Assemport] Permission denied: Unable to create '{output}'.")
            return
        except Exception as e:  # noqa: BLE001
            print(f"[Assemport] An error occurred: {e}")
            return

        # Get function name (falls back for undefined code)
        func_name = get_export_name(func.start_ea)

        # Save Content
        file = ida_fpro.qfile_t()
        filename = sanitize_path(os.path.join(output, f"{func_name}.asm"))

        if file.open(filename, "wt"):
            try:
                unhide_func_and_export_asm(func, file)
                print(f"[Assemport] Exported function {func_name} to {filename}")
                ida_kernwin.info(f"Function {func_name} exported successfully!")
            finally:
                file.close()

        else:
            print(f"[Assemport] Failed to create file {filename}")

    finally:
        ida_kernwin.hide_wait_box()


def export_selected_functions(selection_indices):
    """Export selected functions from Functions window"""
    ida_kernwin.show_wait_box("Exporting selected functions...")

    try:
        # Get Working-Path
        path = os.path.dirname(ida_loader.get_path(ida_loader.PATH_TYPE_CMD))
        output = sanitize_path(os.path.join(path, "Assemport"))

        # Create Output-Directory
        try:
            os.mkdir(output)
        except FileExistsError:
            pass
        except PermissionError:
            print(f"[Assemport] Permission denied: Unable to create '{output}'.")
            return
        except Exception as e:  # noqa: BLE001
            print(f"[Assemport] An error occurred: {e}")
            return

        exported_count = 0

        # Get all functions and export selected ones
        all_functions = list(idautils.Functions())

        for idx in selection_indices:
            if idx < len(all_functions):
                ea = all_functions[idx]
                func = ida_funcs.get_func(ea)

                if func is None:
                    continue

                # Get function name
                func_name = ida_funcs.get_func_name(ea)
                # Save Content
                file = ida_fpro.qfile_t()
                filename = sanitize_path(os.path.join(output, f"{func_name}.asm"))

                if file.open(filename, "wt"):
                    try:
                        unhide_func_and_export_asm(func, file)
                        exported_count += 1
                    finally:
                        file.close()
        ida_kernwin.info(f"Exported {exported_count} functions successfully!")

    finally:
        ida_kernwin.hide_wait_box()


# Persistent settings using IDA netnode
SETTINGS_NODE_NAME = "$ assemport_settings"
SKIP_NAMED_FUNC_TAG = "S"
DEDUPE_TAG = "D"
SKIP_CODE_REFS_TAG = "C"
SKIP_DATA_REFS_TAG = "R"
SKIP_NAMED_DATA_TAG = "N"
MERGE_OUTPUT_TAG = "M"
LOOSE_DATA_LEN_TAG = "L"
SKIP_THUNK_TAG = "T"
SKIP_LIB_TAG = "B"


def get_skip_named_func_setting():
    """Retrieve the 'skip named functions' setting from the IDB netnode"""
    node = idaapi.netnode(SETTINGS_NODE_NAME)
    if node.hashval(SKIP_NAMED_FUNC_TAG):
        val = node.hashval(SKIP_NAMED_FUNC_TAG)
        return val == b"\x01"
    return False


def set_skip_named_func_setting(value):
    """Store the 'skip named functions' setting in the IDB netnode"""
    node = idaapi.netnode(SETTINGS_NODE_NAME)
    node.create(SETTINGS_NODE_NAME)
    node.hashset(SKIP_NAMED_FUNC_TAG, b"\x01" if value else b"\x00")


def get_dedupe_setting():
    """Retrieve the 'dedupe ASM fragments' setting from the IDB netnode"""
    node = idaapi.netnode(SETTINGS_NODE_NAME)
    if node.hashval(DEDUPE_TAG):
        val = node.hashval(DEDUPE_TAG)
        return val == b"\x01"
    return True


def set_dedupe_asm_setting(value):
    """Store the 'dedupe ASM fragments' setting in the IDB netnode"""
    node = idaapi.netnode(SETTINGS_NODE_NAME)
    node.create(SETTINGS_NODE_NAME)
    node.hashset(DEDUPE_TAG, b"\x01" if value else b"\x00")


def get_skip_code_refs_setting():
    """Retrieve the 'skip refs from code' setting from the IDB netnode"""
    node = idaapi.netnode(SETTINGS_NODE_NAME)
    if node.hashval(SKIP_CODE_REFS_TAG):
        val = node.hashval(SKIP_CODE_REFS_TAG)
        return val == b"\x01"
    return False


def set_skip_code_refs_setting(value):
    """Store the 'skip refs from code' setting in the IDB netnode"""
    node = idaapi.netnode(SETTINGS_NODE_NAME)
    node.create(SETTINGS_NODE_NAME)
    node.hashset(SKIP_CODE_REFS_TAG, b"\x01" if value else b"\x00")


def get_skip_data_refs_setting():
    """Retrieve the 'skip refs from data' setting from the IDB netnode"""
    node = idaapi.netnode(SETTINGS_NODE_NAME)
    if node.hashval(SKIP_DATA_REFS_TAG):
        val = node.hashval(SKIP_DATA_REFS_TAG)
        return val == b"\x01"
    return False


def set_skip_data_refs_setting(value):
    """Store the 'skip refs from data' setting in the IDB netnode"""
    node = idaapi.netnode(SETTINGS_NODE_NAME)
    node.create(SETTINGS_NODE_NAME)
    node.hashset(SKIP_DATA_REFS_TAG, b"\x01" if value else b"\x00")


def get_skip_named_data_setting():
    """Retrieve the 'skip named data' setting from the IDB netnode"""
    node = idaapi.netnode(SETTINGS_NODE_NAME)
    if node.hashval(SKIP_NAMED_DATA_TAG):
        val = node.hashval(SKIP_NAMED_DATA_TAG)
        return val == b"\x01"
    return False


def set_skip_named_data_setting(value):
    """Store the 'skip named data' setting in the IDB netnode"""
    node = idaapi.netnode(SETTINGS_NODE_NAME)
    node.create(SETTINGS_NODE_NAME)
    node.hashset(SKIP_NAMED_DATA_TAG, b"\x01" if value else b"\x00")


def get_merge_output_setting():
    """Retrieve the 'merge exported functions into one file' setting from the IDB netnode"""
    node = idaapi.netnode(SETTINGS_NODE_NAME)
    if node.hashval(MERGE_OUTPUT_TAG):
        val = node.hashval(MERGE_OUTPUT_TAG)
        return val == b"\x01"
    return False


def set_merge_output_setting(value):
    """Store the 'merge exported functions into one file' setting in the IDB netnode"""
    node = idaapi.netnode(SETTINGS_NODE_NAME)
    node.create(SETTINGS_NODE_NAME)
    node.hashset(MERGE_OUTPUT_TAG, b"\x01" if value else b"\x00")


def get_loose_data_len_setting():
    """Retrieve the 'max unknown data explore length' setting from the IDB netnode"""
    node = idaapi.netnode(SETTINGS_NODE_NAME)
    val = node.hashval(LOOSE_DATA_LEN_TAG)
    if val:
        try:
            return max(0, int(val.decode()))
        except (ValueError, UnicodeDecodeError):
            return 0
    return 0


def set_loose_data_len_setting(value):
    """Store the 'max unknown data explore length' setting in the IDB netnode"""
    node = idaapi.netnode(SETTINGS_NODE_NAME)
    node.create(SETTINGS_NODE_NAME)
    node.hashset(LOOSE_DATA_LEN_TAG, str(max(0, int(value))).encode())


def get_skip_thunk_setting():
    """Retrieve the 'skip thunk functions' setting from the IDB netnode"""
    node = idaapi.netnode(SETTINGS_NODE_NAME)
    if node.hashval(SKIP_THUNK_TAG):
        val = node.hashval(SKIP_THUNK_TAG)
        return val == b"\x01"
    return False


def set_skip_thunk_setting(value):
    """Store the 'skip thunk functions' setting in the IDB netnode"""
    node = idaapi.netnode(SETTINGS_NODE_NAME)
    node.create(SETTINGS_NODE_NAME)
    node.hashset(SKIP_THUNK_TAG, b"\x01" if value else b"\x00")


def get_skip_lib_setting():
    """Retrieve the 'skip library functions' setting from the IDB netnode.
    Defaults to True to preserve the historical always-skip behavior."""
    node = idaapi.netnode(SETTINGS_NODE_NAME)
    if node.hashval(SKIP_LIB_TAG):
        val = node.hashval(SKIP_LIB_TAG)
        return val == b"\x01"
    return True


def set_skip_lib_setting(value):
    """Store the 'skip library functions' setting in the IDB netnode"""
    node = idaapi.netnode(SETTINGS_NODE_NAME)
    node.create(SETTINGS_NODE_NAME)
    node.hashset(SKIP_LIB_TAG, b"\x01" if value else b"\x00")


class _NoFunc:
    """Sentinel passed as `cur_func` when scanning a range that is not inside a
    function. Only `.start_ea` is read by the check_* helpers; BADADDR never
    matches a real function start, so nothing is wrongly skipped."""

    def __init__(self, start_ea: ida_idaapi.ea_t = idaapi.BADADDR):
        self.start_ea = start_ea
        self.end_ea = idaapi.BADADDR
        self.flags = 0


_NO_FUNC = _NoFunc()


def _merge_code_intervals(intervals: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Merge per-instruction intervals into contiguous code runs.leave gaps as it is"""
    if not intervals:
        return []
    intervals.sort()
    merged = []
    cs, ce = intervals[0]
    for s, e in intervals[1:]:
        if s <= ce:  # contiguous / overlapping instructions
            ce = max(ce, e)
        else:
            merged.append((cs, ce))
            cs, ce = s, e
    merged.append((cs, ce))
    return merged


def reconstruct_func_range(start_ea) -> list[tuple[int, int]]:
    """Best-effort reconstruction of a function's extent when IDA has NOT
    defined a function at `start_ea` -- e.g. a control-flow-flattened or
    obfuscated routine that has data (jump tables / inline constants) embedded
    between its code blocks, which makes IDA refuse to create a function.

    Floods intra-procedural control flow from `start_ea`: follows fall-through
    and local jump targets, but NOT calls (BL/CALL target other functions) and
    does not cross into a different already-defined function (tail calls).

    Returns a LIST of (start, end) ranges -- the reached code blocks, without
    embedded pure-data gaps bridged."""
    visited = set()
    stack = [start_ea]
    intervals = []

    def _is_other_func_start(ea):
        f = ida_funcs.get_func(ea)
        return f is not None and f.start_ea == ea and f.start_ea != start_ea

    while stack:
        ea = stack.pop()
        if ea == idaapi.BADADDR or ea in visited or not ida_bytes.is_mapped(ea):
            continue
        if not ida_bytes.is_code(ida_bytes.get_flags(ea)):
            continue
        insn = ida_ua.insn_t()
        size = ida_ua.decode_insn(insn, ea)
        if size <= 0:
            continue
        visited.add(ea)
        intervals.append((ea, ea + size))

        # Follow jump targets that stay within this procedure. Skip calls and
        # jumps that land on the start of another defined function (tail calls).
        for xref in idautils.XrefsFrom(ea, ida_xref.XREF_FAR):
            if xref.type in (ida_xref.fl_JN, ida_xref.fl_JF) and not _is_other_func_start(xref.to):
                stack.append(xref.to)

        # Fall through to the next instruction unless this one stops flow
        # (RET, ...). Calls (BL) don't stop flow, so execution continues.
        if not ida_idp.is_ret_insn(insn):
            nxt = ea + size
            if not _is_other_func_start(nxt):
                stack.append(nxt)

    return _merge_code_intervals(intervals)


def get_recursive_functions(start_ea, initial=True) -> list:
    """Get all functions called by start_ea recursively, excluding library functions"""
    to_export = []
    stack = [start_ea]

    # Get the current setting from IDB
    skip_named = get_skip_named_func_setting()
    skip_thunk = get_skip_thunk_setting()
    skip_lib = get_skip_lib_setting()

    while stack:
        ea = stack.pop(0)
        func = ida_funcs.get_func(ea) or _NoFunc(ea)
        if not func:
            continue

        func_ea = func.start_ea
        if func_ea in to_export:
            continue

        # When enabled, don't export library functions and don't recurse into them
        if skip_lib and func.flags & ida_funcs.FUNC_LIB:
            continue

        # Thunks: skip all of them when the setting is on; otherwise only skip
        # named thunks (likely import stubs).
        if func.flags & ida_funcs.FUNC_THUNK and skip_thunk:
            continue

        # If setting is enabled, skip any function that doesn't have a default name
        if skip_named and not initial:
            initial = False
            flags = ida_bytes.get_flags(func_ea)
            if ida_bytes.has_name(flags):
                continue
        initial = False

        to_export.append(func_ea)
        # Find all calls from this function
        for head in idautils.FuncItems(func_ea):
            for ref in idautils.XrefsFrom(head, ida_xref.XREF_FAR):
                called_func = ida_funcs.get_func(ref.to)
                if called_func and called_func.start_ea != func_ea:
                    stack.append(called_func.start_ea)
                elif not called_func and ref.type in (ida_xref.fl_CN, ida_xref.fl_CF):
                    to_export.append(ref.to)

    return to_export


def export_recursive_functions(start_ea):
    """Export a function and all its sub-calls recursively"""
    global_processed_ranges = set() if get_dedupe_setting() else None
    merge_output = get_merge_output_setting()
    ida_kernwin.show_wait_box("analyzing recursive calls...")
    file = None
    try:
        funcs_to_export = get_recursive_functions(start_ea)
        if len(funcs_to_export) == 0:
            ida_kernwin.warning(f"no functions found at:{start_ea:#x} to export")
            return
        ida_kernwin.replace_wait_box(f"exporting {len(funcs_to_export)} functions...")
        path = os.path.dirname(ida_loader.get_path(ida_loader.PATH_TYPE_CMD))
        output = sanitize_path(os.path.join(path, "Assemport"))
        try:
            os.mkdir(output)
        except FileExistsError:
            pass
        exported_count = 0
        processed = set()
        while len(funcs_to_export) > 0:
            ea = funcs_to_export.pop(0)
            if ea in processed:
                continue
            if ida_kernwin.user_cancelled():
                break
            func = ida_funcs.get_func(ea) or _NoFunc(ea)
            if func is None or func.start_ea != ea:
                continue
            func_name = get_export_name(ea)
            ida_kernwin.replace_wait_box(f"exporting {exported_count + 1}/{len(funcs_to_export)}: {func_name}")
            filename = sanitize_path(os.path.join(output, f"{func_name}.asm"))
            try:
                if merge_output:
                    if file is None:
                        file = ida_fpro.qfile_t()
                        assert file.open(filename, "wt"), f"cannot open file:{filename}"
                else:
                    file = ida_fpro.qfile_t()
                    assert file.open(filename, "wt"), f"cannot open file:{filename}"
                unhide_func_and_export_asm(func, file, funcs_to_export, global_processed_ranges)
                processed.add(func.start_ea)
                exported_count += 1
            except Exception as e:  # noqa: BLE001
                print(f"export func:{ea:#x} error:{''.join(traceback.format_exception(e))}")
            finally:
                if not merge_output and file:
                    file.close()
        ida_kernwin.info(f"recursively exported {exported_count}/{exported_count + len(funcs_to_export)} functions successfully!")
    except Exception as e:  # noqa: BLE001
        ida_kernwin.error(f"export func error:{''.join(traceback.format_exception(e))}")
    finally:
        ida_kernwin.hide_wait_box()
        if merge_output and file:
            file.close()


# Global hooks instance
ui_hooks = None


class AssemportSettingsForm(ida_kernwin.Form):
    def __init__(self, skip_named_func, dedupe, skip_code_refs, skip_data_refs, skip_named_data, merge_output, loose_data_len, skip_thunk, skip_lib):
        form_str = r"""STARTITEM 0
Assemport Settings

<Skip Named Func:{rSkipNamedFunc}>
<Skip Named Data:{rSkipNamedData}>
<Skip Thunk Func:{rSkipThunk}>
<Skip Lib Func:{rSkipLib}>
<Global ASM/DATA Fragment Deduplication:{rDedupe}>
<Skip Refs From Code:{rSkipCodeRefs}>
<Skip Refs From Data:{rSkipDataRefs}>
<Merge Exported Functions Into One File:{rMergeOutput}>{cGroup}>

<Max Unknown Data Explore Length (0 = off):{iLooseDataLen}>
"""
        controls = {
            "cGroup": ida_kernwin.Form.ChkGroupControl(
                # IMPORTANT: each checkbox's bit follows the order the {rXxx}
                # placeholders appear in form_str (bit = 1 << position). This
                # list MUST be in that same order, and the value masks below plus
                # the masks read in run() MUST agree with it. Order:
                #   1 SkipNamedFunc, 2 SkipNamedData, 4 SkipThunk, 8 SkipLib,
                #   16 Dedupe, 32 SkipCodeRefs, 64 SkipDataRefs, 128 MergeOutput
                ["rSkipNamedFunc", "rSkipNamedData", "rSkipThunk", "rSkipLib", "rDedupe", "rSkipCodeRefs", "rSkipDataRefs", "rMergeOutput"],  # ty:ignore[invalid-argument-type]
                value=(1 if skip_named_func else 0)
                | (2 if skip_named_data else 0)
                | (4 if skip_thunk else 0)
                | (8 if skip_lib else 0)
                | (16 if dedupe else 0)
                | (32 if skip_code_refs else 0)
                | (64 if skip_data_refs else 0)
                | (128 if merge_output else 0),
            ),  # ty:ignore[missing-argument]
            "iLooseDataLen": ida_kernwin.Form.NumericInput(tp=ida_kernwin.Form.FT_DEC, value=loose_data_len),  # ty:ignore[missing-argument]
        }
        ida_kernwin.Form.__init__(self, form_str, controls)


class Assemport(ida_idaapi.plugmod_t):
    def __init__(self):
        global ui_hooks
        print("[Assemport] Initializing...")

        # Register actions
        self.register_actions()

        # Install UI hooks
        if ui_hooks is None:
            ui_hooks = AssemportUIHooks()
            ui_hooks.hook()

    def __del__(self):
        self.unregister_actions()
        self.unhook_ui()
        ida_kernwin.hide_wait_box()
        print("[Assemport] Finished.")

    def register_actions(self):
        """Register context menu actions"""
        # Single function export action
        self.handler_export_single = ExportSingleFunctionHandler()
        action_desc = ida_kernwin.action_desc_t(
            "assemport:export_single",
            "Export Function Assembly",
            self.handler_export_single,
            None,  # No shortcut
            "Export the current function to an assembly file",
        )
        ida_kernwin.register_action(action_desc)

        # Selected functions export action
        self.handler_export_selected = ExportSelectedFunctionsHandler()
        action_desc = ida_kernwin.action_desc_t(
            "assemport:export_selected",
            "Export Selected Functions Assembly",
            self.handler_export_selected,
            None,  # No shortcut
            "Export selected functions to assembly files",
        )
        ida_kernwin.register_action(action_desc)

        # Recursive function export action
        self.handler_export_recursive = ExportRecursiveFunctionHandler()
        action_desc = ida_kernwin.action_desc_t(
            "assemport:export_recursive",
            "Export Recursive Function Assembly",
            self.handler_export_recursive,
            None,  # No shortcut
            "Export the current function and its sub-calls recursively to assembly files",
        )
        ida_kernwin.register_action(action_desc)

    def unregister_actions(self):
        """Unregister context menu actions"""
        ida_kernwin.unregister_action("assemport:export_single")
        ida_kernwin.unregister_action("assemport:export_selected")
        ida_kernwin.unregister_action("assemport:export_recursive")

    def unhook_ui(self):
        """Unhook UI hooks"""
        global ui_hooks
        if ui_hooks:
            ui_hooks.unhook()
            ui_hooks = None

    def run(self, arg):
        skip_named_func = get_skip_named_func_setting()
        dedupe = get_dedupe_setting()
        skip_code_refs = get_skip_code_refs_setting()
        skip_data_refs = get_skip_data_refs_setting()
        skip_named_data = get_skip_named_data_setting()
        merge_output = get_merge_output_setting()
        loose_data_len = get_loose_data_len_setting()
        skip_thunk = get_skip_thunk_setting()
        skip_lib = get_skip_lib_setting()
        f = AssemportSettingsForm(
            skip_named_func, dedupe, skip_code_refs, skip_data_refs, skip_named_data, merge_output, loose_data_len, skip_thunk, skip_lib
        )
        f.Compile()
        if f.Execute() == 1:
            new_skip_named_func = (f.cGroup.value & 1) != 0
            new_skip_named_data = (f.cGroup.value & 2) != 0
            new_skip_thunk = (f.cGroup.value & 4) != 0
            new_skip_lib = (f.cGroup.value & 8) != 0
            new_dedupe = (f.cGroup.value & 16) != 0
            new_skip_code_refs = (f.cGroup.value & 32) != 0
            new_skip_data_refs = (f.cGroup.value & 64) != 0
            new_merge_output = (f.cGroup.value & 128) != 0
            new_loose_data_len = max(0, int(f.iLooseDataLen.value or 0))
            set_skip_named_func_setting(new_skip_named_func)
            set_skip_named_data_setting(new_skip_named_data)
            set_dedupe_asm_setting(new_dedupe)
            set_skip_code_refs_setting(new_skip_code_refs)
            set_skip_data_refs_setting(new_skip_data_refs)
            set_merge_output_setting(new_merge_output)
            set_skip_thunk_setting(new_skip_thunk)
            set_skip_lib_setting(new_skip_lib)
            set_loose_data_len_setting(new_loose_data_len)
            print(
                f"[Assemport] Settings updated: Skip Named Func={new_skip_named_func}, Skip Named Data={new_skip_named_data}, "
                f"Skip Thunk={new_skip_thunk}, Skip Lib={new_skip_lib}, Dedupe={new_dedupe}, Skip Code Refs={new_skip_code_refs}, "
                f"Skip Data Refs={new_skip_data_refs}, Merge Output={new_merge_output}, Max Unknown Data Explore Length={new_loose_data_len}"
            )
        f.Free()
