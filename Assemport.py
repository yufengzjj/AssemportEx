import os
import re
import traceback

import ida_bytes
import ida_fpro
import ida_funcs
import ida_hexrays
import ida_ida
import ida_idaapi
import ida_kernwin
import ida_lines
import ida_loader
import ida_name
import ida_range
import ida_ua
import idaapi
import idautils


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

        func = ida_funcs.get_func(ea)

        if func is None:
            ida_kernwin.warning("No function at current address")
            return 1

        # Export just this function
        export_single_function(func)
        return 1

    def update(self, ctx):
        # Enable only if cursor is on a function
        if hasattr(ctx, "cur_ea"):
            ea = ctx.cur_ea
        else:
            ea = ida_kernwin.get_screen_ea()

        func = ida_funcs.get_func(ea)
        return ida_kernwin.AST_ENABLE if func else ida_kernwin.AST_DISABLE


def is_functions_window(ctx):
    """Check if the context is from the Functions window (handles IDA 9.0 BWN_CHOOSER)"""
    if not ctx:
        return False

    widget_type = getattr(ctx, "widget_type", -1)
    widget_title = ""
    if hasattr(ctx, "widget"):
        widget_title = ida_kernwin.get_widget_title(ctx.widget)

    # Debug: Uncomment to see all widget types/titles
    # print(f"[Assemport] is_functions_window: type={widget_type}, title='{widget_title}'")

    if widget_type == ida_kernwin.BWN_FUNCS:
        return True
    if widget_type == ida_kernwin.BWN_CHOOSER:
        # IDA 9.0 Functions window is often a chooser with "Functions" in title
        if "Functions" in widget_title:
            return True
    return False


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


class ExportSingleFunctionPseudocodeHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        # Get the current function at cursor position
        if hasattr(ctx, "cur_ea"):
            ea = ctx.cur_ea
        else:
            ea = ida_kernwin.get_screen_ea()

        func = ida_funcs.get_func(ea)

        if func is None:
            ida_kernwin.warning("No function at current address")
            return 1

        # Export just this function's pseudocode
        export_single_function_pseudocode(func)
        return 1

    def update(self, ctx):
        # Enable only if cursor is on a function and hexrays is available
        if hasattr(ctx, "cur_ea"):
            ea = ctx.cur_ea
        else:
            ea = ida_kernwin.get_screen_ea()

        func = ida_funcs.get_func(ea)
        return ida_kernwin.AST_ENABLE if func and ida_hexrays.init_hexrays_plugin() else ida_kernwin.AST_DISABLE


class ExportSelectedFunctionsPseudocodeHandler(ida_kernwin.action_handler_t):
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

            # Export selected functions' pseudocode
            export_selected_functions_pseudocode(selection)
        else:
            ida_kernwin.warning("This action is only available in the Functions window")
        return 1

    def update(self, ctx):
        # Enable only in Functions window with selection and hexrays available
        if is_functions_window(ctx):
            has_selection = hasattr(ctx, "chooser_selection") and ctx.chooser_selection
            has_hexrays = ida_hexrays.init_hexrays_plugin()
            return ida_kernwin.AST_ENABLE if has_selection and has_hexrays else ida_kernwin.AST_DISABLE
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

        func = ida_funcs.get_func(ea)

        if func is None:
            ida_kernwin.warning("No function at current address")
            return 1

        # Export this function and all sub-calls recursively
        export_recursive_functions(func.start_ea, "asm")
        return 1

    def update(self, ctx):
        # Enable only if cursor is on a function
        if hasattr(ctx, "cur_ea"):
            ea = ctx.cur_ea
        else:
            ea = ida_kernwin.get_screen_ea()

        func = ida_funcs.get_func(ea)
        return ida_kernwin.AST_ENABLE if func else ida_kernwin.AST_DISABLE


class ExportRecursiveFunctionPseudocodeHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        # Get the current function at cursor position
        if hasattr(ctx, "cur_ea"):
            ea = ctx.cur_ea
        else:
            ea = ida_kernwin.get_screen_ea()

        func = ida_funcs.get_func(ea)

        if func is None:
            ida_kernwin.warning("No function at current address")
            return 1

        # Export this function and all sub-calls recursively (pseudocode)
        export_recursive_functions(func.start_ea, "c")
        return 1

    def update(self, ctx):
        # Enable only if cursor is on a function and hexrays is available
        if hasattr(ctx, "cur_ea"):
            ea = ctx.cur_ea
        else:
            ea = ida_kernwin.get_screen_ea()

        func = ida_funcs.get_func(ea)
        return ida_kernwin.AST_ENABLE if func and ida_hexrays.init_hexrays_plugin() else ida_kernwin.AST_DISABLE


# UI Hooks for context menu
class AssemportUIHooks(ida_kernwin.UI_Hooks):
    def __init__(self):
        ida_kernwin.UI_Hooks.__init__(self)

    def populating_widget_popup(self, widget, popup_handle, ctx):
        # Add context menu items based on widget type
        if ctx is None:
            return

        # For any disassembly view - add single function export
        widget_type = ida_kernwin.get_widget_type(widget)
        if widget_type in [ida_kernwin.BWN_DISASM, ida_kernwin.BWN_PSEUDOCODE]:
            if hasattr(ctx, "cur_ea"):
                ea = ctx.cur_ea
            else:
                ea = ida_kernwin.get_screen_ea()

            func = ida_funcs.get_func(ea)
            if func:
                ida_kernwin.attach_action_to_popup(widget, popup_handle, "assemport:export_single", None)
                # Add recursive export action
                ida_kernwin.attach_action_to_popup(widget, popup_handle, "assemport:export_recursive", None)

                # Add pseudocode export option if hexrays is available
                if ida_hexrays.init_hexrays_plugin():
                    ida_kernwin.attach_action_to_popup(widget, popup_handle, "assemport:export_single_pseudocode", None)
                    # Add recursive pseudocode export action
                    ida_kernwin.attach_action_to_popup(
                        widget,
                        popup_handle,
                        "assemport:export_recursive_pseudocode",
                        None,
                    )

        # For Functions window - add selected functions export
        elif widget_type == ida_kernwin.BWN_FUNCS or (widget_type == ida_kernwin.BWN_CHOOSER and "Functions" in ida_kernwin.get_widget_title(widget)):
            if hasattr(ctx, "chooser_selection"):
                ida_kernwin.attach_action_to_popup(widget, popup_handle, "assemport:export_selected", None)
                # Add pseudocode export options if hexrays is available
                if ida_hexrays.init_hexrays_plugin():
                    ida_kernwin.attach_action_to_popup(
                        widget,
                        popup_handle,
                        "assemport:export_selected_pseudocode",
                        None,
                    )


def get_loose_code_block_range(ea):
    end_ea = ea
    while True:
        curr_flags = ida_bytes.get_flags(end_ea)
        if end_ea == idaapi.BADADDR or not ida_bytes.is_code(curr_flags):
            break
        refs = [ref for ref in idautils.CodeRefsFrom(end_ea, True)]
        if len(refs) == 0:
            end_ea = ida_bytes.get_item_end(end_ea)
            break
        refs = [ref for ref in idautils.CodeRefsFrom(end_ea, False)]
        if len(refs) > 0:
            end_ea = ida_bytes.get_item_end(end_ea)
            break
        cur_func = ida_funcs.get_func(end_ea)
        if cur_func:
            if cur_func.start_ea <= end_ea < cur_func.end_ea:
                end_ea = cur_func.end_ea
                break
            if cur_func.start_ea == end_ea:
                break
        cur_fchunk = ida_funcs.get_fchunk(end_ea)
        if cur_fchunk:
            if cur_fchunk.start_ea <= end_ea < cur_fchunk.end_ea:
                end_ea = cur_fchunk.end_ea
                break
            if cur_fchunk.start_ea == end_ea:
                break
        end_ea = ida_bytes.get_item_end(end_ea)
    return ida_range.range_t(ea, end_ea)


def get_loose_data_range(ea):
    end_ea = ea
    while True:
        name = ida_name.get_name(end_ea)
        if end_ea != ea and name:
            break
        end_ea = ida_bytes.get_item_end(end_ea)
    return ida_range.range_t(ea, end_ea)


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
                if (ref, func.end_ea) not in processed_ranges and r not in ranges:
                    ranges.append(r)
            else:
                r = get_loose_code_block_range(ref)
                if (r.start_ea, r.end_ea) not in processed_ranges and r not in ranges:
                    ranges.append(r)
    elif not func:
        r = get_loose_code_block_range(ref)
        if (r.start_ea, r.end_ea) not in processed_ranges and r not in ranges:
            ranges.append(r)


def check_ref_range(
    ranges: list, addr: int, cur_range: tuple[int, int], cur_func: ida_funcs.func_t, funcs_to_export: list | None, processed_ranges: set
):
    """check code ref at addr"""
    for ref in idautils.CodeRefsFrom(addr, False):
        if cur_range[0] <= ref < cur_range[1]:
            continue
        check_func_range(ranges, ref, cur_func, funcs_to_export, processed_ranges)


def get_ref_from_insn(ea):
    insn = ida_ua.insn_t()  # ty:ignore[missing-argument]
    if ida_ua.decode_insn(insn, ea) == 0:
        return None

    mn = insn.get_canon_mnem()
    if mn not in ("ADR", "ADRL"):
        return None
    for op in insn.ops:
        if op.type in (idaapi.o_mem, idaapi.o_imm, idaapi.o_far, idaapi.o_near):
            if op.addr != 0 and op.addr != idaapi.BADADDR:
                return op.addr
            if op.value != 0 and op.value != idaapi.BADADDR:
                return op.value
    return None


def check_o_ref_range(ranges: list, cur_range: tuple[int, int], cur_func: ida_funcs.func_t, funcs_to_export: list | None, processed_ranges: set):
    """check code opraand ref in cur_range"""
    for head in idautils.Heads(*cur_range):
        o_ref = get_ref_from_insn(head)
        if o_ref is None:
            continue
        if cur_range[0] <= o_ref < cur_range[1]:
            continue
        o_flags = ida_bytes.get_flags(o_ref)
        if ida_bytes.is_code(o_flags):
            check_func_range(ranges, o_ref, cur_func, funcs_to_export, processed_ranges)
        elif ida_bytes.is_data(o_flags):
            r = ida_range.range_t(o_ref, o_ref + ida_bytes.get_item_size(o_ref))
            if (r.start_ea, r.end_ea) not in processed_ranges and r not in ranges:
                ranges.append(r)
        else:
            r = get_loose_data_range(o_ref)
            if (r.start_ea, r.end_ea) not in processed_ranges and r not in ranges:
                ranges.append(r)


def check_d_ref_range(ranges: list, cur_range: tuple[int, int], cur_func: ida_funcs.func_t, funcs_to_export: list | None, processed_ranges: set):
    """check data ref"""
    ea = cur_range[0]
    ptr_size = ida_ida.inf_get_app_bitness() // 8
    while ea < cur_range[1]:
        if ida_bytes.get_item_size(ea) == ptr_size:
            ptr = int.from_bytes(ida_bytes.get_bytes(ea, ptr_size), "big" if ida_ida.inf_is_be() else "little")
            if cur_range[0] <= ptr < cur_range[1]:
                continue
            flags = ida_bytes.get_flags(ptr)
            if ida_bytes.is_code(flags):
                check_func_range(ranges, ptr, cur_func, funcs_to_export, processed_ranges)
            else:
                r = get_loose_data_range(ptr)
                if (r.start_ea, r.end_ea) not in processed_ranges and r not in ranges:
                    ranges.append(r)
        ea = ida_bytes.get_item_end(ea)


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


def unhide_func_and_export_asm(func: ida_funcs.func_t, file, funcs_to_export: list | None = None, processed_ranges: set | None = None):
    """Temporarily unhide function and its chunks, then export to ASM"""
    hidden_funcs = []
    if func.flags & ida_funcs.FUNC_HIDDEN:
        hidden_funcs.append(func)
        func.flags &= ~ida_funcs.FUNC_HIDDEN
        ida_funcs.update_func(func)
    try:
        ranges = ida_range.rangeset_t()  # ty:ignore[missing-argument]
        ida_funcs.get_func_ranges(ranges, func)
        all_ranges = [ranges.getrange(i) for i in range(ranges.nranges())]
        all_ranges.sort(key=lambda r: (0 if r.start_ea == func.start_ea else 1, r.start_ea))
        processed_ranges = set() if processed_ranges is None else processed_ranges
        data_ranges = []
        hidden_ranges = []
        while len(all_ranges) > 0:
            r = all_ranges.pop(0)
            start, end = r.start_ea, r.end_ea
            if start >= end:
                continue
            check_hidden_range(start, end, hidden_ranges)
            f = ida_funcs.get_func(start)
            if f and f.start_ea != func.start_ea and f.flags & ida_funcs.FUNC_HIDDEN:
                hidden_funcs.append(f)
                f.flags &= ~ida_funcs.FUNC_HIDDEN
                ida_funcs.update_func(f)
            flags = ida_bytes.get_flags(start)
            if ida_bytes.is_code(flags):
                if start >= func.start_ea and end <= func.end_ea:
                    ida_loader.gen_file(ida_loader.OFILE_ASM, file.get_fp(), start, end, 0)
                    check_ref_range(all_ranges, ida_bytes.prev_head(end, start), (start, end), func, funcs_to_export, processed_ranges)
                else:
                    r_name = ida_name.get_name(start)
                    ida_fpro._ida_fpro.qfile_t_write(file, f"{r_name}\n")  # ty:ignore[unresolved-attribute]
                    for head in idautils.Heads(start, end):
                        disasm = ida_lines.generate_disasm_line(head, 0)
                        ida_fpro._ida_fpro.qfile_t_write(file, f"{ida_lines.tag_remove(disasm)}\n")  # ty:ignore[unresolved-attribute]
                        check_ref_range(all_ranges, head, (start, end), func, funcs_to_export, processed_ranges)
                    ida_fpro._ida_fpro.qfile_t_write(file, "\n")  # ty:ignore[unresolved-attribute]
                check_o_ref_range(all_ranges, (start, end), func, funcs_to_export, processed_ranges)
            else:
                data_ranges.append(r)
                check_d_ref_range(all_ranges, (start, end), func, funcs_to_export, processed_ranges)
            processed_ranges.add((start, end))
        while len(data_ranges) > 0:
            r = data_ranges.pop(0)
            start, end = r.start_ea, r.end_ea
            flags = ida_bytes.get_flags(start)
            r_name = ida_name.get_name(start)
            if ida_bytes.is_data(flags):
                disasm = ida_lines.generate_disasm_line(start, 0)
                ida_fpro._ida_fpro.qfile_t_write(file, f"{r_name} {ida_lines.tag_remove(disasm)}\n")  # ty:ignore[unresolved-attribute]
            else:
                ida_fpro._ida_fpro.qfile_t_write(file, f"{r_name}\n")  # ty:ignore[unresolved-attribute]
                ea = start
                while ea < end:
                    disasm = ida_lines.generate_disasm_line(ea, 0)
                    ida_fpro._ida_fpro.qfile_t_write(file, f"{ida_lines.tag_remove(disasm)}\n")  # ty:ignore[unresolved-attribute]
                    ea = ida_bytes.get_item_end(ea)

    finally:
        for f in hidden_funcs:
            f.flags |= ida_funcs.FUNC_HIDDEN
            ida_funcs.update_func(f)
        for hr in hidden_ranges:
            ida_bytes.add_hidden_range(*hr)


def export_single_function(func):
    """Export a single function to assembly file"""
    ida_kernwin.show_wait_box("Exporting function...")

    try:
        # Get Working-Path
        path = os.path.dirname(ida_loader.get_path(ida_loader.PATH_TYPE_CMD))
        output = os.path.join(path, "Assemport")

        # Create Output-Directory
        try:
            os.mkdir(output)
        except FileExistsError:
            pass
        except PermissionError:
            print(f"[Assemport] Permission denied: Unable to create '{output}'.")
            return
        except Exception as e:
            print(f"[Assemport] An error occurred: {e}")
            return

        # Get function name
        func_name = ida_funcs.get_func_name(func.start_ea)

        # Save Content
        file = ida_fpro.qfile_t()
        filename = os.path.join(output, f"{re.sub(r'[<>:"/\\|?*]', '_', func_name)}.asm")

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
        output = os.path.join(path, "Assemport")

        # Create Output-Directory
        try:
            os.mkdir(output)
        except FileExistsError:
            pass
        except PermissionError:
            print(f"[Assemport] Permission denied: Unable to create '{output}'.")
            return
        except Exception as e:
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
                filename = os.path.join(output, f"{re.sub(r'[<>:"/\\|?*]', '_', func_name)}.asm")

                if file.open(filename, "wt"):
                    try:
                        unhide_func_and_export_asm(func, file)
                        exported_count += 1
                    finally:
                        file.close()
        ida_kernwin.info(f"Exported {exported_count} functions successfully!")

    finally:
        ida_kernwin.hide_wait_box()


def export_single_function_pseudocode(func):
    """Export a single function's pseudocode to file"""
    ida_kernwin.show_wait_box("Exporting function pseudocode...")

    try:
        # Check if hexrays is available
        if not ida_hexrays.init_hexrays_plugin():
            ida_kernwin.warning("Hex-Rays decompiler is not available")
            return

        # Get Working-Path
        path = os.path.dirname(ida_loader.get_path(ida_loader.PATH_TYPE_CMD))
        output = os.path.join(path, "Assemport")

        # Create Output-Directory
        try:
            os.mkdir(output)
        except FileExistsError:
            pass
        except PermissionError:
            print(f"[Assemport] Permission denied: Unable to create '{output}'.")
            return
        except Exception as e:
            print(f"[Assemport] An error occurred: {e}")
            return

        # Get function name
        func_name = ida_funcs.get_func_name(func.start_ea)

        # Get pseudocode
        try:
            cfunc = ida_hexrays.decompile(func.start_ea)
            if cfunc is None:
                ida_kernwin.warning(f"Failed to decompile function {func_name}")
                return

            pseudocode = str(cfunc)

            # Save pseudocode to file
            filename = os.path.join(output, f"{func_name}.c")

            with open(filename, "w", encoding="utf-8") as f:
                f.write(pseudocode)

            print(f"[Assemport] Exported function pseudocode {func_name} to {filename}")
            ida_kernwin.info(f"Function {func_name} pseudocode exported successfully!")

        except Exception as e:
            print(f"[Assemport] Error decompiling function {func_name}: {e}")
            ida_kernwin.warning(f"Failed to decompile function {func_name}: {str(e)}")

    finally:
        ida_kernwin.hide_wait_box()


# Persistent settings using IDA netnode
SETTINGS_NODE_NAME = "$ assemport_settings"
SKIP_NAMED_TAG = "S"
DEDUPE_ASM_TAG = "D"


def get_skip_named_setting():
    """Retrieve the 'skip named functions' setting from the IDB netnode"""
    node = idaapi.netnode(SETTINGS_NODE_NAME)  # ty:ignore[missing-argument]
    if node.hashval(SKIP_NAMED_TAG):
        val = node.hashval(SKIP_NAMED_TAG)
        return val == b"\x01"
    return False


def set_skip_named_setting(value):
    """Store the 'skip named functions' setting in the IDB netnode"""
    node = idaapi.netnode(SETTINGS_NODE_NAME)  # ty:ignore[missing-argument]
    node.create(SETTINGS_NODE_NAME)
    node.hashset(SKIP_NAMED_TAG, b"\x01" if value else b"\x00")


def get_dedupe_asm_setting():
    """Retrieve the 'dedupe ASM fragments' setting from the IDB netnode"""
    node = idaapi.netnode(SETTINGS_NODE_NAME)  # ty:ignore[missing-argument]
    if node.hashval(DEDUPE_ASM_TAG):
        val = node.hashval(DEDUPE_ASM_TAG)
        return val == b"\x01"
    return True


def set_dedupe_asm_setting(value):
    """Store the 'dedupe ASM fragments' setting in the IDB netnode"""
    node = idaapi.netnode(SETTINGS_NODE_NAME)  # ty:ignore[missing-argument]
    node.create(SETTINGS_NODE_NAME)
    node.hashset(DEDUPE_ASM_TAG, b"\x01" if value else b"\x00")


def get_recursive_functions(start_ea, initial=True) -> list:
    """Get all functions called by start_ea recursively, excluding library functions"""
    to_export = list()
    stack = [start_ea]

    # Get the current setting from IDB
    skip_named = get_skip_named_setting()

    while stack:
        ea = stack.pop(0)
        func = ida_funcs.get_func(ea)
        if not func:
            continue

        func_ea = func.start_ea
        if func_ea in to_export:
            continue

        # Don't export library functions and don't recurse into them
        if func.flags & ida_funcs.FUNC_LIB:
            continue

        # If setting is enabled, skip any function that doesn't have a default name
        if skip_named and not initial:
            initial = False
            flags = ida_bytes.get_flags(func_ea)
            if ida_bytes.has_name(flags):
                continue
        initial = False
        # Check if it's a thunk with a non-default name (likely an import stub)
        if func.flags & ida_funcs.FUNC_THUNK:
            flags = ida_bytes.get_flags(func_ea)
            if ida_bytes.has_name(flags):
                continue

        to_export.append(func_ea)
        # Find all calls from this function
        for head in idautils.FuncItems(func_ea):
            for ref in idautils.CodeRefsFrom(head, False):
                called_func = ida_funcs.get_func(ref)
                if called_func and called_func.start_ea != func_ea:
                    stack.append(called_func.start_ea)

    return to_export


def export_recursive_functions(start_ea, mode="asm"):
    """Export a function and all its sub-calls recursively"""
    ida_kernwin.show_wait_box("analyzing recursive calls...")

    try:
        funcs_to_export = get_recursive_functions(start_ea)
        if len(funcs_to_export) == 0:
            ida_kernwin.warning(f"no functions found at:{start_ea:#x} to export")
            return
        ida_kernwin.replace_wait_box(f"exporting {len(funcs_to_export)} functions...")
        path = os.path.dirname(ida_loader.get_path(ida_loader.PATH_TYPE_CMD))
        output = os.path.join(path, "Assemport")
        try:
            os.mkdir(output)
        except FileExistsError:
            pass
        exported_count = 0
        processed = set()
        global_processed_ranges = set() if get_dedupe_asm_setting() else None

        while len(funcs_to_export) > 0:
            ea = funcs_to_export.pop(0)
            if ea in processed:
                continue
            if ida_kernwin.user_cancelled():
                break
            func = ida_funcs.get_func(ea)
            if func is None or func.start_ea != ea:
                continue
            func_name = ida_funcs.get_func_name(ea)

            ida_kernwin.replace_wait_box(f"exporting {exported_count + 1}/{len(funcs_to_export)}: {func_name}")

            if mode == "asm":
                # Save Content
                file = ida_fpro.qfile_t()  # ty:ignore[missing-argument]
                filename = os.path.join(output, f"{re.sub(r'[<>:"/\\|?*]', '_', func_name)}.asm")

                if file.open(filename, "wt"):
                    try:
                        unhide_func_and_export_asm(func, file, funcs_to_export, global_processed_ranges)
                        processed.add(func.start_ea)
                        exported_count += 1
                    except Exception as e:
                        print(f"export func:{ea:#x} error:{traceback.format_exception(e)}")
                    finally:
                        file.close()
            elif mode == "c":
                if not ida_hexrays.init_hexrays_plugin():
                    continue
                try:
                    cfunc = ida_hexrays.decompile(ea)
                    if cfunc:
                        pseudocode = str(cfunc)
                        filename = os.path.join(output, f"{func_name}.c")
                        with open(filename, "w", encoding="utf-8") as f:
                            f.write(pseudocode)
                        exported_count += 1
                except:
                    pass
        ida_kernwin.info(f"recursively exported {exported_count}/{exported_count + len(funcs_to_export)} functions successfully!")
    except Exception as e:
        ida_kernwin.error(f"export func error:{traceback.format_exception(e)}")
    finally:
        ida_kernwin.hide_wait_box()


def export_selected_functions_pseudocode(selection_indices):
    """Export selected functions' pseudocode from Functions window"""
    ida_kernwin.show_wait_box("Exporting selected functions pseudocode...")

    try:
        # Check if hexrays is available
        if not ida_hexrays.init_hexrays_plugin():
            ida_kernwin.warning("Hex-Rays decompiler is not available")
            return

        # Get Working-Path
        path = os.path.dirname(ida_loader.get_path(ida_loader.PATH_TYPE_CMD))
        output = os.path.join(path, "Assemport")

        # Create Output-Directory
        try:
            os.mkdir(output)
        except FileExistsError:
            pass
        except PermissionError:
            print(f"[Assemport] Permission denied: Unable to create '{output}'.")
            return
        except Exception as e:
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

                # Get pseudocode
                try:
                    cfunc = ida_hexrays.decompile(ea)
                    if cfunc is None:
                        print(f"[Assemport] Failed to decompile function {func_name}")
                        continue

                    pseudocode = str(cfunc)

                    # Save pseudocode to file
                    filename = os.path.join(output, f"{func_name}.c")

                    with open(filename, "w", encoding="utf-8") as f:
                        f.write(pseudocode)

                    print(f"[Assemport] Exported function pseudocode {func_name} to {filename}")
                    exported_count += 1

                except Exception as e:
                    print(f"[Assemport] Error decompiling function {func_name}: {e}")

        ida_kernwin.info(f"Exported {exported_count} functions pseudocode successfully!")

    finally:
        ida_kernwin.hide_wait_box()


def export_function_assembly(func, ea):
    """Helper function to get assembly code for a function"""
    try:
        # Create a temporary file to capture assembly output
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w+t", suffix=".asm", delete=False) as temp_file:
            temp_filename = temp_file.name

        # Generate assembly to temp file
        file = ida_fpro.qfile_t()
        if file.open(temp_filename, "wt"):
            try:
                unhide_func_and_export_asm(func, file)
            finally:
                file.close()

        # Read the content back
        try:
            with open(temp_filename, "r", encoding="utf-8") as f:
                content = f.read()
            os.unlink(temp_filename)  # Clean up temp file
            return content
        except:
            return None

    except Exception as e:
        print(f"[Assemport] Error getting assembly for function: {e}")
        return None


def export_function_pseudocode(func, ea):
    """Helper function to get pseudocode for a function"""
    try:
        cfunc = ida_hexrays.decompile(ea)
        if cfunc is None:
            return None
        return str(cfunc)
    except Exception as e:
        print(f"[Assemport] Error getting pseudocode for function: {e}")
        return None


# Global hooks instance
ui_hooks = None


class AssemportSettingsForm(ida_kernwin.Form):
    def __init__(self, skip_named, dedupe_asm):
        form_str = r"""STARTITEM 0
Assemport Settings

<Skip Named Functions:{rSkipNamedFunctions}>
<Global ASM Fragment Deduplication:{rDedupeAsm}>{cGroup}>
"""
        controls = {
            "cGroup": ida_kernwin.Form.ChkGroupControl(
                ["rSkipNamedFunctions", "rDedupeAsm"],
                value=(1 if skip_named else 0) | (2 if dedupe_asm else 0),
            ),
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

        # Single function pseudocode export action
        self.handler_export_single_pseudocode = ExportSingleFunctionPseudocodeHandler()
        action_desc = ida_kernwin.action_desc_t(
            "assemport:export_single_pseudocode",
            "Export Function Pseudocode",
            self.handler_export_single_pseudocode,
            None,  # No shortcut
            "Export the current function to a pseudocode file",
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

        # Selected functions pseudocode export action
        self.handler_export_selected_pseudocode = ExportSelectedFunctionsPseudocodeHandler()
        action_desc = ida_kernwin.action_desc_t(
            "assemport:export_selected_pseudocode",
            "Export Selected Functions Pseudocode",
            self.handler_export_selected_pseudocode,
            None,  # No shortcut
            "Export selected functions to pseudocode files",
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

        # Recursive function pseudocode export action
        self.handler_export_recursive_pseudocode = ExportRecursiveFunctionPseudocodeHandler()
        action_desc = ida_kernwin.action_desc_t(
            "assemport:export_recursive_pseudocode",
            "Export Recursive Function Pseudocode",
            self.handler_export_recursive_pseudocode,
            None,  # No shortcut
            "Export the current function and its sub-calls recursively to pseudocode files",
        )
        ida_kernwin.register_action(action_desc)

    def unregister_actions(self):
        """Unregister context menu actions"""
        ida_kernwin.unregister_action("assemport:export_single")
        ida_kernwin.unregister_action("assemport:export_single_pseudocode")
        ida_kernwin.unregister_action("assemport:export_selected")
        ida_kernwin.unregister_action("assemport:export_selected_pseudocode")
        ida_kernwin.unregister_action("assemport:export_recursive")
        ida_kernwin.unregister_action("assemport:export_recursive_pseudocode")

    def unhook_ui(self):
        """Unhook UI hooks"""
        global ui_hooks
        if ui_hooks:
            ui_hooks.unhook()
            ui_hooks = None

    def run(self, arg):
        skip_named = get_skip_named_setting()
        dedupe_asm = get_dedupe_asm_setting()
        f = AssemportSettingsForm(skip_named, dedupe_asm)
        f.Compile()
        if f.Execute() == 1:
            new_skip_named = (f.cGroup.value & 1) != 0
            new_dedupe_asm = (f.cGroup.value & 2) != 0
            set_skip_named_setting(new_skip_named)
            set_dedupe_asm_setting(new_dedupe_asm)
            print(f"[Assemport] Settings updated: Skip Named={new_skip_named}, Dedupe ASM={new_dedupe_asm}")
        f.Free()
