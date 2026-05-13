import os

import ida_bytes
import ida_fpro
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_kernwin
import ida_loader
import ida_range
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


class ExportSelectedFunctionsHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        # Get selected functions from Functions window if it's active
        if hasattr(ctx, "widget_type") and ctx.widget_type == ida_kernwin.BWN_FUNCS:
            # Get selection from the Functions window
            selection = (
                ctx.chooser_selection if hasattr(ctx, "chooser_selection") else []
            )
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
        if hasattr(ctx, "widget_type") and ctx.widget_type == ida_kernwin.BWN_FUNCS:
            return (
                ida_kernwin.AST_ENABLE
                if hasattr(ctx, "chooser_selection") and ctx.chooser_selection
                else ida_kernwin.AST_DISABLE
            )
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
        return (
            ida_kernwin.AST_ENABLE
            if func and ida_hexrays.init_hexrays_plugin()
            else ida_kernwin.AST_DISABLE
        )


class ExportSelectedFunctionsPseudocodeHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        # Get selected functions from Functions window if it's active
        if hasattr(ctx, "widget_type") and ctx.widget_type == ida_kernwin.BWN_FUNCS:
            # Get selection from the Functions window
            selection = (
                ctx.chooser_selection if hasattr(ctx, "chooser_selection") else []
            )
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
        if hasattr(ctx, "widget_type") and ctx.widget_type == ida_kernwin.BWN_FUNCS:
            has_selection = hasattr(ctx, "chooser_selection") and ctx.chooser_selection
            has_hexrays = ida_hexrays.init_hexrays_plugin()
            return (
                ida_kernwin.AST_ENABLE
                if has_selection and has_hexrays
                else ida_kernwin.AST_DISABLE
            )
        return ida_kernwin.AST_DISABLE


class ExportSelectedFunctionsCombinedHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        # Get selected functions from Functions window if it's active
        if hasattr(ctx, "widget_type") and ctx.widget_type == ida_kernwin.BWN_FUNCS:
            # Get selection from the Functions window
            selection = (
                ctx.chooser_selection if hasattr(ctx, "chooser_selection") else []
            )
            if not selection:
                ida_kernwin.warning("No functions selected")
                return 1

            # Export selected functions to one combined assembly file
            export_selected_functions_combined(selection, "asm")
        else:
            ida_kernwin.warning("This action is only available in the Functions window")
        return 1

    def update(self, ctx):
        # Enable only in Functions window with selection
        if hasattr(ctx, "widget_type") and ctx.widget_type == ida_kernwin.BWN_FUNCS:
            return (
                ida_kernwin.AST_ENABLE
                if hasattr(ctx, "chooser_selection") and ctx.chooser_selection
                else ida_kernwin.AST_DISABLE
            )
        return ida_kernwin.AST_DISABLE


class ExportSelectedFunctionsCombinedPseudocodeHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        # Get selected functions from Functions window if it's active
        if hasattr(ctx, "widget_type") and ctx.widget_type == ida_kernwin.BWN_FUNCS:
            # Get selection from the Functions window
            selection = (
                ctx.chooser_selection if hasattr(ctx, "chooser_selection") else []
            )
            if not selection:
                ida_kernwin.warning("No functions selected")
                return 1

            # Export selected functions to one combined pseudocode file
            export_selected_functions_combined(selection, "c")
        else:
            ida_kernwin.warning("This action is only available in the Functions window")
        return 1

    def update(self, ctx):
        # Enable only in Functions window with selection and hexrays available
        if hasattr(ctx, "widget_type") and ctx.widget_type == ida_kernwin.BWN_FUNCS:
            has_selection = hasattr(ctx, "chooser_selection") and ctx.chooser_selection
            has_hexrays = ida_hexrays.init_hexrays_plugin()
            return (
                ida_kernwin.AST_ENABLE
                if has_selection and has_hexrays
                else ida_kernwin.AST_DISABLE
            )
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
        return (
            ida_kernwin.AST_ENABLE
            if func and ida_hexrays.init_hexrays_plugin()
            else ida_kernwin.AST_DISABLE
        )


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
                ida_kernwin.attach_action_to_popup(
                    widget, popup_handle, "assemport:export_single", None
                )
                # Add recursive export action
                ida_kernwin.attach_action_to_popup(
                    widget, popup_handle, "assemport:export_recursive", None
                )

                # Add pseudocode export option if hexrays is available
                if ida_hexrays.init_hexrays_plugin():
                    ida_kernwin.attach_action_to_popup(
                        widget, popup_handle, "assemport:export_single_pseudocode", None
                    )
                    # Add recursive pseudocode export action
                    ida_kernwin.attach_action_to_popup(
                        widget,
                        popup_handle,
                        "assemport:export_recursive_pseudocode",
                        None,
                    )

        # For Functions window - add selected functions export
        elif widget_type == ida_kernwin.BWN_FUNCS:
            if hasattr(ctx, "chooser_selection") and ctx.chooser_selection:
                ida_kernwin.attach_action_to_popup(
                    widget, popup_handle, "assemport:export_selected", None
                )
                ida_kernwin.attach_action_to_popup(
                    widget, popup_handle, "assemport:export_selected_combined", None
                )
                # Add pseudocode export options if hexrays is available
                if ida_hexrays.init_hexrays_plugin():
                    ida_kernwin.attach_action_to_popup(
                        widget,
                        popup_handle,
                        "assemport:export_selected_pseudocode",
                        None,
                    )
                    ida_kernwin.attach_action_to_popup(
                        widget,
                        popup_handle,
                        "assemport:export_selected_combined_pseudocode",
                        None,
                    )


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

        # Get function ranges
        ranges = ida_range.rangeset_t()
        if ida_funcs.get_func_ranges(ranges, func) == ida_idaapi.BADADDR:
            print(f"[Assemport] Bad Range for function {func_name}")
            return

        start = ranges.begin().start_ea
        end = ranges.begin().end_ea

        # Save Content
        file = ida_fpro.qfile_t()
        filename = os.path.join(output, f"{func_name}.asm")

        if file.open(filename, "wt"):
            try:
                ida_loader.gen_file(ida_loader.OFILE_ASM, file.get_fp(), start, end, 0)
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

                # Get function ranges
                ranges = ida_range.rangeset_t()
                if ida_funcs.get_func_ranges(ranges, func) == ida_idaapi.BADADDR:
                    print(f"[Assemport] Bad Range for function {func_name}")
                    continue

                start = ranges.begin().start_ea
                end = ranges.begin().end_ea

                # Save Content
                file = ida_fpro.qfile_t()
                filename = os.path.join(output, f"{func_name}.asm")

                if file.open(filename, "wt"):
                    try:
                        ida_loader.gen_file(
                            ida_loader.OFILE_ASM, file.get_fp(), start, end, 0
                        )
                        print(
                            f"[Assemport] Exported function {func_name} to {filename}"
                        )
                        exported_count += 1
                    finally:
                        file.close()
                else:
                    print(f"[Assemport] Failed to create file {filename}")

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


def get_recursive_functions(start_ea):
    """Get all functions called by start_ea recursively, excluding library functions"""
    to_export = set()
    stack = [start_ea]

    while stack:
        ea = stack.pop()
        func = ida_funcs.get_func(ea)
        if not func:
            continue

        func_ea = func.start_ea
        if func_ea in to_export:
            continue

        # Don't export library functions and don't recurse into them
        if func.flags & ida_funcs.FUNC_LIB:
            continue

        # Check if it's a thunk with a non-default name (likely an import stub)
        # Default IDA names typically start with "sub_"
        if func.flags & ida_funcs.FUNC_THUNK:
            flags = ida_bytes.get_flags(func_ea)
            if ida_bytes.has_name(flags):
                continue

        to_export.add(func_ea)
        # Find all calls from this function
        for head in idautils.FuncItems(func_ea):
            for ref in idautils.CodeRefsFrom(head, False):
                called_func = ida_funcs.get_func(ref)
                if called_func and called_func.start_ea != func_ea:
                    stack.append(called_func.start_ea)

    return to_export


def export_recursive_functions(start_ea, mode="asm"):
    """Export a function and all its sub-calls recursively"""
    ida_kernwin.show_wait_box("Analyzing recursive calls...")

    try:
        functions_to_export = get_recursive_functions(start_ea)
        total = len(functions_to_export)

        if total == 0:
            ida_kernwin.warning("No functions found to export")
            return

        ida_kernwin.replace_wait_box(f"Exporting {total} functions...")

        # Get Working-Path
        path = os.path.dirname(ida_loader.get_path(ida_loader.PATH_TYPE_CMD))
        output = os.path.join(path, "Assemport")

        # Create Output-Directory
        try:
            os.mkdir(output)
        except FileExistsError:
            pass

        exported_count = 0

        for i, ea in enumerate(functions_to_export):
            if ida_kernwin.user_cancelled():
                break

            func = ida_funcs.get_func(ea)
            func_name = ida_funcs.get_func_name(ea)

            ida_kernwin.replace_wait_box(f"Exporting {i + 1}/{total}: {func_name}")

            if mode == "asm":
                # Get function ranges
                ranges = ida_range.rangeset_t()
                if ida_funcs.get_func_ranges(ranges, func) == ida_idaapi.BADADDR:
                    continue

                start = ranges.begin().start_ea
                end = ranges.begin().end_ea

                # Save Content
                file = ida_fpro.qfile_t()
                filename = os.path.join(output, f"{func_name}.asm")

                if file.open(filename, "wt"):
                    try:
                        ida_loader.gen_file(
                            ida_loader.OFILE_ASM, file.get_fp(), start, end, 0
                        )
                        exported_count += 1
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

        ida_kernwin.info(
            f"Recursively exported {exported_count} functions successfully!"
        )

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

                    print(
                        f"[Assemport] Exported function pseudocode {func_name} to {filename}"
                    )
                    exported_count += 1

                except Exception as e:
                    print(f"[Assemport] Error decompiling function {func_name}: {e}")

        ida_kernwin.info(
            f"Exported {exported_count} functions pseudocode successfully!"
        )

    finally:
        ida_kernwin.hide_wait_box()


def export_selected_functions_combined(selection_indices, file_type):
    """Export selected functions to one combined file"""
    if file_type == "asm":
        ida_kernwin.show_wait_box(
            "Exporting selected functions to combined assembly file..."
        )
        file_ext = "asm"
        export_func = export_function_assembly
    elif file_type == "c":
        ida_kernwin.show_wait_box(
            "Exporting selected functions to combined pseudocode file..."
        )
        file_ext = "c"
        export_func = export_function_pseudocode
        # Check if hexrays is available
        if not ida_hexrays.init_hexrays_plugin():
            ida_kernwin.warning("Hex-Rays decompiler is not available")
            return
    else:
        ida_kernwin.warning("Invalid file type specified")
        return

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

        # Create combined filename with timestamp
        import time

        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = os.path.join(output, f"combined_functions_{timestamp}.{file_ext}")

        exported_count = 0

        # Get all functions
        all_functions = list(idautils.Functions())

        with open(filename, "w", encoding="utf-8") as combined_file:
            # Write header
            if file_type == "asm":
                combined_file.write(
                    f"; Combined Assembly Export - {len(selection_indices)} functions\n"
                )
                combined_file.write(
                    f"; Generated on {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                )
                combined_file.write(";\n\n")
            else:
                combined_file.write(
                    f"/* Combined Pseudocode Export - {len(selection_indices)} functions */\n"
                )
                combined_file.write(
                    f"/* Generated on {time.strftime('%Y-%m-%d %H:%M:%S')} */\n\n"
                )

            for idx in selection_indices:
                if idx < len(all_functions):
                    ea = all_functions[idx]
                    func = ida_funcs.get_func(ea)

                    if func is None:
                        continue

                    # Get function name
                    func_name = ida_funcs.get_func_name(ea)

                    # Write separator and function header
                    if file_type == "asm":
                        combined_file.write(
                            f"\n; ===============================================\n"
                        )
                        combined_file.write(f"; Function: {func_name}\n")
                        combined_file.write(f"; Address: 0x{ea:x}\n")
                        combined_file.write(
                            f"; ===============================================\n\n"
                        )
                    else:
                        combined_file.write(
                            f"\n/* =============================================== */\n"
                        )
                        combined_file.write(f"/* Function: {func_name} */\n")
                        combined_file.write(f"/* Address: 0x{ea:x} */\n")
                        combined_file.write(
                            f"/* =============================================== */\n\n"
                        )

                    # Export function content
                    content = export_func(func, ea)
                    if content:
                        combined_file.write(content)
                        combined_file.write("\n\n")
                        exported_count += 1
                        print(
                            f"[Assemport] Added function {func_name} to combined file"
                        )

        print(f"[Assemport] Combined export saved to {filename}")
        ida_kernwin.info(
            f"Exported {exported_count} functions to combined {file_ext.upper()} file!\nFile: {filename}"
        )

    finally:
        ida_kernwin.hide_wait_box()


def export_function_assembly(func, ea):
    """Helper function to get assembly code for a function"""
    try:
        # Get function ranges
        ranges = ida_range.rangeset_t()
        if ida_funcs.get_func_ranges(ranges, func) == ida_idaapi.BADADDR:
            return None

        start = ranges.begin().start_ea
        end = ranges.begin().end_ea

        # Create a temporary file to capture assembly output
        import tempfile

        with tempfile.NamedTemporaryFile(
            mode="w+t", suffix=".asm", delete=False
        ) as temp_file:
            temp_filename = temp_file.name

        # Generate assembly to temp file
        file = ida_fpro.qfile_t()
        if file.open(temp_filename, "wt"):
            try:
                ida_loader.gen_file(ida_loader.OFILE_ASM, file.get_fp(), start, end, 0)
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


class Assemport(ida_idaapi.plugmod_t):
    def __init__(self):
        global ui_hooks

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
        action_desc = ida_kernwin.action_desc_t(
            "assemport:export_single",
            "Export Function Assembly",
            ExportSingleFunctionHandler(),
            None,  # No shortcut
            "Export the current function to an assembly file",
        )
        ida_kernwin.register_action(action_desc)

        # Single function pseudocode export action
        action_desc = ida_kernwin.action_desc_t(
            "assemport:export_single_pseudocode",
            "Export Function Pseudocode",
            ExportSingleFunctionPseudocodeHandler(),
            None,  # No shortcut
            "Export the current function to a pseudocode file",
        )
        ida_kernwin.register_action(action_desc)

        # Selected functions export action
        action_desc = ida_kernwin.action_desc_t(
            "assemport:export_selected",
            "Export Selected Functions Assembly",
            ExportSelectedFunctionsHandler(),
            None,  # No shortcut
            "Export selected functions to assembly files",
        )
        ida_kernwin.register_action(action_desc)

        # Selected functions pseudocode export action
        action_desc = ida_kernwin.action_desc_t(
            "assemport:export_selected_pseudocode",
            "Export Selected Functions Pseudocode",
            ExportSelectedFunctionsPseudocodeHandler(),
            None,  # No shortcut
            "Export selected functions to pseudocode files",
        )
        ida_kernwin.register_action(action_desc)

        # Selected functions combined assembly export action
        action_desc = ida_kernwin.action_desc_t(
            "assemport:export_selected_combined",
            "Export Selected Functions to Combined Assembly File",
            ExportSelectedFunctionsCombinedHandler(),
            None,  # No shortcut
            "Export selected functions to one combined assembly file",
        )
        ida_kernwin.register_action(action_desc)

        # Selected functions combined pseudocode export action
        action_desc = ida_kernwin.action_desc_t(
            "assemport:export_selected_combined_pseudocode",
            "Export Selected Functions to Combined Pseudocode File",
            ExportSelectedFunctionsCombinedPseudocodeHandler(),
            None,  # No shortcut
            "Export selected functions to one combined pseudocode file",
        )
        ida_kernwin.register_action(action_desc)

        # Recursive function export action
        action_desc = ida_kernwin.action_desc_t(
            "assemport:export_recursive",
            "Export Recursive Function Assembly",
            ExportRecursiveFunctionHandler(),
            None,  # No shortcut
            "Export the current function and its sub-calls recursively to assembly files",
        )
        ida_kernwin.register_action(action_desc)

        # Recursive function pseudocode export action
        action_desc = ida_kernwin.action_desc_t(
            "assemport:export_recursive_pseudocode",
            "Export Recursive Function Pseudocode",
            ExportRecursiveFunctionPseudocodeHandler(),
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
        ida_kernwin.unregister_action("assemport:export_selected_combined")
        ida_kernwin.unregister_action("assemport:export_selected_combined_pseudocode")
        ida_kernwin.unregister_action("assemport:export_recursive")
        ida_kernwin.unregister_action("assemport:export_recursive_pseudocode")

    def unhook_ui(self):
        """Unhook UI hooks"""
        global ui_hooks
        if ui_hooks:
            ui_hooks.unhook()
            ui_hooks = None

    def run(self, arg):
        ida_kernwin.show_wait_box("Processing Export")

        # Get Working-Path
        path = os.path.dirname(ida_loader.get_path(ida_loader.PATH_TYPE_CMD))
        output = os.path.join(path, "Assemport")

        print(f"[Assemport] Path = {path}")
        print(f"[Assemport] Output = {output}")

        # Create Output-Directory
        try:
            os.mkdir(output)
        except FileExistsError:
            pass
        except PermissionError:
            print(f"[Assemport] Permission denied: Unable to create '{output}'.")
        except Exception as e:
            print(f"[Assemport] An error occurred: {e}")

        try:
            all_eas = list(idautils.Functions())
            neas = len(all_eas)

            # Iterate each function
            for i, ea in enumerate(all_eas):
                if ida_kernwin.user_cancelled():
                    break

                # Get Func
                func = ida_funcs.get_func(ea)

                if func is None:
                    print("[Assemport] Not a Function, Skipping 0x%x" % ea)
                    continue

                # Get Name
                func_name = ida_funcs.get_func_name(ea)

                # Get Info
                range = ida_range.rangeset_t()
                if ida_funcs.get_func_ranges(range, func) == ida_idaapi.BADADDR:
                    print("[Assemport] Bad Range, Skipping 0x%x" % ea)
                    continue

                start = range.begin().start_ea
                end = range.begin().end_ea

                # Save Assembly Content
                file = ida_fpro.qfile_t()

                if file.open(os.path.join(output, "%s.asm" % func_name), "wt"):
                    try:
                        ida_loader.gen_file(
                            ida_loader.OFILE_ASM, file.get_fp(), start, end, 0
                        )
                    finally:
                        file.close()

                # Save Pseudocode Content (if decompiler is available)
                if ida_hexrays.init_hexrays_plugin():
                    try:
                        cfunc = ida_hexrays.decompile(ea)
                        if cfunc is not None:
                            pseudocode = str(cfunc)
                            filename = os.path.join(output, f"{func_name}.c")

                            with open(filename, "w", encoding="utf-8") as f:
                                f.write(pseudocode)

                            print(f"[Assemport] Exported pseudocode for {func_name}")
                    except Exception as e:
                        print(
                            f"[Assemport] Error decompiling function {func_name}: {e}"
                        )

                print(f"[Assemport] Handle function {func_name} on Address 0x{ea:x}")
                print(func)
                ida_kernwin.replace_wait_box(
                    "Processing Export...\n\n\t%d / %d\t" % (i + 1, neas)
                )

        finally:
            ida_kernwin.hide_wait_box()
