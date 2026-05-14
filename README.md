# AssemportEx (assemport++)

[![IDA Pro](https://img.shields.io/badge/IDA%20Pro-9.0+-blue.svg)](https://hex-rays.com/ida-pro/)
![License](https://img.shields.io/badge/license-MIT-green.svg)

**AssemportEx** is an enhanced plugin for IDA Pro (>= 9.0) designed for seamless exporting of function assembly and pseudocode. It is optimized for external analysis and AI-assisted reverse engineering workflows.

## Features
- **Multi-Format Export**: Save functions as `.asm` (Disassembly) or `.c` (Hex-Rays Pseudocode).
- **Recursive Extraction**: Automatically identifies and exports the entire call tree (skips library functions and thunks).
- **Flexible Selection**: Export single functions from disassembly/pseudocode views or multiple selections from the **Functions Window**.
- **IDA 9.0 Optimized**: Full support for the latest IDA 9.0 UI components and chooser widgets.
- **Safe extraction**: Handles hidden ranges, unhides chunks temporarily for export, and sanitizes filenames.

## Installation
Place the `AssemportEx` folder into your IDA plugins directory:
- **Windows**: `%AppData%\Hex-Rays\IDA Pro\plugins\AssemportEx`
- **Linux/macOS**: `~/.idapro/plugins/AssemportEx`

Restart IDA Pro or use `Ctrl+Shift+P` to refresh plugins.

## Usage & Configuration

### Exporting Code
Right-click on a function or selection in the **Disassembly**, **Pseudocode**, or **Functions Window** to access:
- **Export Function Assembly/Pseudocode**: Save the current or selected functions.
- **Export Recursive**: Export the function and all sub-calls in the tree.

### Settings
Navigate to `Edit -> Plugins -> AssemportEx` to configure:
- **Skip Named Functions**: Recursive exports skip functions with custom names, focusing on auto-named `sub_XXXX` functions.
- **Global ASM Fragment Deduplication**: Prevents redundant export of shared code blocks across different functions during recursive ASM export.

## Output
All files are saved in an `Assemport` subdirectory relative to your database file.

## Credits
- Based on the original [Assemport](https://github.com/Bizarrus/Assemport) by [Bizarrus](https://github.com/Bizarrus/Assemport).
- Enhanced and updated for IDA 9.0+.
