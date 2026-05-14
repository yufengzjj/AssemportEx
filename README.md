# AssemportEx (assemport++)

[![IDA Pro](https://img.shields.io/badge/IDA%20Pro-9.0+-blue.svg)](https://hex-rays.com/ida-pro/)
![License](https://img.shields.io/badge/license-MIT-green.svg)

**AssemportEx** is an enhanced fork of [Assemport](https://github.com/Bizarrus/Assemport) for IDA Pro (>= 9.0). It allows for seamless exporting of function assembly and pseudocode, making it easier to analyze code in external editors or process it with AI tools.

## Features

- **Assembly & Pseudocode Export**: Export functions as `.asm` (Disassembly) or `.c` (Hex-Rays Pseudocode).
- **Recursive Exporting**: Automatically identifies and exports all sub-calls made by a function (skips library functions and thunks).
- **Flexible Selection**: 
  - Export a single function from the disassembly/pseudocode view.
  - Export multiple selected functions directly from the **Functions Window**.
- **Smart Recursive Filtering**: Toggle whether to skip exporting functions that already have custom names (via Plugins menu).
- **IDA 9.0 Optimized**: Support for the latest IDA 9.0 UI and chooser widgets.
- **Safe Extraction**: Automatically handles hidden ranges and sanitizes filenames.

## Installation

1. Download the repository.
2. Place the `AssemportEx` folder into your IDA plugins directory:
   - **Windows**: `%AppData%\Hex-Rays\IDA Pro\plugins\AssemportEx`
   - **Linux/macOS**: `~/.idapro/plugins/AssemportEx`
3. Restart IDA Pro or use `Ctrl+Shift+P` to refresh plugins.

## Usage

### Context Menu
Right-click on a function name or within the disassembly/pseudocode window to access:
- **Export Function Assembly**: Save the current function as an `.asm` file.
- **Export Function Pseudocode**: Save the current function as a `.c` file.
- **Export Recursive Function Assembly/Pseudocode**: Export the function and its entire call tree.

### Functions Window
Select one or more functions in the **Functions Window** (usually `Shift+F3`), right-click, and select:
- **Export Selected Functions Assembly**
- **Export Selected Functions Pseudocode**

### Configuration
navigate to `Edit -> Plugins -> AssemportEx` to toggle the **Skip Named Functions** setting.
- **Enabled**: Recursive exports will only include functions with default IDA names (e.g., `sub_XXXXXX`), skipping functions you've already named or that were imported with names.
- **Disabled**: Recursive exports will include all called functions (except library functions).

## Output
All files are saved in an `Assemport` subdirectory relative to your database file.

## Credits
- Originally created by [Bizarrus](https://github.com/Bizarrus/Assemport).
- Enhanced and updated for IDA 9.0 by the community.
