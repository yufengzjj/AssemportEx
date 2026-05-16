# AssemportEx

[![IDA Pro](https://img.shields.io/badge/IDA%20Pro-9.0+-blue.svg)](https://hex-rays.com/ida-pro/)
![License](https://img.shields.io/badge/license-MIT-green.svg)

IDA Pro (>= 9.0) plugin for exporting function assembly and pseudocode — built for external analysis and AI-assisted reverse engineering.

## Features
- Export functions as `.asm` or `.c` (Hex-Rays pseudocode).
- Recursive export of the call tree (skips library functions and thunks).
- Follows code/data references (branches, `ADR`/`ADRL`/`ADRP`/`LDR` operands, data pointers) so each `.asm` is self-contained.
- Single-function export from disassembly/pseudocode views, multi-selection from the Functions window.
- Safely handles hidden ranges and sanitizes filenames.

## Installation
Drop the `AssemportEx` folder into your IDA plugins directory:
- Windows: `%AppData%\Hex-Rays\IDA Pro\plugins\AssemportEx`
- Linux/macOS: `~/.idapro/plugins/AssemportEx`

Restart IDA.

## Usage
Right-click in **Disassembly**, **Pseudocode**, or the **Functions** window to export the current/selected function, or its full recursive call tree.

Output is written to an `Assemport/` folder next to your IDB.

## Settings
`Edit → Plugins → AssemportEx`:

| Setting | Effect |
|---|---|
| Skip Named Func | Recursive export skips functions with custom names (keeps `sub_XXXX`). |
| Skip Named Data | When following refs, skip data with custom names (assumed exported elsewhere). |
| Global ASM/DATA Fragment Deduplication | Deduplicates shared code/data fragments across recursive exports. |
| Skip Refs From Code | Don't follow operand refs (`ADR`,etc). Call/branch refs are still followed. |
| Skip Refs From Data | Don't follow pointer refs inside data (vtables, jump tables, etc.). |
| Merge Exported Functions Into One File | Recursive export writes every function into a single `.asm`/`.c` instead of one file per function. |
| Max Unknown Data Explore Length | When following a ref that lands on unknown bytes, keep walking up to N bytes past the first item. `0` (default) disables extra exploration. |

## Credits
Based on [Assemport](https://github.com/Bizarrus/Assemport) by [Bizarrus](https://github.com/Bizarrus). Enhanced for IDA 9.0+.
