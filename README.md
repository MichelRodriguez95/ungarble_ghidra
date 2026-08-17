# Ungarble for Ghidra

Recovers strings from Go binaries built with [garble](https://github.com/burrowers/garble) `-literals`, and optionally writes out a copy of the binary with those strings in plain sight.

It started as a port of Invoke RE's Binary Ninja plugin [Ungarble](https://github.com/Invoke-RE), and it still works the same way: find the code garble emits to rebuild a string at run time, emulate it, read the result. It has since grown a Go symbol-table parser, support for two more garble obfuscators the original didn't handle, and an in-place patcher.

If you only read one section, read [What it actually finds](#what-it-actually-finds). Those numbers are measured rather than hoped for, and they'll tell you whether this is worth your time on your particular binary.

## Requirements

Ghidra 11.3 or newer, launched in PyGhidra mode. PyGhidra means CPython 3, which is what makes the Unicorn backend possible at all — the old Jython 2.7 interpreter can't load native extension modules.

Only Ghidra 12.0 has actually been tested. The one API difference known to bite is Ghidra replacing `CodeUnit.EOL_COMMENT` with a `CommentType` enum; that's resolved in one place (`ungarble/compat.py`) and covered by tests, so 11.3 through 11.x ought to work. Nobody has run it there.

Nothing else is required. The PCode backend and the symbol parser have no third-party dependencies, and they're the paths that do most of the work.

## Install

Copy the `ungarble_ghidra` directory anywhere, then in Ghidra open **Window → Script Manager → Manage Script Directories** and add `ungarble_ghidra/ghidra_scripts`. `Ungarble.py`, `UngarbleHeadless.py` and `UngarbleAnalyze.py` show up under the **Golang** category.

Keep the layout as it is — the scripts find the `ungarble` package one directory above themselves.

### The refinery backend, if you want it

```sh
pip install -r requirements.txt
```

Optional, and since split/seed support landed it is no longer the better option — see [Backends](#backends). It exists so you can reproduce the original Binary Ninja plugin's results exactly.

Install it into the interpreter PyGhidra actually uses, not just any Python. If you launched Ghidra with `support/pyghidraRun`, that's the one; from inside Ghidra's Python window, `import sys; print(sys.executable)` will tell you.

Two traps. The distribution you want is `binary-refinery`; PyPI also carries an unrelated `refinery` (a Halo map editor) that installs a clashing top-level package. If `import refinery` works but `refinery.lib` is missing you have the wrong one — `pip uninstall refinery && pip install binary-refinery`. Ungarble detects this and falls back to PCode rather than failing.

The other: `binary-refinery` 0.11.x pins `lief~=0.17.0` while `goresolver` pins `lief~=0.16.4`, so pip may refuse to install both. This turned out to be survivable in practice — with refinery 0.11.2, goresolver 1.4.1 and lief 0.17.6 in one `site-packages`, goresolver ran fine, because it's invoked as a subprocess and never imported. If pip does block you, put refinery in its own virtualenv, or don't install it.

## Usage

### The window

Run `Ungarble.py` from the Script Manager and you get a table with buttons over it.

**Get Target Locations** identifies `slicebytetostring` and works out where each obfuscation sequence begins. Rows appear as they're found rather than all at the end, because these scans can take a while and the original's deferred population made it look hung. **Ungarble Locations** then emulates every row without a result yet, and **Cancel** stops it.

**Apply to Program** writes the recovered strings into the Ghidra database as EOL *and* PRE comments — the PRE ones are what make the decompiler show them inline — plus bookmarks. **Write Deobfuscated Binary** produces a runnable copy with the strings patched in; see [Patching](#patching-a-runnable-copy). **Recover Function Names** does what it says, from the Go symbol table; see [Function names](#function-names).

**Export Table…** saves JSON or CSV and **Copy All** puts the table on the clipboard as TSV. The **Backend** selector is explained under [Backends](#backends). Clicking an address navigates the listing; right-clicking a row offers *Ungarble String*, *Copy String* and *Go To Start/End Address*.

The workflow matches the original: find locations first, then ungarble them in bulk or one at a time.

### Headless

Not with `analyzeHeadless`. These scripts are `@runtime PyGhidra` and `analyzeHeadless` doesn't start Ghidra in PyGhidra mode — there is no flag for it. It completes the whole analysis and then fails with *"Ghidra was not started with PyGhidra. Python is not available"*. Use the `pyghidra` launcher instead:

```sh
pyghidra --project-path /path/to/projects --project-name MyProject \
    ./garbled_binary \
    /path/to/ungarble_ghidra/ghidra_scripts/UngarbleHeadless.py \
    results.json
```

`pyghidra` comes from the Python package that ships with Ghidra 12 (`pip install <GhidraInstallDir>/Ghidra/Features/PyGhidra/pypkg`) and needs `GHIDRA_INSTALL_DIR` set. It analyses the binary first unless you pass `--skip-analysis`, which you shouldn't — the finder needs the function list. From Python the equivalent is `pyghidra.run_script(binary, script, script_args=[...])`.

Flags: `--patch out.deobf` also writes a patched copy, `--names` recovers Go function names, `--graph` makes `--names` use GoResolver's slow graph matching, `--report file.json` imports a pre-made GoResolver report, and `--loose-patch` drops the side-effect guard — useful for comparing yield, not for output you rely on.

`UngarbleAnalyze.py` runs the whole pipeline — find, emulate, annotate, recover names — with no window and no arguments. A real auto-triggered Ghidra *Analyzer* would have to be a compiled Java class, since JPype can't subclass `AbstractAnalyzer` from Python, so this script is the copy-a-folder equivalent.

## What it actually finds

`garble -literals` picks among three literal obfuscators per string, and they differ at the callsite in how the decoded buffer gets handed to `slicebytetostring`:

| Family | What the callsite looks like | Where the blob is built |
| --- | --- | --- |
| stack | `lea rbx,[rsp+X]` / `mov ecx,imm` | the caller's own frame |
| split | `xor eax,eax` / `mov rbx,<reg>` / `mov rcx,<reg>` | a heap slice grown with `runtime.growslice` |
| seed | `mov rbx,[<reg>]` / `mov rcx,[<reg>+8]` | closures allocated with `runtime.newobject` |

The original plugin modelled only the stack family, and only the variant that builds its blob out of `mov reg, imm64` immediates. Three searches run now, in order, each additive so nothing an earlier one found gets lost.

The **block scan** is the port of the original, and finds the immediate-`mov` stack variant.

The **callsite anchor** doesn't care how the blob was built. It asks the callsite where its buffer is and how long, then walks backwards for the earliest instruction that writes into that stack range — whatever put the bytes there had to put them *there*. This also catches the stack variant that keeps its key in `.rodata` and decodes with a subtract loop, which has no large immediate anywhere for the block scan to latch onto.

The **subroutine search** handles split and seed, where there's no region in a caller to carve out because the decoder *is* a function.

Here's what that gets you on a garble v0.13 `-literals` build of the test program:

| | amd64 | arm64 |
| --- | --- | --- |
| `slicebytetostring` callsites | 365 | 351 |
| block scan alone (the original) | 54 | 0 |
| plus the callsite anchor | 192 | 183 |
| plus split and seed | 314 | 320 |
| of those, emulate to a string | 241 | 266 |
| of ten planted program strings | 5 | 8 |

That last row is the honest one. Tripling the location count is nice, but half the strings the program actually contains still don't come back on amd64. The ones that do are exact — the PCode backend reads the pointer and length the program passes, so there's no trailing junk from carving printable runs.

Two other gaps worth naming. Of 100 split decoders in the amd64 sample, 58 get found; the rest are inlined into functions too large to treat as a dedicated decoder. And 173 amd64 callsites are found by none of the three searches, some of which are ordinary `string(byteSlice)` conversions rather than garble sequences at all.

## Emulating a decoder

The stack family needs nothing but a stack. The other two call into the Go runtime, and that's what makes them harder than a longer pattern list would fix. Split calls `runtime.growslice` — six times, in the sample measured — to grow the byte slice it assembles. Seed calls `runtime.newobject` four times and then makes roughly two dozen *indirect* calls to the closures it just allocated, which is where the decryption actually happens.

Emulating the real helpers is hopeless; they want an initialised mheap, a goroutine and a P. Stepping over them is just as useless, because the decoder then works through a null pointer. So `ungarble/goruntime.py` stands in for them, and the rule that makes it work is this: a *direct* call to a runtime helper gets stubbed, an *indirect* call gets executed, because that's the obfuscator's own code.

Helpers are recognised by name out of the `gopclntab` the plugin already parses, rather than guessed from the callsite. `newobject` allocates from a fake heap, sized by reading `_type.Size_` at the type pointer instead of picking a number. `growslice` allocates a bigger buffer *and copies the old contents over*, which matters more than it sounds — the split decoder appends to that slice repeatedly and loses the string if each grow hands back a blank buffer. `memmove` and friends do the copy. Barriers and stack checks get stepped over. Anything else direct gets a fresh allocation, which is the right shape for an allocator and harmless otherwise.

Two more details. Every Go function opens with `cmp rsp,[r14+0x10]`, so `r14` gets pointed at the emulated stack rather than left at zero where it resolves through unmapped memory. And the stubbed pass runs *first*: it used to be the other way round, execute the calls and fall back to stepping over them, which burnt the instruction cap inside `runtime.newobject` 66 times per run. Reaching the callsite with implausible arguments now counts as an answer rather than a failure, so there's no second futile pass either.

## Function names

**Recover Function Names**, or `--names` headless, pulls Go function names out of the binary and applies them as function names, labels and PLATE comments. It needs nothing installed.

The bundled `gopclntab` parser is the reason. Go binaries carry a table mapping every function's entry address to its name, and it survives stripping. Two garble quirks defeat Ghidra's own Golang analyzer here: garble scrubs the build info, so `GoRttiMapper` throws *"Invalid Go version"*, and it randomises the pcHeader magic — `0xa0ab2568` instead of `0xFFFFFFF1` on the test binary. Any parser that validates the magic gives up. This one never looks at it and reads the structure directly. That's 2147 names in 0.7 seconds with nothing installed.

garble hashes the author's own names (`main.checkPassword` becomes `main.fwKj4nfcNL25`) but leaves the standard library alone, so the parser recovers most of the call graph's context even though the interesting names stay scrambled.

If `goresolver` is on your `PATH` the plugin shells out to it, resolved with `which` rather than a hard-coded path. Running it out-of-process means it uses its own environment, so its `lief` version can't clash with PyGhidra's. `resolve -x` extracts the same table the built-in parser reads; `resolve -g`, the GUI's "graph" option, additionally de-hashes the author's names by control-flow-graph similarity against reference builds. Graph mode is slow — it builds reference Go binaries — and it's the only way to turn `main.fwKj4nfcNL25` back into `main.checkPassword`. You can also point the plugin at a `report.json` made earlier, and its names take precedence.

Resolution order: GoResolver when present, otherwise the built-in parser, with a supplied report overlaid on top.

One measured detail worth passing on. The two sources agree on 2145 of 2147 names, and the two that differ are `type:.eq.[6]internal/cpu.option` versus `type:.eq.6.internal/cpu.option`. The built-in parser is the faithful one; GoResolver mangles the brackets.

### Do the names go into the patched binary?

No, and they don't need to. Recovered names are analysis metadata: they live in your Ghidra database and drive the decompiler, but a Go binary doesn't consult them at run time. The *strings* are different — the program rebuilds those at run time, so they have to be patched into the file.

It would be possible to append an ELF `.symtab` of the recovered names to the patched file, since appended sections aren't loaded and `nm`/`objdump` would then see them. That's a separate, ELF-specific feature and it isn't implemented. Ask if you want it.

## Patching a runnable copy

**Write Deobfuscated Binary**, or `--patch`, produces a copy of the executable that still runs but has its obfuscated strings replaced with plaintext, so `strings`, YARA and the decompiler see them without any emulation.

Everything here rests on one constraint: the patch has to be the same size and stay where it is. Go's `pclntab` maps program counters to runtime metadata — GC, stack unwinding, panics — and moving or resizing code invalidates it, after which the binary dies at run time. Fortunately garble's sequences are always *larger* than the strings they produce (a `mov r64, imm64` costs ten bytes per eight characters), so there's room.

There are two patch shapes, because the families differ in what owns the sequence. The stack family builds its blob in the caller's frame, so the patch replaces a region inside that caller and flows into the original `call slicebytetostring`:

```asm
xor eax, eax          ; nil tmp buffer
lea rbx, [rip+disp]   ; -> inline plaintext
mov ecx, <length>
jmp over
<plaintext bytes>
over:
nop ... nop           ; pad to the original call
```

Split and seed put their decoder in a dedicated function, so the patch replaces the whole function. That's *safer* rather than less safe: the function's contract is "return this string", so there's nothing else to preserve. It's also the only shape that can work — replacing just a region would overwrite the prologue (`push rbp` / `sub rsp,X`) and leave the epilogue (`add rsp,X` / `pop rbp` / `ret`) behind, unbalancing the stack.

```asm
xor  eax, eax
lea  rbx, [rip+disp]
mov  ecx, <length>
call slicebytetostring
ret
<plaintext bytes>
<0xCC padding to the original size>
```

Whole-function patching is amd64 only, and the reason is worth reading if you ever want to fix it. The arm64 version of that stub assembles correctly and passes verification, and the patched binary died anyway — twice. First it hung: aarch64 keeps the return address in `x30`, so the `bl` overwrites it, and a stub going straight from `bl` to `ret` returns to its own `ret` forever. With the link register saved and restored around the call it then died with `SIGILL` *on the inline plaintext*, meaning control was reaching the data along some path this model doesn't account for. Until that's understood, arm64 gets region patches only.

Both failures were invisible to re-emulation, which stops at the call and never reaches the return. Only executing the binary caught them.

### The guards

Four things can make a location get skipped, and all of them report rather than mis-patch.

If anything *outside* the sequence jumps or points into its interior, overwriting would corrupt that target. A garble sequence routinely spans several basic blocks and so contains internal branch targets — those are fine, they're part of the code being replaced. Only an external reference is a problem.

If the region has side effects the stub doesn't reproduce, it's skipped. The stub rebuilds exactly one thing, the `(pointer, length)` pair; anything else that code was doing is gone. What makes this check cheap is that the region ends immediately before a `call`, and Go's register ABI treats essentially every integer register as scratch across a call — so a scratch register the region clobbers needs no check at all, since the `call slicebytetostring` we leave in place could clobber it anyway. That leaves a short list to reject on: a write to `RSP`/`RBP`/`R14`(g)/`R15` (arm64: `SP`/`x29`/`x28`/`x18`), a `call` inside the region, a `ret` inside it, a store through anything that can't be tied to the frame, or undefined bytes in the middle. This applies to region patches only; a whole decoder function writes its own prologue and would be rejected by every one of them.

Strings that aren't constant get skipped. Broadening the search to the callsite also picks up ordinary `string(byteSlice)` conversions, whose contents are runtime data — patching one freezes an arbitrary snapshot into the program, and re-emulation can't tell the difference because it only confirms the stub reproduces whatever emulation produced. So each sequence runs from two different machine states and is only patched if they agree. In fairness this caught nothing on the test binary: the printable-ratio filter already rejects runtime conversions, whose buffers hold fill bytes in a blank machine. Defence in depth that did no work here.

Finally, every stub is re-emulated on the patched bytes before anything is written and dropped if the emulation doesn't hand back the expected plaintext. Worth being clear about what that proves: the stub is self-contained, so of course it produces the right pointer. It confirms the encoding, not that the region was safe to delete.

### What you get

On the amd64 test binary, 178 of 314 locations patched and 136 skipped and reported, every patch verified, and the written file byte-for-byte the same size and byte-for-byte identical in behaviour. Four of the ten planted strings are now visible to `strings` that weren't before. On arm64 it's 8 region patches, also verified by running the result under `qemu-aarch64`.

The side-effect guard costs nothing measurable. Over the 192 region locations, strict and loose mode both patched 114 — it rejected zero locations that loose mode accepted, which says these sequences really do have no effects beyond building the string.

To be plain about the limits: this does not un-garble a binary. Names stay hashed, metadata stays stripped, control flow is untouched. Only the strings become legible. Pair it with name recovery for the rest, and remember those live in your Ghidra database rather than in the file.

32-bit Go targets (386, arm) still use the stack-based ABI0, so they're reported as unsupported for patching rather than mis-patched. Their strings can still be recovered.

## Backends

`auto` means PCode. That's a change: it used to mean refinery-when-available, for bit-for-bit parity with the original plugin.

It stopped being the right default when split and seed support landed. Those decoders call into the Go runtime and only the PCode backend stands in for the helpers, so refinery sees the stack family and nothing else. Measured over the same 314 locations: 241 strings via PCode against 176 via refinery, and five of the ten planted strings against three. `refinery` is still selectable explicitly and is still the way to reproduce the original exactly.

**PCode** uses Ghidra's own `EmulatorHelper` and has no third-party dependencies. Emulation stops *at* the `call slicebytetostring`, so the Go register ABI still holds the arguments — `RBX` is the pointer and `RCX` the length on amd64, `x1` and `x2` on arm64 — and the string comes back exactly. If those registers look implausible it carves the longest printable run out of the emulated stack window instead, which is what `vstack | carve printable` amounts to. A permissive memory-fault handler treats faults as zero reads, so unmapped TLS and `.bss` accesses degrade rather than abort.

**refinery** feeds the raw file to Binary Refinery's `vstack` unit, Unicorn underneath, using the same pipeline strings the Binary Ninja version used:

```
vstack -C  -s=<stop> <start> -b <base> | carve printable -n 8        # bulk
vstack -W -c -L -s=<stop> <start> -b <base> | carve printable -n 9   # single row
```

It needs the original file on disk. Ungarble takes the path from `Program.getExecutablePath()` and prompts with a file chooser if that fails, the same fallback the Qt version had. Both the modern and legacy `vstack` argument spellings are emitted, since the CLI changed between refinery versions. Because `carve printable` returns whole printable runs, results can carry adjacent bytes that happened to sit next to the string on the stack — an XOR key of `0x20` bytes shows up as trailing spaces. That's inherent to the approach and matches the original.

## arm64

String recovery on arm64 works, and recovers more of the planted strings than amd64 does. That took two fixes, worth writing down because the symptom was total: the finder used to return zero locations.

The original search matches x86 instruction shapes and AArch64 has none of them. Counted over 40,000 instructions of a real garble arm64 build: zero matches for `MOV [mem], reg`, zero for `LEA reg, [mem]`, zero for the `xor` mnemonic. AArch64 stores with `str`/`strb`, takes addresses with `add x5, sp, #0x2b`, and zeroes with `orr x6, xzr, #0x18` or `movz`. A real callsite has none of the three shapes anywhere:

```asm
adrp  x5, 0x10a000          ; key in .rodata
add   x5, x5, #0x123
ldrb  w6, [x5, x1, LSL]
add   x7, sp, #0x136        ; buffer address into a register...
ldrb  w8, [x7, x1, LSL]
add   x6, x8, x6
strb  w6, [x7, x1, LSL]     ; ...and the store goes through *that*
...
add   x1, sp, #0x136        ; hand the buffer over
mov   x2, #0x1d             ; and its length
bl    runtime.slicebytetostring
```

So first, finding `slicebytetostring` at all. The heuristic can't, so the plugin asks the `gopclntab` for `runtime.slicebytetostring` by name and only falls back to the heuristic if that fails. The table survives garble and the plugin already parses it, so this costs nothing — and it's better on amd64 too, where it agreed with the heuristic exactly (`0x44e3e0`) in 0.7 seconds instead of 4.6.

Second, recognising the stores. Two things defeated the buffer search, both visible above. The buffer is addressed through a derived register, so the finder tracks registers holding `sp+k`. And Ghidra reports the memory operand of an AArch64 store as `refType=DATA` with `isWrite()` false, so a check built on operand ref types sees *no arm64 stores at all* — store detection goes through the p-code `STORE` op instead, which is portable. That one line was the difference between 192 locations on amd64 and 0 on arm64.

What's left: patching is mostly refused there, correctly, and Ghidra's emulator doesn't model AArch64 atomics, so runs log `Unimplemented CALLOTHER pcodeop (ExclusiveMonitorPass)` and are less robust than on amd64.

## How this maps to the original

The detection heuristics were rewritten rather than transliterated. The Binary Ninja version matched on *disassembly text tokens* — `len(instr[0]) == 5` for `mov ecx, 0x2e`, `== 12` for `mov qword [rsp+0x88], rbp`. Those counts are an artifact of Binary Ninja's tokeniser and mean nothing in Ghidra, so each is expressed against Ghidra's structured operand model with the same semantics:

| Binary Ninja | here | meaning |
| --- | --- | --- |
| `len(tokens) == 5` | `_is_reg_imm_mov` | `MOV reg, imm` |
| `len(tokens) == 12` | `_is_mem_store_mov` | `MOV [mem], reg` |
| `'lea'`, 5 tokens | `_is_lea_mem` | `LEA reg, [mem]` |
| `token[4].value` | `_imm` | the immediate |
| `match_param_type` | `_has_big_scalar` | any operand scalar > `0xFFFF` |

Class for class, `FindLocations` became `ungarble/finder.py`, `EmulateLocations` became `ungarble/engine.py` plus `ungarble/backends/`, the Qt `UngarblePaneWidget` became `ungarble/ui.py`, `BackgroundTaskThread` plus Qt signals became `ungarble/tasks.py`, and `binaryninja.log.Logger` became `ungarble/log.py`.

A few differences are deliberate. Ghidra's dockable `ComponentProvider` is an abstract Java class and JPype can only implement Java *interfaces* from Python, so the UI is a plain Swing `JFrame` parented to the tool; it picks up Ghidra's look and feel and navigates through `GoToService`, so it behaves like a native window without being one. Rows appear during the scan instead of only at the end. `check_bb_slicebytetostr` and `get_obf_start` recursed over basic-block edges with no visited set, and Go functions are loop-heavy, so both track visited blocks now. Everything under **Apply to Program**, export, name recovery and the patcher is new.

## Testing

```sh
python3 -m pytest
```

154 tests, no Ghidra, no JVM, no pip install — they run under plain CPython because the code they cover is deliberately Ghidra-free, and `ungarble.log` already degrades to `print` when `ghidra.util.Msg` is missing.

The stub encoders get the most attention, because they're the highest-risk lines here: a wrong displacement produces a binary that still runs and hands `slicebytetostring` the wrong bytes. Those tests *decode* each stub and assert that the `lea`/`adr` displacement really points at the inline plaintext and the jump really clears it, rather than comparing against golden hex — a golden-bytes test would happily pass a rewrite that broke the arithmetic in a self-consistent way. Also covered: the rel8-to-rel32 boundary at 127, four-byte alignment on arm64, the whole-function shape including the arm64 link-register save, every rejection path, `apply_patches` overlap handling, the `gopclntab` walk against a synthetic Go 1.18+ table (including the randomised magic and the empty-name sentinel), the printable carver, the GoResolver report reader, portable store detection, and both branches of the `CommentType` resolution.

The suite was checked by mutation. Nine deliberate bugs were introduced — an off-by-one `lea` displacement, a wrong `adr` offset, the rel8 boundary moved to 128, the arm64 branch forgetting its alignment padding, an inverted overlap test, `gopclntab` reading the wrong header field, `gopclntab` validating the magic, the empty-name sentinel counted in the sample, `carve` returning the shortest run — and all nine were caught. Removing the arm64 link-register save breaks fifteen tests.

### What the unit tests can't reach

Everything that needs a live `Program`: the finder's predicates and its three searches, the PCode emulator, the runtime stubs, the side-effect guard. And everything about whether a patched binary actually works.

That gap is not theoretical. During development, running a real binary caught seven bugs the unit suite did not and structurally could not: a guard that rejected every location, a finder that scored zero on arm64, a verification that stopped at the wrong address, a constancy check that rejected real literals, 628 redundant symbol-table parses in a single run, a call to `Function.getMaxAddress()` that doesn't exist, and two ways of producing a patched binary that assembled perfectly, passed verification, and then hung or died with `SIGILL`.

So the numbers in this README come from an end-to-end harness that compiles a Go program, builds it with `garble -literals` for amd64 and arm64, runs the plugin under PyGhidra against Ghidra 12.0, patches the binary and *executes the result*, diffing its stdout against the original. Baseline first: all ten planted strings are visible with `strings` in a plain `go build` and invisible in the garbled build, and the garbled binary runs.

Both patched binaries came out the same size as their inputs and produced stdout identical to the original — amd64 natively, arm64 under `qemu-aarch64`. The GUI was driven directly too: window, table, JSON and CSV export, clipboard, apply-to-program, backend selector. So were all three shipped scripts.

Two things the run did *not* confirm, said plainly because the numbers look like they do. "Runs identically" means one binary on one input; code paths the test program never takes were never executed, so a mis-patch on a cold path wouldn't have shown up. And only half the planted strings come back on amd64. This isn't a solved problem.

## Credits

The original Binary Ninja plugin is by [Invoke RE](https://github.com/Invoke-RE). The `vstack` unit is part of [Binary Refinery](https://github.com/binref/refinery) by @huettenhain.

garble's three literal obfuscators — and the insight that the split and seed decoders are standalone subroutines calling `runtime.growslice` and `runtime.newobject` — are documented in Mandiant's [GoStringUngarbler](https://github.com/mandiant/gostringungarbler) (Apache 2.0, Google LLC), whose `doc/StringObfuscation.md` is the best write-up of the transformations anywhere. The split and seed support here is built on that analysis, and the direct-versus-indirect call rule is theirs.

The implementations don't share code. GoStringUngarbler matches byte regexes over `.text`; this matches the same shapes against Ghidra's instruction model. Over the same test binary those byte patterns also matched 147 positions that aren't instruction boundaries, which is the practical reason for the difference rather than a stylistic one.

## License

Apache 2.0, as the original.
