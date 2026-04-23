# Format-aware PE mutator

## Introduction
The project focuses on mutating Windows PE binaries while preserving enough structure to remain interesting for downstream parsers and classification logic. The current implementation includes generic PE mutations plus assembly-aware mutations for executable sections on x86 and x64.

## How does it work
`libafl-pe-mutator` can be used in three simple ways, depending on how your fuzzer is built:

1. Integrate it directly in a native LibAFL fuzzer.
   If your fuzzer is already written in Rust on top of LibAFL, you can add the `pe-mutator-libafl` crate and plug `PeMutator` into your mutation stage like any other LibAFL mutator.

2. Use it from C-like fuzzers through the C bindings.
   If your fuzzer supports custom mutators through a C ABI, such as AFL++, you can use the `pe-mutator-capi` crate and call the exported mutation entrypoints from your custom mutator bridge.

3. Run it as a standalone CLI tool.
   If you just want to mutate PE samples from the command line, the `pe-mutator-cli` crate provides a small utility to parse, generate, and mutate PE files without embedding the library into another fuzzer.

## Building and installing

The repository contains three crates in the main Cargo workspace:

- `pe-mutator-core`: the PE parsing, serialization, and mutation engine
- `pe-mutator-capi`: C bindings for external fuzzers
- `pe-mutator-cli`: a small standalone command-line frontend

Build them from the repository root with:

```bash
cargo build --release
```

This produces:

- the Rust library artifacts for `pe-mutator-core`
- the C ABI shared/static libraries for `pe-mutator-capi`
- the `pe-mutator-cli` executable

If you want only one component, you can build it explicitly:

```bash
cargo build --release -p pe-mutator-core
cargo build --release -p pe-mutator-capi
cargo build --release -p pe-mutator-cli
```

The LibAFL integration crate is kept outside the main workspace because it depends on a local LibAFL checkout. Build it separately with:

```bash
cargo build --release --manifest-path crates/pe-mutator-libafl/Cargo.toml
```

If you want to regenerate the C header in `crates/pe-mutator-capi/include/pe_mutator.h`, install `cbindgen` and run:

```bash
cargo install cbindgen
bash crates/pe-mutator-capi/generate-bindings.sh
```

There is no separate installer yet. For now, the usual workflow is to build the crate you need and then consume the resulting binary or library directly from `target/release/`.



## Usage

### CLI tool

The standalone CLI is the simplest way to try the mutator without integrating it into another fuzzer.

After building the project, the binary is available at:

```bash
./target/release/pe-mutator-cli
```

The CLI currently supports three subcommands:

- `parse`: parse a PE file and print a short structural summary
- `template`: generate a minimal PE template for a chosen architecture
- `mutate`: read a PE file, apply one or more mutations, and write the result back

A minimal mutation example looks like this:

```bash
./target/release/pe-mutator-cli mutate input.exe -o mutated.exe
```

This reads `input.exe`, applies a random PE-aware mutation stack, and writes the mutated output to `mutated.exe`.

If you want the tool to also emit a mutation report, you can use:

```bash
./target/release/pe-mutator-cli mutate input.exe -o mutated.exe --report mutation-report.txt
```

A few useful options are:

- `--seed <n>` to make mutations reproducible
- `--stack-depth <n>` to force an exact mutation stack depth
- `--min-stack-depth <n>` and `--max-stack-depth <n>` to control mutation stacking
- `--enable-category <list>` to restrict mutations to selected categories
- `--disable-category <list>` to exclude selected categories

For example, to mutate only data-directory-related structures:

```bash
./target/release/pe-mutator-cli mutate input.exe -o mutated.exe --enable-category data-directories
```

To inspect a sample before mutating it:

```bash
./target/release/pe-mutator-cli parse input.exe
```

To generate a fresh minimal PE sample:

```bash
./target/release/pe-mutator-cli template x64 template.exe
```

### Native LibAFL integration

If your fuzzer is already written in Rust on top of LibAFL, you can integrate `PeMutator` directly in the mutational stage.

A minimal `Cargo.toml` setup looks like this:

```toml
[dependencies]
libafl = { path = "../LibAFL/crates/libafl" }
libafl_bolts = { path = "../LibAFL/crates/libafl_bolts" }
libafl_pe_mutator = { path = "../libafl-pe-mutator/crates/pe-mutator-libafl", package = "pe-mutator-libafl" }
```

In `../libafl_bdclient_fuzzer`, the dependency is wired in exactly this style, with `pe-mutator-libafl` consumed as `libafl_pe_mutator`.

At a high level, the integration looks like this:

```rust
use libafl::mutators::{havoc_mutations, StdMOptMutator};
use libafl_pe_mutator::{
    core::{PeMutatorConfig, PeMutationCategory, PeMutationCategorySet, PeMutationKind, PeMutationSet},
    PeMutator, PeMutatorOptions,
};

fn pe_mutator_from_options(enable_report: bool) -> PeMutator {
    let mut enabled_categories = PeMutationCategorySet::ALL;
    let mut enabled_mutations = PeMutationSet::ALL;

    // Optional: restrict the active mutation groups.
    enabled_categories = PeMutationCategorySet::NONE;
    enabled_mutations = PeMutationSet::NONE;
    enabled_categories.insert(PeMutationCategory::Assembly);
    enabled_mutations.insert(PeMutationKind::EntryPoint);
    enabled_mutations.insert(PeMutationKind::ExecutableChunkAssembly);

    let config = PeMutatorConfig {
        min_stack_depth: 2,
        max_stack_depth: 2,
        enabled_categories,
        enabled_mutations,
        ..PeMutatorConfig::default()
    };

    PeMutator::with_options(
        config,
        PeMutatorOptions {
            reporting: enable_report.then(|| "/tmp/pe-report.txt".into()),
            max_size: Some(MAX_TARGET_INPUT_SIZE),
        },
    )
}
```

Then, plug that `PeMutator` instance into the normal LibAFL stage in place of the default mutator:

```rust
let mutator = pe_mutator_from_options(self.options.pe_mutator_reporting);
let mut stages = tuple_list!(StdMutationalStage::new(mutator));
```

## What exists

The project already targets mutations across these macro-categories:

- PE header and architecture-related fields
- section table and section contents
- assembly-aware executable code mutations
- overlay mutations
- data directory mutations
- export directory mutations
- resource directory mutations

## Next steps

The next important steps are:

- expanding assembly mutations to cover more instructions
- CLR directory mutations
- Import directory mutations
