use std::{
    env, fs,
    time::{SystemTime, UNIX_EPOCH},
};

use pe_mutator_core::{
    DEFAULT_SEED, PeMutationCategory, PeMutationCategorySet, PeMutationSet, PeMutator,
    PeMutatorConfig, SimpleRng,
    pe::{self, PeInput, machine_family},
};

fn parse_pe(path: &str) -> Result<(), String> {
    let bytes = fs::read(path).map_err(|err| format!("failed to read {path}: {err}"))?;
    let input = PeInput::parse(&bytes).map_err(|err| format!("failed to parse {path}: {err}"))?;
    print!("{}", input.summary());
    Ok(())
}

fn emit_template(machine: &str, output: &str) -> Result<(), String> {
    let machine = match machine {
        "x86" => pe::IMAGE_FILE_MACHINE_I386,
        "x64" => pe::IMAGE_FILE_MACHINE_AMD64,
        "armnt" => pe::IMAGE_FILE_MACHINE_ARMNT,
        "arm64" => pe::IMAGE_FILE_MACHINE_ARM64,
        other => return Err(format!("unknown machine template: {other}")),
    };

    let input = PeInput::template(machine);
    let bytes = input
        .to_bytes()
        .map_err(|err| format!("failed to serialize template: {err}"))?;
    fs::write(output, bytes).map_err(|err| format!("failed to write {output}: {err}"))?;
    println!("wrote {} template to {}", machine_family(machine), output);
    Ok(())
}

#[derive(Debug, Clone)]
struct MutateArgs {
    input: String,
    output: Option<String>,
    report: Option<String>,
    seed: Option<u64>,
    stack_depth: Option<usize>,
    min_stack_depth: Option<usize>,
    max_stack_depth: Option<usize>,
    overlay_max_len: Option<usize>,
    enable_categories: Vec<PeMutationCategory>,
    disable_categories: Vec<PeMutationCategory>,
}

fn parse_integer<T>(value: &str, flag: &str) -> Result<T, String>
where
    T: TryFrom<u64>,
{
    let parsed = if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16)
    } else {
        value.parse::<u64>()
    }
    .map_err(|err| format!("invalid value for {flag}: {value} ({err})"))?;

    T::try_from(parsed).map_err(|_| format!("value out of range for {flag}: {value}"))
}

fn next_flag_value(args: &[String], index: &mut usize, flag: &str) -> Result<String, String> {
    *index += 1;
    args.get(*index)
        .cloned()
        .ok_or_else(|| format!("missing value for {flag}"))
}

fn parse_mutation_category(value: &str) -> Result<PeMutationCategory, String> {
    let normalized = value
        .trim()
        .chars()
        .filter(|ch| !matches!(ch, '-' | '_' | ' ' | '\t'))
        .flat_map(char::to_lowercase)
        .collect::<String>();

    match normalized.as_str() {
        "architecture" => Ok(PeMutationCategory::Architecture),
        "headers" => Ok(PeMutationCategory::Headers),
        "sections" => Ok(PeMutationCategory::Sections),
        "assembly" => Ok(PeMutationCategory::Assembly),
        "datadirectories" => Ok(PeMutationCategory::DataDirectories),
        "overlay" => Ok(PeMutationCategory::Overlay),
        _ => Err(format!(
            "unknown mutation category: {value} (expected one of: architecture, headers, sections, assembly, data-directories, overlay)"
        )),
    }
}

fn parse_category_list(value: &str, flag: &str) -> Result<Vec<PeMutationCategory>, String> {
    let mut categories = Vec::new();
    for raw in value.split(',') {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(format!("empty category in {flag}: {value}"));
        }
        categories.push(parse_mutation_category(trimmed)?);
    }
    Ok(categories)
}

fn parse_mutate_args(args: &[String]) -> Result<MutateArgs, String> {
    let mut input = None;
    let mut output = None;
    let mut report = None;
    let mut seed = None;
    let mut stack_depth = None;
    let mut min_stack_depth = None;
    let mut max_stack_depth = None;
    let mut overlay_max_len = None;
    let mut enable_categories = Vec::new();
    let mut disable_categories = Vec::new();

    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "-o" | "--output" => {
                output = Some(next_flag_value(args, &mut index, "--output")?);
            }
            "--report" => {
                report = Some(next_flag_value(args, &mut index, "--report")?);
            }
            "--seed" => {
                let value = next_flag_value(args, &mut index, "--seed")?;
                seed = Some(parse_integer::<u64>(&value, "--seed")?);
            }
            "--stack-depth" => {
                let value = next_flag_value(args, &mut index, "--stack-depth")?;
                stack_depth = Some(parse_integer::<usize>(&value, "--stack-depth")?);
            }
            "--min-stack-depth" => {
                let value = next_flag_value(args, &mut index, "--min-stack-depth")?;
                min_stack_depth = Some(parse_integer::<usize>(&value, "--min-stack-depth")?);
            }
            "--max-stack-depth" => {
                let value = next_flag_value(args, &mut index, "--max-stack-depth")?;
                max_stack_depth = Some(parse_integer::<usize>(&value, "--max-stack-depth")?);
            }
            "--overlay-max-len" => {
                let value = next_flag_value(args, &mut index, "--overlay-max-len")?;
                overlay_max_len = Some(parse_integer::<usize>(&value, "--overlay-max-len")?);
            }
            "--enable-category" => {
                let value = next_flag_value(args, &mut index, "--enable-category")?;
                enable_categories.extend(parse_category_list(&value, "--enable-category")?);
            }
            "--disable-category" => {
                let value = next_flag_value(args, &mut index, "--disable-category")?;
                disable_categories.extend(parse_category_list(&value, "--disable-category")?);
            }
            value if value.starts_with('-') => {
                return Err(format!("unknown mutate option: {value}"));
            }
            value => {
                if input.is_some() {
                    return Err(format!("unexpected positional argument: {value}"));
                }
                input = Some(value.to_string());
            }
        }
        index += 1;
    }

    let input = input.ok_or_else(|| "missing input path for mutate".to_string())?;

    Ok(MutateArgs {
        input,
        output,
        report,
        seed,
        stack_depth,
        min_stack_depth,
        max_stack_depth,
        overlay_max_len,
        enable_categories,
        disable_categories,
    })
}

fn default_seed() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_nanos() as u64,
        Err(_) => DEFAULT_SEED,
    }
}

fn render_mutation_report(
    input_path: &str,
    output_path: &str,
    input_len: usize,
    output_len: usize,
    seed: u64,
    config: &PeMutatorConfig,
    report: &pe_mutator_core::PeMutationReport,
) -> String {
    let size_delta = output_len as i128 - input_len as i128;
    let mutation_names = if report.selected_mutations.is_empty() {
        "none".to_string()
    } else {
        report
            .selected_mutations
            .iter()
            .map(|kind| kind.name())
            .collect::<Vec<_>>()
            .join(", ")
    };

    format!(
        concat!(
            "input_path: {input_path}\n",
            "output_path: {output_path}\n",
            "in_place: {in_place}\n",
            "seed: 0x{seed:016x}\n",
            "input_size: {input_len}\n",
            "output_size: {output_len}\n",
            "size_delta: {size_delta}\n",
            "min_stack_depth: {min_stack_depth}\n",
            "max_stack_depth: {max_stack_depth}\n",
            "requested_stack_depth: {requested_stack_depth}\n",
            "attempted_mutations: {attempted_mutations}\n",
            "mutated_count: {mutated_count}\n",
            "skipped_count: {skipped_count}\n",
            "any_mutated: {any_mutated}\n",
            "overlay_max_len: {overlay_max_len}\n",
            "selected_mutations: {mutation_names}\n"
        ),
        input_path = input_path,
        output_path = output_path,
        in_place = input_path == output_path,
        seed = seed,
        input_len = input_len,
        output_len = output_len,
        size_delta = size_delta,
        min_stack_depth = config.stack.min_stack_depth,
        max_stack_depth = config.stack.max_stack_depth,
        requested_stack_depth = report.requested_stack_depth,
        attempted_mutations = report.attempted_count(),
        mutated_count = report.mutated_count,
        skipped_count = report.skipped_count,
        any_mutated = report.any_mutated(),
        overlay_max_len = config.overlay_max_len,
        mutation_names = mutation_names,
    )
}

fn build_mutator_config(args: &MutateArgs) -> PeMutatorConfig {
    let mut config = PeMutatorConfig::default();
    if let Some(depth) = args.stack_depth {
        config.stack.min_stack_depth = depth;
        config.stack.max_stack_depth = depth;
    }
    if let Some(min_depth) = args.min_stack_depth {
        config.stack.min_stack_depth = min_depth;
    }
    if let Some(max_depth) = args.max_stack_depth {
        config.stack.max_stack_depth = max_depth;
    }
    if let Some(overlay_max_len) = args.overlay_max_len {
        config.overlay_max_len = overlay_max_len;
    }
    if !args.enable_categories.is_empty() {
        config.enabled_categories = PeMutationCategorySet::NONE;
        // Category selection should expose every mutation kind within the chosen
        // categories, including non-default kinds like data-directory mutators.
        config.enabled_mutations = PeMutationSet::ALL;
        for category in args.enable_categories.iter().copied() {
            config.enabled_categories.insert(category);
        }
    }
    for category in args.disable_categories.iter().copied() {
        config.enabled_categories.remove(category);
    }
    let (min_depth, max_depth) = config.normalized_stack_depth_bounds();
    config.stack.min_stack_depth = min_depth;
    config.stack.max_stack_depth = max_depth;
    config
}

fn mutate_pe(args: &[String]) -> Result<(), String> {
    let args = parse_mutate_args(args)?;
    let config = build_mutator_config(&args);
    let input_path = args.input;
    let output_path = args.output.clone().unwrap_or_else(|| input_path.clone());
    let input_bytes =
        fs::read(&input_path).map_err(|err| format!("failed to read {}: {err}", input_path))?;

    let seed = args.seed.unwrap_or_else(default_seed);
    let mut mutator = PeMutator::with_config(SimpleRng::new(seed), config.clone());
    let (mutated_bytes, report) = mutator
        .mutate_bytes(&input_bytes)
        .map_err(|err| format!("failed to mutate {}: {err}", input_path))?;

    fs::write(&output_path, &mutated_bytes)
        .map_err(|err| format!("failed to write {}: {err}", output_path))?;

    if let Some(report_path) = args.report {
        let report_text = render_mutation_report(
            &input_path,
            &output_path,
            input_bytes.len(),
            mutated_bytes.len(),
            seed,
            &config,
            &report,
        );
        fs::write(&report_path, report_text)
            .map_err(|err| format!("failed to write report {}: {err}", report_path))?;
    }

    println!(
        "mutated {} -> {} (seed=0x{seed:016x}, stack_depth={}..{}, attempted={}, mutated={}, skipped={})",
        input_path,
        output_path,
        config.stack.min_stack_depth,
        config.stack.max_stack_depth,
        report.attempted_count(),
        report.mutated_count,
        report.skipped_count,
    );
    Ok(())
}

fn print_usage(bin: &str) {
    eprintln!("Usage:");
    eprintln!("  {bin} parse <file>");
    eprintln!("  {bin} template <x86|x64|armnt|arm64> <output>");
    eprintln!("  {bin} mutate <input> [options]");
    eprintln!();
    eprintln!("Mutate options:");
    eprintln!("  -o, --output <path>              Write mutated bytes to <path>");
    eprintln!("                                  Defaults to replacing <input> in place");
    eprintln!("      --report <path>              Write a mutation report to <path>");
    eprintln!("      --seed <n>                  RNG seed (decimal or 0x...)");
    eprintln!("      --stack-depth <n>           Use exactly <n> stacked mutations");
    eprintln!("      --min-stack-depth <n>       Minimum stacked mutations");
    eprintln!("      --max-stack-depth <n>       Maximum stacked mutations");
    eprintln!("      --overlay-max-len <n>       Maximum overlay length");
    eprintln!("      --enable-category <list>    Enable only the selected categories");
    eprintln!(
        "                                  Comma-separated: architecture, headers, sections, assembly, data-directories, overlay"
    );
    eprintln!("      --disable-category <list>   Disable only the selected categories");
    eprintln!(
        "                                  Comma-separated: architecture, headers, sections, assembly, data-directories, overlay"
    );
}

fn main() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("parse") => {
            let Some(path) = args.get(2) else {
                print_usage(&args[0]);
                return Ok(());
            };
            parse_pe(path)
        }
        Some("template") => {
            let (Some(machine), Some(output)) = (args.get(2), args.get(3)) else {
                print_usage(&args[0]);
                return Ok(());
            };
            emit_template(machine, output)
        }
        Some("mutate") => mutate_pe(&args[2..]),
        Some(_) | None => {
            print_usage(&args[0]);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{MutateArgs, build_mutator_config};
    use pe_mutator_core::{PeMutationCategory, PeMutationKind, PeMutationSet};

    fn args_with_categories(enable_categories: Vec<PeMutationCategory>) -> MutateArgs {
        MutateArgs {
            input: "input.exe".to_string(),
            output: None,
            report: None,
            seed: None,
            stack_depth: None,
            min_stack_depth: None,
            max_stack_depth: None,
            overlay_max_len: None,
            enable_categories,
            disable_categories: Vec::new(),
        }
    }

    #[test]
    fn enabling_categories_keeps_all_mutation_kinds_exported() {
        let config = build_mutator_config(&args_with_categories(vec![
            PeMutationCategory::DataDirectories,
        ]));

        assert_eq!(config.enabled_mutations, PeMutationSet::ALL);
        for kind in [
            PeMutationKind::DataDirectoryEntry,
            PeMutationKind::ExportDirectory,
            PeMutationKind::ResourceDirectory,
        ] {
            assert!(config.is_mutation_enabled(kind));
        }
    }

    #[test]
    fn every_core_mutation_kind_is_reachable_through_cli_categories() {
        for kind in PeMutationKind::ALL {
            let config = build_mutator_config(&args_with_categories(vec![kind.category()]));
            assert!(
                config.is_mutation_enabled(kind),
                "expected {kind:?} to stay reachable when enabling category {:?}",
                kind.category()
            );
        }
    }
}
