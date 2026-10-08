use std::{env, process, time::Instant};

use lattice_mesh_simulator::{simulate, SimulationConfig, SimulationReport};
use serde_json::{json, Value};

fn main() {
    match run(env::args().skip(1)) {
        Ok((output, converged)) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&output).expect("JSON serialization is infallible")
            );
            if !converged {
                process::exit(2);
            }
        }
        Err(error) => {
            eprintln!("{error}\n\n{}", usage());
            process::exit(64);
        }
    }
}

fn run(args: impl IntoIterator<Item = String>) -> Result<(Value, bool), String> {
    let mut args = args.into_iter();
    let command = args.next().unwrap_or_else(|| "simulate".to_owned());
    if command == "--help" || command == "-h" || command == "help" {
        return Ok((json!({ "usage": usage() }), true));
    }
    if command != "simulate" && command != "benchmark" {
        return Err(format!("unknown command `{command}`"));
    }

    let mut config = SimulationConfig::default();
    let mut iterations = 10_u32;
    while let Some(option) = args.next() {
        if option == "--help" || option == "-h" {
            return Ok((json!({ "usage": usage() }), true));
        }
        let value = args
            .next()
            .ok_or_else(|| format!("missing value for {option}"))?;
        match option.as_str() {
            "--nodes" => config.nodes = parse_value(&option, &value)?,
            "--events-per-node" => config.events_per_node = parse_value(&option, &value)?,
            "--seed" => config.seed = parse_value(&option, &value)?,
            "--drop-per-mille" => config.drop_per_mille = parse_value(&option, &value)?,
            "--duplicate-per-mille" => config.duplicate_per_mille = parse_value(&option, &value)?,
            "--max-delay-ticks" => config.max_delay_ticks = parse_value(&option, &value)?,
            "--max-ticks" => config.max_ticks = parse_value(&option, &value)?,
            "--capacity" => config.capacity = parse_value(&option, &value)?,
            "--iterations" if command == "benchmark" => iterations = parse_value(&option, &value)?,
            _ => return Err(format!("unknown option `{option}`")),
        }
    }

    if command == "simulate" {
        let report = simulate(config).map_err(|error| error.to_string())?;
        let converged = report.converged;
        return Ok((report_json(&report), converged));
    }

    if !(1..=1000).contains(&iterations) {
        return Err("--iterations must be between 1 and 1000".to_owned());
    }
    let started = Instant::now();
    let mut reports = Vec::with_capacity(iterations as usize);
    for iteration in 0..iterations {
        let run_config = SimulationConfig {
            seed: config.seed.wrapping_add(u64::from(iteration)),
            ..config
        };
        reports.push(simulate(run_config).map_err(|error| error.to_string())?);
    }
    let elapsed_nanos = started.elapsed().as_nanos();
    let converged_runs = reports.iter().filter(|report| report.converged).count();
    let attempted_packets: u64 = reports.iter().map(|report| report.packets_attempted).sum();
    let unique_ingress_copies: u64 = reports
        .iter()
        .map(|report| report.unique_ingress_copies)
        .sum();
    let simulated_ticks: u64 = reports.iter().map(|report| report.ticks_elapsed).sum();
    let reports_per_second = if elapsed_nanos == 0 {
        0.0
    } else {
        f64::from(iterations) * 1_000_000_000.0 / elapsed_nanos as f64
    };
    let output = json!({
        "benchmark": "deterministic-mesh-simulation",
        "iterations": iterations,
        "converged_runs": converged_runs,
        "seed_start": config.seed,
        "seed_end": config.seed.wrapping_add(u64::from(iterations - 1)),
        "wall_time_ns": elapsed_nanos,
        "runs_per_second": reports_per_second,
        "simulated_ticks": simulated_ticks,
        "packets_attempted": attempted_packets,
        "unique_ingress_copies": unique_ingress_copies,
        "scenario": {
            "nodes": config.nodes,
            "events_per_node": config.events_per_node,
            "drop_per_mille": config.drop_per_mille,
            "duplicate_per_mille": config.duplicate_per_mille,
            "max_delay_ticks": config.max_delay_ticks,
            "max_ticks": config.max_ticks,
        }
    });
    Ok((output, converged_runs == iterations as usize))
}

fn parse_value<T: std::str::FromStr>(option: &str, value: &str) -> Result<T, String> {
    value
        .parse()
        .map_err(|_| format!("invalid value `{value}` for {option}"))
}

fn report_json(report: &SimulationReport) -> Value {
    json!({
        "seed": report.seed,
        "nodes": report.nodes,
        "events_per_node": report.events_per_node,
        "total_events": report.total_events,
        "converged": report.converged,
        "ticks_elapsed": report.ticks_elapsed,
        "packets_attempted": report.packets_attempted,
        "packets_dropped": report.packets_dropped,
        "queue_full_attempts": report.queue_full_attempts,
        "duplicate_packets_queued": report.duplicate_packets_queued,
        "copies_delivered": report.copies_delivered,
        "duplicate_ingress_copies": report.duplicate_ingress_copies,
        "unique_ingress_copies": report.unique_ingress_copies,
        "delayed_copies": report.delayed_copies,
        "reordered_unique_copies": report.reordered_unique_copies,
        "max_queue_depth": report.max_queue_depth,
        "latency_ticks": {
            "min": report.latency_min_ticks,
            "p50": report.latency_p50_ticks,
            "p95": report.latency_p95_ticks,
            "max": report.latency_max_ticks,
        }
    })
}

fn usage() -> &'static str {
    "lattice-mesh-simulator <simulate|benchmark> [options]\n\
     Options: --nodes N --events-per-node N --seed N --drop-per-mille N\n\
     --duplicate-per-mille N --max-delay-ticks N --max-ticks N --capacity N\n\
     benchmark only: --iterations N\n\
     Limits: 2-16 nodes, 1-256 events per node, 0-1000 per-mille rates,\n\
     max delay 1024 ticks, max simulation 4096 ticks, queue capacity 1-4096."
}
