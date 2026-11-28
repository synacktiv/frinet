use std::{
    fs::File,
    path::PathBuf,
    time::{Duration, Instant},
};

use clap::Parser;
use frinet_db::{
    db::Db,
    search::{Pattern, search_pattern},
    task::Task,
};
use frinet_index::{
    build_index,
    parser::{Pass, ProgressReporter, TraceFile},
    storage::FileStorage,
};
use indicatif::{
    HumanBytes, HumanDuration, MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle,
};
use log::{LevelFilter, Log, error, info};
use memmap2::Mmap;

use crate::mem_usage::{max_mem_usage, reset_mem_usage};

mod mem_usage;

#[derive(clap::Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Index a trace file
    Index {
        /// Input trace file (FRINET-TRACE format)
        trace_path: PathBuf,

        /// Output DB file
        db_path: PathBuf,
    },

    /// Pattern search inside an indexed DB
    Search {
        db_path: PathBuf,

        /// Enable regex mode
        #[arg(long)]
        regex: bool,

        /// Search pattern
        pattern: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Index {
            trace_path,
            db_path,
        } => {
            let multi = MultiProgress::new();
            setup_logger(Some(&multi));

            let start = Instant::now();
            reset_mem_usage();

            let mut parser = match TraceFile::open(&trace_path) {
                Ok(parser) => parser,
                Err(err) => {
                    error!("Cannot open trace '{}' : {err}", trace_path.display());
                    std::process::exit(1);
                }
            };

            let mut reporter = CliIndexingReporter::new(multi.clone());
            let mut storage = match FileStorage::create(&db_path) {
                Ok(storage) => storage,
                Err(err) => {
                    error!("Cannot create database '{}' : {err}", db_path.display());
                    std::process::exit(1);
                }
            };

            if let Err(err) = build_index(&mut parser, &mut reporter, &mut storage, 3) {
                error!("Indexing failed : {err}");
                std::process::exit(1);
            }
            reporter.finish();

            // build is over, prevent redrawing progress bars after logging a message
            multi.set_draw_target(ProgressDrawTarget::hidden());

            let duration = start.elapsed();
            let mem_usage = max_mem_usage();

            info!("Total time : {}", HumanDuration(duration));
            info!("Maximum memory usage : {}", HumanBytes(mem_usage as _));
        }
        Commands::Search {
            db_path,
            regex,
            pattern,
        } => {
            setup_logger(None);

            let pattern = if regex {
                Pattern::parse(&pattern)
            } else {
                Pattern::literal(pattern.as_bytes())
            };
            let pattern = pattern.unwrap_or_else(|err| {
                error!("Invalid pattern : {err}");
                std::process::exit(1);
            });

            let file = File::open(db_path).unwrap();
            let mmap = unsafe { Mmap::map(&file) }.unwrap();

            match Db::from_aligned_slice(&mmap) {
                Ok(db) => {
                    let mut count = 0;
                    for result in search_pattern(&db, &pattern, &Task::new()) {
                        println!(
                            "{}..{} : {:#x?}..{:#x?}",
                            result.time_min, result.time_max, result.addr_min, result.addr_max,
                        );
                        count += 1;
                    }
                    info!("{count} total matches");
                }
                Err(err) => {
                    error!("Loading fail : {err}")
                }
            }
        }
    }
}

/// Setup logging and optionnally with a progress bar see [LogWrapper]
fn setup_logger(progress: Option<&MultiProgress>) {
    let logger = env_logger::Builder::new()
        .filter_level(LevelFilter::Info)
        .parse_default_env()
        .build();

    let max_level = logger.filter();

    let boxed_logger: Box<dyn Log> = if let Some(multi) = progress.cloned() {
        Box::new(LogWrapper { log: logger, multi })
    } else {
        Box::new(logger)
    };

    let r = log::set_boxed_logger(boxed_logger);
    if r.is_ok() {
        log::set_max_level(max_level);
    }
}

/// A [`log::Log`] wrapper that keeps log output and [`MultiProgress`] bars from
/// clobbering each other.
struct LogWrapper<L: Log> {
    multi: MultiProgress,
    log: L,
}

impl<L: Log> Log for LogWrapper<L> {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        self.log.enabled(metadata)
    }

    fn log(&self, record: &log::Record) {
        if self.log.enabled(record.metadata()) {
            self.multi.suspend(|| self.log.log(record))
        }
    }

    fn flush(&self) {
        self.log.flush()
    }
}

struct CliIndexingReporter {
    current_pass: Option<Pass>,
    scout: ProgressBar,
    partitions: ProgressBar,
    fill: ProgressBar,
}

impl CliIndexingReporter {
    pub fn new(multi: MultiProgress) -> Self {
        let style = ProgressStyle::with_template(
            "{prefix:>10} [{elapsed_precise}] {wide_bar:.cyan/blue} {bytes:>7}/{total_bytes:7} {msg}",
        )
        .unwrap()
        .progress_chars("##-");

        let mut scout = ProgressBar::no_length().with_prefix("Scout");
        let mut partitions = ProgressBar::no_length().with_prefix("Partitions");
        let mut fill = ProgressBar::no_length().with_prefix("Fill");

        let bars = [&mut scout, &mut partitions, &mut fill];

        for bar in bars {
            *bar = multi.add(bar.clone().with_style(style.clone()));
            bar.force_draw();
        }

        Self {
            scout,
            partitions,
            fill,
            current_pass: None,
        }
    }

    fn bar(&mut self, pass: Pass) -> &mut ProgressBar {
        match pass {
            Pass::Scout => &mut self.scout,
            Pass::Partitions => &mut self.partitions,
            Pass::Fill => &mut self.fill,
        }
    }

    fn finish(&mut self) {
        if let Some(pass) = self.current_pass.take() {
            self.bar(pass).finish();
        }
    }
}

impl ProgressReporter for CliIndexingReporter {
    fn start(&mut self, pass: Pass) {
        self.finish();
        self.current_pass = Some(pass);
        self.bar(pass).set_elapsed(Duration::ZERO);
    }

    fn total(&mut self, total: usize) {
        if let Some(pass) = self.current_pass {
            self.bar(pass).set_length(total as _);
        }
    }

    fn current(&mut self, current: usize) {
        if let Some(pass) = self.current_pass {
            self.bar(pass).set_position(current as _);
        }
    }
}
