pub mod emulator {
    pub mod limits {
        pub const DEFAULT_BASIC_BLOCKS: usize = 3_000_000;
        pub const DEFAULT_INTERRUPTS: usize = 3_000;
        pub const DEFAULT_MMIO_READ: usize = 0;
        pub const DEFAULT_INPUT_READ_OVERDUE: usize = 150_000;
    }

    pub const ENABLE_HIT_COUNT: bool = true;
    pub const FIX_EXCEPTION_EDGE: bool = true;
    pub const FIX_TASK_SWITCH_EDGE: bool = true;
}

pub mod input {
    pub const INPUT_CONTEXT_TYPE: InputContextType = InputContextType::AccessContext;
    pub enum InputContextType {
        AccessContext, // pc, mmio, type
        MmioContext,   // mmio, type
        None,          // none
    }
}

pub mod fuzzer {
    use std::ops::RangeInclusive;

    // u8 bitmap with 32k entries (32 KiB)
    pub type CoverageBitmapEntry = u8;
    pub const COVERAGE_BITMAP_SIZE: usize = 0x8000;

    // corpus archive
    pub const ARCHIVE_KEEP_SHORTER_INPUT: bool = false;
    pub const ARCHIVE_EARLY_WRITE: bool =
        ARCHIVE_KEEP_SHORTER_INPUT || !super::corpus::REPLACE_WITH_SHORTER_INPUT;

    // AFL like mutation stacking (do all mutations, then execute)
    pub const MUTATION_STACKING: bool = true;
    pub const MUTATION_COUNT_POW2: RangeInclusive<usize> = 2..=5; // 4, 8, 16, 32

    // minimization
    pub const MINIMIZE_MUTATION_CHAIN: bool = true;
    pub const MINIMIZE_INPUT_LENGTH: bool = true;
    pub const REMOVE_UNREAD_VALUES: bool = true;

    // snapshot fuzzing (only partially supported)
    pub const SNAPSHPOT_MUTATION_LIMIT: usize = 100;

    // mono / chrono mutations
    pub const MUTATION_MODE_SWITCH_CHANCE: u8 = 1; // always switch mode
    pub const MUTATION_MODE_MONO: bool = true;
    pub const MUTATION_MODE_DISTRIBUTION: [usize; 2] = [
        50,                                      // MutationMode::Stream
        if MUTATION_MODE_MONO { 50 } else { 0 }, // MutationMode::Mono
    ];

    // 1/4 chance to add random to any mutated input
    pub const RANDOM_CHANCE_INPUT: Option<u8> = Some(4);
    pub const RANDOM_NEW_STREAM: bool = true; // add random count (if none is set) when new stream is found
    pub const RANDOM_EMPTY_STREAM: bool = true; // return random value for empty streams
    pub const RANDOM_NO_VIABLE_MUTATION: bool = true; // add random when no viable mutation was found (e.g. empty input)

    // stream distributions
    pub const STREAM_DISTRIBUTION_UNIFORM: bool = true;
    pub const STREAM_DISTRIBUTION_SUCCESS: bool = true;

    // fixed stream distributions
    pub const STREAM_RANDOM_DISTRIBUTION: [usize; 2] = [
        if STREAM_DISTRIBUTION_UNIFORM { 10 } else { 0 }, // StreamRandomDistribution::Uniform
        if STREAM_DISTRIBUTION_SUCCESS { 40 } else { 0 }, // StreamRandomDistribution::Success
    ];

    pub const SIZE_DISTRIBUTION_SCALE: SizeDistributionScale = SizeDistributionScale::BitValues;
    pub enum SizeDistributionScale {
        Bits,
        BitValues,
        BitValuesPow2,
        Bytes,
        Values,
    }

    // success distribution options
    pub const SUCCESS_DISTRIBUTION_LN_SUCCESSES: bool = false;
    pub const SUCCESS_DISTRIBUTION_LN_MUTATIONS: bool = false;
    pub const SUCCESS_DISTRIBUTION_PARENT_SUCCESS_NEW_COVERAGE: bool = true;
    pub const SUCCESS_DISTRIBUTION_PARENT_SUCCESS_SHORTER_INPUT: bool = false;
    pub const SUCCESS_DISTRIBUTION_UPDATE_INTERVAL: usize = 1_000;
    pub const SUCCESS_DISTRIBUTION_RESET_INTERVAL: Option<usize> = None;
    pub const SUCCESS_DISTRIBUTION_SCALE: Option<SizeDistributionScale> =
        Some(SizeDistributionScale::BitValuesPow2);

    // mutator distribution
    pub const MUTATOR_ERASE_VALUES: bool = false;
    pub const MUTATOR_INSERT_VALUE: bool = true;
    pub const MUTATOR_INSERT_REPEATED_VALUE: bool = true;
    pub const MUTATOR_CHANGE_VALUE: bool = true;
    pub const MUTATOR_OFFSET_VALUE: bool = true;
    pub const MUTATOR_INVERT_VALUE_BIT: bool = true;
    pub const MUTATOR_SHUFFLE_VALUES: bool = true;
    pub const MUTATOR_COPY_VALUE_PART: bool = true;
    pub const MUTATOR_CROSS_OVER_VALUE_PART: bool = true;
    pub const MUTATOR_SPLICE: bool = true;
    pub const MUTATOR_CHRONO_ERASE_VALUES: bool = true;
    pub const MUTATOR_CHRONO_COPY_VALUE_PART: bool = true;
    pub const MUTATOR_DICTIONARY: bool = false;
    pub const MUTATOR_INTERESTING_VALUE: bool = true;

    pub const MUTATOR_DISTRIBUTION: [usize; 14] = [
        if MUTATOR_ERASE_VALUES { 1 } else { 0 }, // EraseValues
        if MUTATOR_INSERT_VALUE { 1 } else { 0 }, // InsertValue
        if MUTATOR_INSERT_REPEATED_VALUE { 1 } else { 0 }, // InsertRepeatedValue
        if MUTATOR_CHANGE_VALUE { 1 } else { 0 }, // ChangeValue
        if MUTATOR_OFFSET_VALUE { 1 } else { 0 }, // OffsetValue
        if MUTATOR_INVERT_VALUE_BIT { 1 } else { 0 }, // InvertValueBit
        if MUTATOR_SHUFFLE_VALUES { 1 } else { 0 }, // ShuffleValues
        if MUTATOR_COPY_VALUE_PART { 1 } else { 0 }, // CopyValuePart
        if MUTATOR_CROSS_OVER_VALUE_PART { 1 } else { 0 }, // CrossOverValuePart
        if MUTATOR_SPLICE { 1 } else { 0 },       // Splice
        if MUTATOR_CHRONO_ERASE_VALUES { 1 } else { 0 }, // ChronoEraseValues
        if MUTATOR_CHRONO_COPY_VALUE_PART { 1 } else { 0 }, // ChronoCopyValuePart
        if MUTATOR_DICTIONARY { 1 } else { 0 },   // Dictionary
        if MUTATOR_INTERESTING_VALUE { 1 } else { 0 }, // InterestingValue
    ];
}

pub mod corpus {
    pub const MIN_RARE_FEATURES: usize = 100;
    pub const FEATURE_FREQUENCY_THRESHOLD: u16 = 0xff;

    pub const MAX_MUTATION_FACTOR: f64 = 20f64;
    pub const UPDATE_ENERGY_INTERVAL: usize = 128;

    pub const REPLACE_WITH_SHORTER_INPUT: bool = true;

    pub const SCHEDULE_INPUT: bool = true;
    pub const SCHEDULE_EXIT: bool = false;
    pub const SCHEDULE_CRASH: bool = false;
    pub const SCHEDULE_TIMEOUT: bool = true;

    pub const SCALE_ENERGY: bool = true;
    pub const DISINCENTIVIZE_TIMEOUTS: bool = true;
    pub const TIMEOUT_SCALE: [f64; 4] = [
        1. / 100., // Limit::BasicBlocks
        1. / 50.,  // Limit::Interrupts
        1. / 10.,  // Limit::MmioRead
        1. / 5.,   // Limit::InputReadOverdue
    ];
    pub const DISINCENTIVIZE_BY_CHILD_RESULT: bool = true;
    pub const CHILD_RESULT_SCALE_INV: [usize; 4] = [
        1,  // 1    InputCategory::Input,
        10, // 1/10 InputCategory::Crash,
        10, // 1/10 InputCategory::Exit,
        5,  // 1/5  InputCategory::Timeout,
    ];
}

pub mod mutation {
    use std::ops::RangeInclusive;

    pub const MAX_RETRY: usize = 100;
    pub const MAX_CROSS_OVER_RETRY: usize = 10;

    // random mutation range
    pub const RANDOM_COUNT_INPUT_RANGE_POW2: RangeInclusive<usize> = 5..=8; // 32, 64, 128, 256
    pub const RANDOM_COUNT_STREAM_RANGE_POW2: RangeInclusive<usize> = 3..=5; // 8, 16, 32

    // max mutation block sizes
    pub const BLOCK_SIZES_DISTRIBUTION: [usize; 4] = [35, 35, 25, 5];
    pub const BLOCK_SIZES_POW2: [usize; 4] = [
        5,  // 2^5 = 32
        7,  // 2^7 = 128
        11, // 2^11 = 2048
        15, // 2^15 = 32k
    ];

    pub const SHUFFLE_RANGE: RangeInclusive<usize> = 2..=8;

    pub const INTERESTING_VALUES_U8: [u8; 7] = [
        0x10, // One-off with common buffer size
        0x20, // One-off with common buffer size
        0x40, // One-off with common buffer size
        0x64, // One-off with common buffer size
        0x7f, // Overflow signed 8-bit when incremented
        0x80, // Overflow signed 8-bit when decremented
        0xff, // Overflow unsig 8-bit when incremented
    ];
    pub const INTERESTING_VALUES_U16: [u16; 14] = [
        0x10,   // One-off with common buffer size
        0x20,   // One-off with common buffer size
        0x40,   // One-off with common buffer size
        0x64,   // One-off with common buffer size
        0x7f,   // Overflow signed 8-bit when incremented
        0xff,   // Overflow unsig 8-bit when incremented
        0x0100, // Overflow unsig 8-bit
        0x0200, // One-off with common buffer size
        0x03e8, // One-off with common buffer size
        0x0400, // One-off with common buffer size
        0x1000, // One-off with common buffer size
        0x7fff, // Overflow signed 16-bit when incremented
        0x8000, // Overflow signed 16-bit when decremented
        0xffff, // Overflow unsig 16-bit when incremented
    ];
    pub const INTERESTING_VALUES_U32: [u32; 21] = [
        0x10,        // One-off with common buffer size
        0x20,        // One-off with common buffer size
        0x40,        // One-off with common buffer size
        0x64,        // One-off with common buffer size
        0x7f,        // Overflow signed 8-bit when incremented
        0xff,        // Overflow unsig 8-bit when incremented
        0x0100,      // Overflow unsig 8-bit
        0x0200,      // One-off with common buffer size
        0x03e8,      // One-off with common buffer size
        0x0400,      // One-off with common buffer size
        0x1000,      // One-off with common buffer size
        0x7fff,      // Overflow signed 16-bit when incremented
        0x8000,      // Overflow signed 16-bit when decremented
        0xffff,      // Overflow unsig 16-bit when incremented
        0x0001_0000, // Overflow unsig 16 bit
        0x05ff_ff05, // Large positive number (endian-agnostic)
        0x7fff_ffff, // Overflow signed 32-bit when incremented
        0x8000_0000, // Overflow signed 32-bit when decremented
        0xfa00_00fa, // Large negative number (endian-agnostic)
        0xffff_7fff, // Overflow signed 16-bit
        0xffff_ffff, //
    ];
}

pub mod statistics {
    use std::time::Duration;

    pub const MIN_UPDATE_INTERVAL: Duration = Duration::from_secs(1);
    pub const MAX_UPDATE_INTERVAL: Duration = Duration::from_secs(60);

    pub const EXECUTIONS_HISTORY: bool = true;
    pub const INPUT_SIZE_HISTORY: bool = true;
    pub const MUTATION_GRAPH: bool = true;
}

pub mod fuzzware {
    pub const DEFAULT_LOCAL_BINARY: &str = "fuzzware";
    pub const DEFAULT_DOCKER_BINARY: &str = "docker";
    pub const DEFAULT_DOCKER_IMAGE: &str = "fuzzware";
    pub const DEFAULT_DOCKER_TAG: &str = "latest";
    pub const MODEL_PER_PC_LIMIT: usize = 16;
}
