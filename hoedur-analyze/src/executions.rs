use std::time::Duration;

use fuzzer::statistics::ExecutionsHistory;

use crate::Point;

const DIFF_LEN: f32 = 5. * 60.; // 5 minutes

#[derive(Debug, Default)]
pub struct ExecutionsPlot {
    pub duration: Duration,
    pub total: ExecutionsData,
    pub per_second: ExecutionsData,
}

#[derive(Debug, Default)]
pub struct ExecutionsData {
    pub executions: Vec<Point>,
    pub minimizations: Vec<Point>,
    pub basic_blocks: Vec<Point>,
    pub interrupts: Vec<Point>,
    pub mmio_reads: Vec<Point>,
    pub mmio_writes: Vec<Point>,
}

impl ExecutionsPlot {
    pub fn from_history(executions_history: Vec<ExecutionsHistory>) -> Self {
        let mut current = ExecutionsHistory::default();
        let mut last = ExecutionsHistory::default();
        let mut plot = Self::default();

        let len = executions_history.len();
        for (i, executions) in executions_history.into_iter().enumerate() {
            plot.duration += executions.interval;
            current += executions;

            let ts_diff = (current.interval - last.interval).as_secs_f32();
            let is_last = (i + 1) == len;

            if ts_diff > DIFF_LEN || is_last {
                let timestamp = current.interval.as_secs_f32();
                let diff = current.clone() - last;

                // total
                let total = &mut plot.total;
                for (points, value_diff) in [
                    (&mut total.executions, diff.new_executions),
                    (&mut total.minimizations, diff.new_minimizations),
                    (&mut total.basic_blocks, diff.new_counts.basic_block()),
                    (&mut total.interrupts, diff.new_counts.interrupt()),
                    (&mut total.mmio_reads, diff.new_counts.mmio_read()),
                    (&mut total.mmio_writes, diff.new_counts.mmio_write()),
                ] {
                    let value = points.last().map(|(_, value)| value).copied().unwrap_or(0.);
                    points.push((timestamp, value + value_diff as f32));
                }

                // per second
                let per_second = &mut plot.per_second;
                for (points, value_diff) in [
                    (&mut per_second.executions, diff.new_executions),
                    (&mut per_second.minimizations, diff.new_minimizations),
                    (&mut per_second.basic_blocks, diff.new_counts.basic_block()),
                    (&mut per_second.interrupts, diff.new_counts.interrupt()),
                    (&mut per_second.mmio_reads, diff.new_counts.mmio_read()),
                    (&mut per_second.mmio_writes, diff.new_counts.mmio_write()),
                ] {
                    points.push((timestamp, value_diff as f32 / ts_diff));
                }

                last = current.clone();
            }
        }

        plot
    }
}
