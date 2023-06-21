use average::{Estimate, Mean};
use common::FxHashMap;
use fuzzer::statistics::InputSizeHistory;

use crate::{add_last_point, add_point, Point};

const MIN_DIFF: f32 = 60.; // 1 min

#[derive(Debug, Default)]
pub struct InputPlot {
    pub count: Vec<Point>,
    pub size_values: InputSizePlot,
    pub size_bytes: InputSizePlot,
}

#[derive(Debug, Default)]
pub struct InputSizePlot {
    pub max_size: Vec<Point>,
    pub mean_size: Vec<Point>,
    pub median_size: Vec<Point>,
}

impl InputPlot {
    pub fn from_history(input_size_history: &[InputSizeHistory]) -> Self {
        let mut input_values = FxHashMap::default();
        let mut input_bytes = FxHashMap::default();
        let mut size_values: Vec<usize> = vec![];
        let mut size_bytes: Vec<usize> = vec![];
        let mut mean_size_values = Mean::new();
        let mut mean_size_bytes = Mean::new();
        let mut plot = Self::default();
        let mut ts = 0.;

        let start = if let Some(start) = input_size_history.first() {
            start.timestamp
        } else {
            return plot;
        };

        for input_size in input_size_history {
            ts = (input_size.timestamp - start) as f32;
            debug_assert!(input_size.timestamp >= start);

            for (inputs, size, sizes, mean_size) in [
                // input size (values)
                (
                    &mut input_values,
                    input_size.input_len,
                    &mut size_values,
                    &mut mean_size_values,
                ),
                // input size (bytes)
                (
                    &mut input_bytes,
                    input_size.input_bytes,
                    &mut size_bytes,
                    &mut mean_size_bytes,
                ),
            ] {
                // track input sizes
                if let Some(old_size) = inputs.insert(input_size.input_id, size) {
                    match sizes.binary_search(&old_size) {
                        Ok(idx) => {
                            // update old input size
                            sizes[idx] = size;

                            // (re)calculate mean size
                            *mean_size = sizes.iter().map(|size| *size as f64).collect::<Mean>();
                        }
                        // old input size missing => should never happen
                        Err(_) => unreachable!(),
                    }
                } else {
                    // new input => add input size
                    sizes.push(size);

                    // add input size to mean
                    mean_size.add(size as f64);
                }
                debug_assert_eq!(inputs.len(), sizes.len());

                // sort input sizes
                sizes.sort_unstable();
            }

            // add count point to plot data
            let count = input_values.len();
            debug_assert_eq!(input_values.len(), input_bytes.len());
            add_point(&mut plot.count, MIN_DIFF, ts, count as f32);

            // calculate statistic for input size values/bytes
            for (size_plot, sizes, mean_size) in [
                (&mut plot.size_values, &size_bytes, &mean_size_bytes),
                (&mut plot.size_bytes, &size_values, &mean_size_values),
            ] {
                // collect statistic values
                let max_size = sizes.last().copied().unwrap();
                let median_size = sizes[count / 2];

                // add points to plot data
                for (points, value) in [
                    (&mut size_plot.max_size, max_size as f32),
                    (&mut size_plot.mean_size, mean_size.mean() as f32),
                    (&mut size_plot.median_size, median_size as f32),
                ] {
                    add_point(points, MIN_DIFF, ts, value);
                }
            }
        }

        // add point at last timestamp
        add_last_point(&mut plot.count, ts);

        // add point at last timestamp
        for size_plot in [&mut plot.size_values, &mut plot.size_bytes] {
            // add points to plot data
            for points in [
                &mut size_plot.max_size,
                &mut size_plot.mean_size,
                &mut size_plot.median_size,
            ] {
                add_last_point(points, ts);
            }
        }

        plot
    }
}
