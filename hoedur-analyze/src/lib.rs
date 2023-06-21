pub mod coverage;
pub mod executions;
pub mod input;
pub mod plot;

pub type Point = (f32, f32);

fn add_point(points: &mut Vec<Point>, min_diff: f32, timestamp: f32, value: f32) {
    debug_assert!(min_diff.is_finite());
    debug_assert!(timestamp.is_finite());

    // value must be real
    let value = if value.is_finite() { value } else { 0. };

    if let Some((last_ts, last_value)) = points.last_mut() {
        if value == *last_value {
            // same value => keep
            return;
        } else if timestamp == *last_ts {
            // update exisiting value
            *last_value = value;
            return;
        } else if (timestamp - *last_ts) < min_diff {
            // update only every x seconds
            return;
        } else {
            // insert new
        }
    }

    // insert new value
    points.push((timestamp, value));
}

fn add_last_point(points: &mut Vec<Point>, timestamp: f32) {
    let value = points.last().map(|(_, y)| y).copied().unwrap_or(0.);
    points.push((timestamp, value));
}
