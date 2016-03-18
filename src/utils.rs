use std;
use std::fmt;
use time;

// TODO(canndrew): Deprecate this function as soon as #[feature(time2)] is stable.
pub fn time_duration_to_std_duration(dur: time::Duration) -> std::time::Duration {
    let millis = dur.num_milliseconds();
    std::time::Duration::from_millis(millis as u64)
}

pub struct DisplaySlice<'a, T: 'a>(pub &'static str, pub &'a [T]);

impl<'a, T> fmt::Display for DisplaySlice<'a, T>
        where T: fmt::Display
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let DisplaySlice(description, slice) = *self;
        let len = slice.len();
        try!(write!(f, "{} {}(s):", len, description));
        for (i, t) in slice.iter().enumerate() {
            try!(write!(f, " ({} of {}) {}", i + 1, len, t));
        }
        Ok(())
    }
}

