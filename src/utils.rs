use std::fmt;

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

