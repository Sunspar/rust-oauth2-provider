use std::fmt::{Display, Formatter, Result};
use std::ops::{Deref, DerefMut};
use hyper;
use hyper::header::{Header, HeaderFormat};
use hyper::header::parsing;

#[derive(Clone, Debug, PartialEq)]
pub struct WWWAuthenticate(pub String);

impl Header for WWWAuthenticate {
	fn header_name() -> &'static str {
		"WWW-Authenticate"
	}

	fn parse_header(raw: &[Vec<u8>]) -> hyper::Result<Self> {
		parsing::from_one_raw_str(raw).map(WWWAuthenticate)
	}
}

impl HeaderFormat for WWWAuthenticate {
	fn fmt_header(&self, f: &mut Formatter) -> Result {
		Display::fmt(&self, f)
	}
}

impl Display for WWWAuthenticate {
	fn fmt(&self, f: &mut Formatter) -> Result {
		Display::fmt(&**self, f)
	}
}

impl Deref for WWWAuthenticate {
	type Target = String;
	
		fn deref<'a>(&'a self) -> &'a String {
				&self.0
		}
}

impl DerefMut for WWWAuthenticate {
		fn deref_mut<'a>(&'a mut self) -> &'a mut String {
				&mut self.0
		}
}