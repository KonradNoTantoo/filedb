use std::error::Error;

use data_encoding::HEXLOWER;
use ring::digest::SHA256_OUTPUT_LEN;

const FILE_ID_ENCODED_LENGTH: usize = FILE_ID_DECODED_LENGTH * 2;
const FILE_ID_DECODED_LENGTH: usize = SHA256_OUTPUT_LEN;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Id
{
	value: [u8; FILE_ID_DECODED_LENGTH],
}

impl std::fmt::Display for Id
{
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result
	{
		write!(f, "{}", HEXLOWER.encode(&self.value))
	}
}

impl Id
{
	pub fn new(text: impl AsRef<str>) -> Result<Id, Box<dyn Error>>
	{
		let decoded_id = HEXLOWER.decode(text.as_ref().as_bytes())?;

		if decoded_id.len() == FILE_ID_DECODED_LENGTH
		{
			let mut result = Id {
				value: [0; FILE_ID_DECODED_LENGTH],
			};

			for (i, b) in decoded_id.iter().enumerate()
			{
				result.value[i] = *b;
			}

			Ok(result)
		}
		else
		{
			Err("Bad Id value".into())
		}
	}

	pub(crate) fn from_digest(digest: &[u8]) -> Id
	{
		Id {
			value: digest.try_into().expect("Bad digest size"),
		}
	}
}

#[derive(Debug, Copy, Clone, Ord, Eq)]
pub struct IdHint
{
	length: usize,
	value: [u8; FILE_ID_DECODED_LENGTH],
}

impl IdHint
{
	const MIN_ENCODED_LENGTH: usize = 4;
	const MAX_ENCODED_LENGTH: usize = FILE_ID_ENCODED_LENGTH;

	pub fn new(text: impl AsRef<str>) -> Result<IdHint, Box<dyn Error>>
	{
		let bytes = text.as_ref().as_bytes();
		let encoded_length = bytes.len();

		if encoded_length >= Self::MIN_ENCODED_LENGTH
			&& encoded_length <= Self::MAX_ENCODED_LENGTH
			&& encoded_length % 2 == 0
		{
			let decoded_id = HEXLOWER.decode(bytes)?;

			if decoded_id.len() <= FILE_ID_DECODED_LENGTH
			{
				let mut result = IdHint {
					length: encoded_length / 2,
					value: [0; FILE_ID_DECODED_LENGTH],
				};

				for (i, b) in decoded_id.iter().enumerate()
				{
					result.value[i] = *b;
				}

				Ok(result)
			}
			else
			{
				Err("Bad IdHint value".into())
			}
		}
		else
		{
			Err("Bad IdHint length".into())
		}
	}

	fn view(&self) -> &[u8] { &self.value[0..self.length] }
}

impl std::fmt::Display for IdHint
{
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result
	{
		write!(f, "{}", HEXLOWER.encode(self.view()))
	}
}

impl PartialEq for IdHint
{
	fn eq(&self, other: &Self) -> bool { self.view() == other.view() }
}

impl PartialOrd for IdHint
{
	fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering>
	{
		Some(self.view().cmp(other.view()))
	}
}

impl PartialEq<Id> for IdHint
{
	fn eq(&self, other: &Id) -> bool { self.view() == &other.value[0..self.length] }
}

impl PartialOrd<Id> for IdHint
{
	fn partial_cmp(&self, other: &Id) -> Option<std::cmp::Ordering>
	{
		Some(self.view().cmp(&other.value[0..self.length]))
	}
}

#[cfg(test)]
mod tests
{
	use super::*;

	#[test]
	#[should_panic(expected = "Bad digest size")]
	fn id_from_bad_digest()
	{
		let x: [u8; 3] = [12, 13, 14];
		Id::from_digest(&x);
	}

	#[test]
	fn id_format() -> Result<(), Box<dyn Error>>
	{
		let text = "bef57ec7f53a6d40beb640a780a639c83bc29ac8a9816f1fc6c5c6dcd93c4721";
		let id = Id::new(text)?;
		assert_eq!(text, id.to_string());
		Ok(())
	}

	#[test]
	fn id_from_short_string() -> Result<(), &'static str>
	{
		match Id::new("be")
		{
			Ok(_) => return Err("Construction from short string should fail"),
			_ => Ok(()),
		}
	}

	#[test]
	fn id_from_long_string() -> Result<(), &'static str>
	{
		match Id::new("bef57ec7f53a6d40beb640a780a639c83bc29ac8a9816f1fc6c5c6dcd93c47210")
		{
			Ok(_) => return Err("Construction from long string should fail"),
			_ => Ok(()),
		}
	}

	#[test]
	fn id_from_non_hex_string() -> Result<(), &'static str>
	{
		match Id::new("abcdefgh")
		{
			Ok(_) => return Err("Construction from non hex string should fail"),
			_ => Ok(()),
		}
	}

	#[test]
	fn hint_format() -> Result<(), Box<dyn Error>>
	{
		let text = "bef57e";
		let hint = IdHint::new(text)?;
		assert_eq!(text, hint.to_string());
		Ok(())
	}

	#[test]
	fn hint_from_short_string() -> Result<(), &'static str>
	{
		match IdHint::new("be")
		{
			Ok(_) => return Err("Construction from short string should fail"),
			_ => Ok(()),
		}
	}

	#[test]
	fn hint_from_long_string() -> Result<(), &'static str>
	{
		match IdHint::new("bef57ec7f53a6d40beb640a780a639c83bc29ac8a9816f1fc6c5c6dcd93c47210")
		{
			Ok(_) => return Err("Construction from long string should fail"),
			_ => Ok(()),
		}
	}

	#[test]
	fn hint_from_non_hex_string() -> Result<(), &'static str>
	{
		match IdHint::new("abcdefgh")
		{
			Ok(_) => return Err("Construction from non hex string should fail"),
			_ => Ok(()),
		}
	}

	#[test]
	fn hint_from_odd_length_string() -> Result<(), &'static str>
	{
		match IdHint::new("bef57ec")
		{
			Ok(_) => return Err("Construction from odd length string should fail"),
			_ => Ok(()),
		}
	}

	#[test]
	fn hint_match() -> Result<(), Box<dyn Error>>
	{
		let id = Id::new("bef57ec7f53a6d40beb640a780a639c83bc29ac8a9816f1fc6c5c6dcd93c4721")?;
		let hint = IdHint::new("bef57e")?;
		assert_eq!(hint, id);
		assert_eq!(false, (hint < id));
		assert_eq!(false, (hint > id));
		assert!(hint <= id);
		assert!(hint >= id);
		Ok(())
	}

	#[test]
	fn hint_order() -> Result<(), Box<dyn Error>>
	{
		let higher = Id::new("bef57fc7f53a6d40beb640a780a639c83bc29ac8a9816f1fc6c5c6dcd93c4721")?;
		let lower = Id::new("bef57dc7f53a6d40beb640a780a639c83bc29ac8a9816f1fc6c5c6dcd93c4721")?;
		let hint = IdHint::new("bef57e")?;
		assert_ne!(hint, higher);
		assert_ne!(hint, lower);
		assert!(hint < higher);
		assert!(hint > lower);
		assert!(hint <= higher);
		assert!(hint >= lower);
		assert_eq!(false, (hint <= lower));
		assert_eq!(false, (hint >= higher));
		Ok(())
	}
}
