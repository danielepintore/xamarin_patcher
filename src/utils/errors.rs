#[derive(Debug)]
pub enum GenericError {
    PathNotValid,
    NoDynSymTable,
    NoDynStrTable,
    NoSysVHashTable,
    NotMonoMKBundle,
    OutputPathNotEmpty,
    UnableToGetDLLNameFromPath,
}

impl core::fmt::Display for GenericError {
	fn fmt(
		&self,
		fmt: &mut core::fmt::Formatter,
	) -> core::result::Result<(), core::fmt::Error> {
		write!(fmt, "{self:?}")
	}
}

impl std::error::Error for GenericError {}
