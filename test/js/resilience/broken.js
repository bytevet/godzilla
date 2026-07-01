// Deliberately malformed JavaScript (unbalanced parens/braces) used only to
// prove that converters/javascript's directory walk skips an unparseable
// file rather than aborting the whole batch conversion. See
// converters/javascript/converter_test.go's
// TestConvertDirectorySkipsUnparseableFile.
function totallyBroken( {
  return 1;
