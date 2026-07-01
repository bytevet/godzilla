# Deliberately malformed Python (unbalanced parens, invalid syntax) used only
# to prove that converters/python's directory walk skips an unparseable file
# rather than aborting the whole batch conversion. See
# converters/python/converter_test.go's
# TestConvertFile_DirectorySkipsUnparseableFile.
def totally_broken(:
    return 1
