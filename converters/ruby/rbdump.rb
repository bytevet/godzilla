# rbdump.rb is Godzilla's embedded Ruby frontend helper, run as
# `ruby rbdump.rb [--batch] <file.rb> [more...]`. It parses each file with the
# standard library's Ripper and prints its S-expression AST as JSON to stdout,
# which converters/ruby/lower.go lowers to gIR. Ripper ships with every MRI
# Ruby (no gems), so the frontend needs only `ruby` on PATH. Output modes —
# batch (one JSON doc per line, argv order, always exit 0, per-file failures
# as {"error": ...} lines) vs single-file (historical bare document) — are
# documented at the dispatch at the bottom of this file.
#
# Ripper.sexp returns nested arrays whose head is a symbol tag (e.g. :program,
# :def, :call, :@ident); leaf tokens carry a [line, col] position. We serialize
# symbols as plain strings so the Go side sees a regular JSON tree.
require 'ripper'
require 'json'

def jsonable(node)
  case node
  when Array then node.map { |e| jsonable(e) }
  when Symbol then node.to_s
  else node
  end
end

def dump_one(path)
  src = File.read(path)
  sexp = Ripper.sexp(src)
  sexp.nil? ? { "error" => "syntax error" } : jsonable(sexp)
rescue => e
  { "error" => e.message }
end

# Batch mode (--batch <files...>): one JSON document per line, in argument
# order, always exit 0 — a per-file failure is that file's own {"error": ...}
# line, so interpreter startup is paid once per batch instead of once per file.
if ARGV[0] == "--batch"
  ARGV[1..].each { |path| puts JSON.generate(dump_one(path)) }
else
  # Single-file mode: historical behavior (bare JSON document, no newline).
  print JSON.generate(dump_one(ARGV[0]))
end
