# rbdump.rb is Godzilla's embedded Ruby frontend helper, run as
# `ruby rbdump.rb <file.rb>`. It parses the file with the standard library's
# Ripper and prints its S-expression AST as JSON to stdout, which
# converters/ruby/lower.go lowers to gIR. Ripper ships with every MRI Ruby
# (no gems), so the frontend needs only `ruby` on PATH.
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

path = ARGV[0]
begin
  src = File.read(path)
  sexp = Ripper.sexp(src)
  if sexp.nil?
    print JSON.generate({ "error" => "syntax error" })
  else
    print JSON.generate(jsonable(sexp))
  end
rescue => e
  print JSON.generate({ "error" => e.message })
end
