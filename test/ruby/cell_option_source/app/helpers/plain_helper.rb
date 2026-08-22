# The scoping control: `options` outside a cells directory is an ordinary method
# name, not a cell argument, and must NOT be seeded. If this fires, the source has
# escaped the one directory where the name has that meaning.
class PlainHelper
  def initialize(options)
    @options = options
  end

  def render_title(options)
    raw(options[:title])
  end
end
