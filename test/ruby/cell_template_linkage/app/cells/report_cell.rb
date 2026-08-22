# A cell's class and its template are separate files, so the flow that matters
# crosses a module boundary: the option is read here, the unescaped interpolation
# is in show.erb. Decidim CVE-2024-41673 is that shape.
class ReportCell < Decidim::ViewModel
  def title
    options[:title]
  end

  # The positional translation form carries what it interpolates.
  def translated
    t(options[:title])
  end

  def escaped
    html_escape(options[:title])
  end
end
