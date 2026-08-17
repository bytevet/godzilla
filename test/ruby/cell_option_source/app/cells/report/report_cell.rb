# A cell's options are the arguments its CALLER passed. Decidim CVE-2024-41673
# is a request value handed in that way and interpolated unescaped.
class ReportCell < Decidim::ViewModel
  def unsafe_title
    raw(options[:title])
  end

  # Escaping at the point of use is the fix the CVE applied.
  def safe_title
    raw(html_escape(options[:title]))
  end

  # A cell's own model is not sourced here -- only options.
  def from_model
    raw(model.name)
  end
end
