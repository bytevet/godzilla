# Code injection: no shell involved, the attacker's string IS the program.
class AdminController < ApplicationController
  def run
    eval(params[:code])
  end

  # A tainted method NAME chooses which method runs — the shape that made
  # dispatch-by-hash gems remotely exploitable.
  def dispatch
    @report.send(params[:m])
  end

  # A tainted TEMPLATE is Ruby source; a fixed template rendering a tainted
  # value is not, and is XSS at most.
  def render_template
    ERB.new(params[:tpl]).result
  end

  # Passing tainted DATA to a fixed method is ordinary, not injection.
  def data_to_fixed_method
    @report.send(:title=, params[:title])
  end

  def constant_template
    ERB.new("hello <%= 1 %>").result
  end
end
