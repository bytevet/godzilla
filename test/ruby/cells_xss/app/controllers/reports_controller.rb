class ReportsController < ApplicationController
  def show
    @label = params[:label]
  end
end
