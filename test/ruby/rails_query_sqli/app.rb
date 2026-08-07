# ActiveRecord's query surface: the ordinary Rails SQL-injection vectors, and
# the two idioms that are safe and must stay quiet.
class ReportsController < ApplicationController
  def interpolated
    User.where("name = '#{params[:q]}'")
  end

  # `order` takes raw SQL, so a tainted sort column is injectable.
  def sortable
    User.order(params[:sort])
  end

  # A bind placeholder puts the value at a later argument, where it is escaped
  # by the adapter.
  def placeholder
    User.where("name = ?", params[:q])
  end

  # The hash form is parameterized by construction.
  def hash_condition
    User.where(name: params[:q])
  end
end
