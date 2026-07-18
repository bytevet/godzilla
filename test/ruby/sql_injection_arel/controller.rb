# SQL injection (CWE-89), CVE-2024-43415 shape: a request parameter crosses a
# controller helper and a model class method (in another file) and reaches
# Arel.sql -- ActiveRecord's raw-SQL escape hatch, which performs NO escaping.
module Shop
  module Admin
    class ReportsController < ApplicationController
      def index
        @rows ||= Order.for_store(current_store).by_role(params[:role_type])
      end
    end
  end
end
