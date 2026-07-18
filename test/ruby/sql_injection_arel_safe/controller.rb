# Safe control for sql_injection_arel: the SAME request param reaches the SAME
# model class method, but the model uses a parameterized query (bound `?`
# placeholder) instead of Arel.sql, so no SQL injection is possible.
module Shop
  module Admin
    class ReportsController < ApplicationController
      def index
        @rows ||= Order.for_store(current_store).by_role(params[:role_type])
      end
    end
  end
end
