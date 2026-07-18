module Shop
  class Order < ApplicationRecord
    def self.by_role(role = nil)
      base = order("created_at DESC")
      base.where(Arel.sql("roles LIKE '%- #{role}%'"))
    end
  end
end
