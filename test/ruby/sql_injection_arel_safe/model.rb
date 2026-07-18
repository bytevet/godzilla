module Shop
  class Order < ApplicationRecord
    def self.by_role(role = nil)
      where("roles LIKE ?", role)
    end
  end
end
