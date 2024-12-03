# frozen_string_literal: true

require "test_helper"

describe AtprotoAuth do
  it "has a VERSION constant defined" do
    _(AtprotoAuth.const_defined?(:VERSION)).must_equal true
  end
end
