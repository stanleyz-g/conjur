# frozen_string_literal: true

Before do |scenario|
  @scenario_name = scenario.name
end

Before '@echo' do |_scenario|
  @echo = true
end
