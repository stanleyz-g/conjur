# frozen_string_literal: true

class PublicKeysController < ApplicationController
  def show
    account = params[:account]
    kind = params[:kind]
    id = params[:identifier]

    values = Secret.latest_public_keys account, kind, id
    # For test stability.
    values.sort! if %w[test development].member?(Rails.env)
    result = values.map(&:strip).join("\n").strip + "\n"

    render text: result, content_type: 'text/plain'
  end
end
