# frozen_string_literal: true

require 'command_class'

module Authentication
  Authenticate = CommandClass.new(
    dependencies: {
      enabled_authenticators: ENV['CONJUR_AUTHENTICATORS'],
      token_factory:          TokenFactory.new,
      validate_security:      ::Authentication::ValidateSecurity.new,
      validate_origin:        ::Authentication::ValidateOrigin.new,
      audit_event:            ::Authentication::AuditEvent.new
    },
    inputs:       %i(authenticator_input authenticators)
  ) do

    def call
      validate_authenticator_exists
      validate_security
      validate_credentials
      validate_origin
      audit_success
      new_token
    rescue => e
      audit_failure(e)
      raise e
    end

    private

    def authenticator
      @authenticator = @authenticators[@authenticator_input.authenticator_name]
    end

    def validate_authenticator_exists
      raise AuthenticatorNotFound, @authenticator_input.authenticator_name unless authenticator
    end

    def validate_credentials
      raise ::Authentication::InvalidCredentials unless authenticator.valid?(@authenticator_input)
    end

    def validate_security
      @validate_security.(input: @authenticator_input, enabled_authenticators: @enabled_authenticators)
    end

    def validate_origin
      @validate_origin.(input: @authenticator_input)
    end

    def audit_success
      @audit_event.(input: @authenticator_input, success: true, message: nil)
    end

    def audit_failure(err)
      @audit_event.(input: @authenticator_input, success: false, message: err.message)
    end

    def new_token
      @token_factory.signed_token(
        account:  @authenticator_input.account,
        username: @authenticator_input.username
      )
    end

  end
end
