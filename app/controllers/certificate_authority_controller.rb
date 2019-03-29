# frozen_string_literal: true

# Responsible for API calls to interact with a Conjur-configured
# certificate authority (CA) service
class CertificateAuthorityController < RestController
  include ActionController::MimeResponds
  include BodyParser

  before_action :verify_ca_exists
  before_action :verify_role
  before_action :verify_kind
  before_action :verify_request
 
  def sign_certificate
    signed_certificate = ca_sign.(certificate_request: certificate_request)
      
    formatted_certificate = signed_certificate.to_formatted

    render(
      body: formatted_certificate.to_s,
      content_type: formatted_certificate.content_type, 
      status: :created
    )
  end

  protected

  def verify_role
    can_sign = current_user.allowed_to?('sign', webservice.resource)
    raise Forbidden, "Role is not authorized to request signed certificate." unless can_sign
  end

  def verify_kind
    raise ArgumentError, "Invalid certificate kind: '#{certificate_kind}'" unless certificate_authority.present?
  end

  def verify_ca_exists
    exists = webservice.resource.present?
    raise RecordNotFound, "There is no certificate authority with ID: #{service_id}" unless exists
  end

  def verify_request
    ca_verify.(certificate_request: certificate_request)
  end

  private

  def certificate_request
    ::CA::CertificateRequest.new(
      kind: certificate_kind, 
      params: params, 
      role: current_user
    )
  end

  def ca_verify
    certificate_authority.const_get(:Verify).new(webservice: webservice)
  end

  def ca_sign
    certificate_authority.const_get(:Sign).new(webservice: webservice)
  end

  def certificate_authority
    @certificate_authority ||= ::CA.from_type(certificate_kind)
  end

  def certificate_kind
    (params[:kind] || 'x509').downcase.to_sym
  end

  def webservice
    @webservice ||= ::CA::Webservice.load(account, service_id)
  end

  def service_id
    params[:service_id]
  end

  def account
    params[:account]
  end
end
