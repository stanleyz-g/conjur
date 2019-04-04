# frozen_string_literal: true

# K8sObjectLookup is used to lookup Kubernetes object metadata using 
# Kubernetes API. This is essentially a facade over the API
#
module Authentication
  module AuthnK8s
    #TODO: rename to K8sApiFacade
    #

    VARIABLE_BEARER_TOKEN = 'kubernetes/service-account-token'
    VARIABLE_CA_CERT = 'kubernetes/ca-cert'
    VARIABLE_API_URL = 'kubernetes/api-url'
    SERVICEACCOUNT_DIR = '/var/run/secrets/kubernetes.io/serviceaccount'
    SERVICEACCOUNT_CA_PATH = File.join(SERVICEACCOUNT_DIR, 'ca.crt').freeze
    SERVICEACCOUNT_TOKEN_PATH = File.join(SERVICEACCOUNT_DIR, 'token').freeze

    class K8sObjectLookup

      class K8sForbiddenError < RuntimeError; end

      def initialize webservice
        @webservice = webservice
        @cert_store = OpenSSL::X509::Store.new
        @cert_store.set_default_paths
        @cert_store.add_cert(ca_cert)
      end

      def bearer_token
        @bearer_token ||= @webservice.variable(VARIABLE_BEARER_TOKEN).secret.value
      end

      def ca_cert
        cert = begin
          File.read(SERVICEACCOUNT_CA_PATH)
        rescue
          @webservice.variable(VARIABLE_CA_CERT).secret.value
        end

        OpenSSL::X509::Certificate.new(cert)
      end

      def options
        @options ||= {
          auth_options: auth_options,
          ssl_options: {
            cert_store: @cert_store,
            verify_ssl: OpenSSL::SSL::VERIFY_PEER
          }
        }
      end

      def auth_options
        if File.exist?(SERVICEACCOUNT_TOKEN_PATH)
          { bearer_token_file: SERVICEACCOUNT_TOKEN_PATH }
        else
          { bearer_token: bearer_token }
        end
      end

      def api_url
        if ENV['KUBERNETES_SERVICE_HOST'].present? && ENV['KUBERNETES_SERVICE_PORT'].present?
          "https://#{ENV['KUBERNETES_SERVICE_HOST']}:#{ENV['KUBERNETES_SERVICE_PORT']}"
        else
          @webservice.variable(VARIABLE_API_URL).secret.value
        end
      end

      # Gets the client object to the /api v1 endpoint.
      def kubectl_client
        KubeClientFactory.client(host_url: api_url, options: options)
      end

      # Locates the Pod with a given IP address.
      #
      # @return nil if no such Pod exists.
      def pod_by_ip(request_ip, namespace)
        # TODO: use "status.podIP" field_selector for versions of k8s that
        # support it the current implementation is a performance optimization
        # for very early K8s versions usage of "status.podIP" field_selector on
        # versions of k8s that do not support it results in no pods returned
        # from #get_pods
        k8s_client_for_method("get_pods")
          .get_pods(field_selector: "", namespace: namespace)
          .select do |pod|
          # Just in case the filter is mis-implemented on the server side.
          pod.status.podIP == request_ip
        end.first
      end

      # Locates the Pod with a given podname in a namespace.
      #
      # @return nil if no such Pod exists.
      def pod_by_name(podname, namespace)
        k8s_client_for_method("get_pod").get_pod(podname, namespace)
      end

      # Locates pods matching label selector in a namespace.
      #
      def pods_by_label(label_selector, namespace)
        k8s_client_for_method("get_pods").get_pods(label_selector: label_selector, namespace: namespace)
      end

      # Look up an object according to the controller name. In Kubernetes, the 
      # "controller" means something like ReplicaSet, Job, Deployment, etc.
      #
      # Here, controller_name should be the underscore-ized controller, e.g.
      # "replica_set".
      #
      # @return nil if no such object exists.
      def find_object_by_name controller_name, name, namespace
        begin
          handle_object_not_found do
            invoke_k8s_method "get_#{controller_name}", name, namespace
          end
        rescue KubeException => e
          # This error message can be a bit confusing when multiple authorizers are
          # present, as is the case with GKE (IAM and k8s RBAC).
          # See: https://github.com/kubernetes/kubernetes/issues/52279
          if e.error_code == 403
            raise K8sForbiddenError, e.message
          else
            raise e
          end
        end
      end

      protected

      def invoke_k8s_method method_name, *arguments
        k8s_client_for_method(method_name).send(method_name, *arguments)
      end

      # Methods move around between API versions across releases, so search the
      # client API objects to find the method we are looking for.
      def k8s_client_for_method method_name
        k8s_clients.find do |client|
          begin
            client.respond_to?(method_name)
          rescue KubeException
            false
          end
        end
      end

      # If more API versions appear, add them here.
      # List them in the order that you want them to be searched for methods.
      def k8s_clients
        @clients ||= [
          kubectl_client,
          KubeClientFactory.client(api: 'apis/apps', version: 'v1beta2', host_url: api_url, options: options),
          KubeClientFactory.client(api: 'apis/apps', version: 'v1beta1', host_url: api_url, options: options),
          KubeClientFactory.client(api: 'apis/extensions', version: 'v1beta1', host_url: api_url, options: options),
          # OpenShift 3.3 DeploymentConfig
          KubeClientFactory.client(api: 'oapi', version: 'v1', host_url: api_url, options: options),
          # OpenShift 3.7 DeploymentConfig
          KubeClientFactory.client(api: 'apis/apps.openshift.io', version: 'v1', host_url: api_url, options: options)
        ]
      end

      # returns nil if an HTTP status 404 exception occurs.
      # All other exceptions are re-raised.
      def handle_object_not_found &block
        begin
          yield
        rescue KubeException
          raise unless $!.error_code == 404
        end
      end
    end
  end
end
