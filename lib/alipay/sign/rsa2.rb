require 'openssl'
require 'base64'

module Alipay
  module Sign
    class RSA2
      def self.sign(key, string)
        rsa = OpenSSL::PKey::RSA.new(key)
        Base64.strict_encode64(rsa.sign('sha256', string))
      end

      def self.verify?(key, string, sign)
        rsa = OpenSSL::PKey::RSA.new(key)
        match = rsa.verify('sha256', Base64.strict_decode64(sign), string)
        OpenSSL.errors.clear
        match
      end
    end
  end
end
