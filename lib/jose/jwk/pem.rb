module JOSE::JWK::PEM
  extend self

  def from_binary(object, password = nil)
    begin
      pkey = OpenSSL::PKey.read(object, password)
      return JOSE::JWK::KTY.from_key(pkey)
    rescue OpenSSL::PKey::PKeyError
      begin
        cert = OpenSSL::X509::Certificate.new(object)
        return JOSE::JWK::KTY_X509.new(JOSE::JWK::PKeyProxy.new(cert.public_key))
      rescue OpenSSL::X509::CertificateError => e
        raise RuntimeError, "Unsupported key type or incorrect password: #{e.message}"
      end
    end
  end

  def to_binary(key, password = nil)
    if key.is_a?(OpenSSL::PKey::PKey)
      if password
        cipher = OpenSSL::Cipher.new('DES-EDE3-CBC')
        return key.to_pem(cipher, password)
      else
        return key.to_pem
      end
    elsif key.is_a?(OpenSSL::X509::Certificate)
      return key.to_pem
    else
      raise ArgumentError, "Unsupported key type: #{key.class}"
    end
  end
end
