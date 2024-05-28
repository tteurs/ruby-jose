class JOSE::JWK::KTY_X509 < Struct.new(:key)

  def self.from_key(object)
    object = object.__getobj__ if object.is_a?(JOSE::JWK::PKeyProxy)
    case object
    when OpenSSL::PKey::PKey
      JOSE::JWK::KTY_X509.new(JOSE::JWK::PKeyProxy.new(object))
    when OpenSSL::X509::Certificate
      JOSE::JWK::KTY_X509.new(JOSE::JWK::PKeyProxy.new(object.public_key))
    else
      raise ArgumentError, "'object' is not a recognized key type: #{object.class.name}"
    end
  end

  def to_key
    key.__getobj__
  end

  def to_map(fields)
    {
      'kty' => 'RSA',
      'n' => JOSE.urlsafe_encode64(key.n.to_s(2)),
      'e' => JOSE.urlsafe_encode64(key.e.to_s(2))
    }
  end

  def to_public_map(fields)
    to_map(fields)
  end

  def to_thumbprint_map(fields)
    to_map(fields).slice('e', 'kty', 'n')
  end

  def block_encryptor(fields = nil)
    if fields && fields['use'] == 'enc' && !fields['alg'].nil? && !fields['enc'].nil?
      JOSE::Map[
        'alg' => fields['alg'],
        'enc' => fields['enc']
      ]
    else
      JOSE::Map[
        'alg' => 'RSA-OAEP',
        'enc' => 'A128GCM'
      ]
    end
  end

  def encrypt_public(plain_text, rsa_padding: :rsa_pkcs1_padding, rsa_oaep_md: nil)
    case rsa_padding
    when :rsa_pkcs1_padding
      key.public_encrypt(plain_text, OpenSSL::PKey::RSA::PKCS1_PADDING)
    when :rsa_pkcs1_oaep_padding
      rsa_oaep_md ||= OpenSSL::Digest::SHA1
      key.public_encrypt(plain_text, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
    else
      raise ArgumentError, "unsupported RSA padding: #{rsa_padding.inspect}"
    end
  end

  def verify(message, digest_type, signature, padding: :rsa_pkcs1_padding)
    case padding
    when :rsa_pkcs1_padding
      key.verify(digest_type.new, signature, message)
    when :rsa_pkcs1_pss_padding
      if key.respond_to?(:verify_pss)
        digest_name = digest_type.new.name
        key.verify_pss(digest_name, signature, message, salt_length: :digest, mgf1_hash: digest_name)
      else
        JOSE::JWA::PKCS1.rsassa_pss_verify(digest_type, message, signature, key)
      end
    else
      raise ArgumentError, "unsupported RSA padding: #{padding.inspect}"
    end
  rescue OpenSSL::PKey::PKeyError
    false
  end

  def signer(fields = nil)
    if fields && fields['use'] == 'sig' && !fields['alg'].nil?
      JOSE::Map['alg' => fields['alg']]
    else
      JOSE::Map['alg' => 'RS256']
    end
  end

  def verifier(fields)
    if fields && fields['use'] == 'sig' && !fields['alg'].nil?
      [fields['alg']]
    else
      ['PS256', 'PS384', 'PS512', 'RS256', 'RS384', 'RS512']
    end
  end
end
