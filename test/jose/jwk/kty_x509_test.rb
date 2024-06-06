require 'test_helper'

class JOSE::JWK::KTY_X509Test < Minitest::Test
  def test_from_key_and_to_key
    x509_pem_data = <<~PEM
      -----BEGIN CERTIFICATE-----
      MIIDxzCCAq+gAwIBAgIUXm1i9UarQZwGQ3MaNarRSUZbwVAwDQYJKoZIhvcNAQEL
      BQAwczELMAkGA1UEBhMCQlIxCzAJBgNVBAgMAlJTMQwwCgYDVQQHDANQT0ExDTAL
      BgNVBAoMBHRlc3QxDTALBgNVBAsMBHRlc3QxDTALBgNVBAMMBHRlc3QxHDAaBgkq
      hkiG9w0BCQEWDXRlc3RAdGVzdC5jb20wHhcNMjQwNTMxMjIyNDI3WhcNMjUwNTMx
      MjIyNDI3WjBzMQswCQYDVQQGEwJCUjELMAkGA1UECAwCUlMxDDAKBgNVBAcMA1BP
      QTENMAsGA1UECgwEdGVzdDENMAsGA1UECwwEdGVzdDENMAsGA1UEAwwEdGVzdDEc
      MBoGCSqGSIb3DQEJARYNdGVzdEB0ZXN0LmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD
      ggEPADCCAQoCggEBALsMvAFvOJtRO8rwF6QwJ/UfhhJ+JHtLdycfLrR/wCW0acHr
      MqMeoTKJcRsyQTTQCjO7r1QScv+xaEQohBE6Vq8O8rD38xZn4lesCq3mSf2mUi3k
      etZv1pFKU/lN7SceUG65/vVAMoj9HEFZ43WfpDkYFvFDw2dR+vkcSp5SWQW8JxrA
      nuGSP+1E57cAsoPHcWPgYBe5y8ndOQREikpOkKUbCcDN5mrg0Y0kUHboXm18jKeW
      dCejOj9z0DS1mFqpE8sG4Khv0aL7kAzwQb8vNVoMog3R+qqgv61e3U6BAKyU3k0w
      Xet9tyAgofHscO4QEo6ThELTFPgHnvD9DaclKZ8CAwEAAaNTMFEwHQYDVR0OBBYE
      FE8ld9J8T8FPZtudE6emFcwOL1MiMB8GA1UdIwQYMBaAFE8ld9J8T8FPZtudE6em
      FcwOL1MiMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAIhtTzS3
      yoUnKYhIqUIRs5Dp+iwXjAjx9J5kR1cjfBuNGOKvJIqPTkcL7wu9fEG0eR8wsuWD
      kYbwNk07fc03Gx/44COH0jIwn8XsDffj3ITA0gU8p9Ee6I/f2jBUQ2SvyC+lr6lc
      YJKY3aNi+osMhXOVOguOl6DsxvvmGCI26BMpZueu1WXBEcMNCH/lgFwzNC6HHVKu
      kxvYEOrhcgodA5kiOFltgZdwqb1Q7EBFFn1rKPQFvc2XVlJrubyiOXalcwWJ/REa
      o0bTj132BSdfkPF2l1rZBQM2pzPg0U7DiTvEa6yMaj4IN8Gv140ogF0niyDegElt
      ls8R0jfIBZj2N0I=
      -----END CERTIFICATE-----
    PEM

    x509_cert = OpenSSL::X509::Certificate.new(x509_pem_data)
    x509_key = x509_cert.public_key
    x509_jwk = JOSE::JWK::KTY_X509.new(JOSE::JWK::PKeyProxy.new(x509_key))
    assert_equal x509_key.to_pem.strip, x509_jwk.key.__getobj__.to_pem.strip
  end

  def test_from_binary_and_to_binary
    x509_pem_data = <<~PEM
      -----BEGIN CERTIFICATE-----
      MIIDxzCCAq+gAwIBAgIUXm1i9UarQZwGQ3MaNarRSUZbwVAwDQYJKoZIhvcNAQEL
      BQAwczELMAkGA1UEBhMCQlIxCzAJBgNVBAgMAlJTMQwwCgYDVQQHDANQT0ExDTAL
      BgNVBAoMBHRlc3QxDTALBgNVBAsMBHRlc3QxDTALBgNVBAMMBHRlc3QxHDAaBgkq
      hkiG9w0BCQEWDXRlc3RAdGVzdC5jb20wHhcNMjQwNTMxMjIyNDI3WhcNMjUwNTMx
      MjIyNDI3WjBzMQswCQYDVQQGEwJCUjELMAkGA1UECAwCUlMxDDAKBgNVBAcMA1BP
      QTENMAsGA1UECgwEdGVzdDENMAsGA1UECwwEdGVzdDENMAsGA1UEAwwEdGVzdDEc
      MBoGCSqGSIb3DQEJARYNdGVzdEB0ZXN0LmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD
      ggEPADCCAQoCggEBALsMvAFvOJtRO8rwF6QwJ/UfhhJ+JHtLdycfLrR/wCW0acHr
      MqMeoTKJcRsyQTTQCjO7r1QScv+xaEQohBE6Vq8O8rD38xZn4lesCq3mSf2mUi3k
      etZv1pFKU/lN7SceUG65/vVAMoj9HEFZ43WfpDkYFvFDw2dR+vkcSp5SWQW8JxrA
      nuGSP+1E57cAsoPHcWPgYBe5y8ndOQREikpOkKUbCcDN5mrg0Y0kUHboXm18jKeW
      dCejOj9z0DS1mFqpE8sG4Khv0aL7kAzwQb8vNVoMog3R+qqgv61e3U6BAKyU3k0w
      Xet9tyAgofHscO4QEo6ThELTFPgHnvD9DaclKZ8CAwEAAaNTMFEwHQYDVR0OBBYE
      FE8ld9J8T8FPZtudE6emFcwOL1MiMB8GA1UdIwQYMBaAFE8ld9J8T8FPZtudE6em
      FcwOL1MiMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAIhtTzS3
      yoUnKYhIqUIRs5Dp+iwXjAjx9J5kR1cjfBuNGOKvJIqPTkcL7wu9fEG0eR8wsuWD
      kYbwNk07fc03Gx/44COH0jIwn8XsDffj3ITA0gU8p9Ee6I/f2jBUQ2SvyC+lr6lc
      YJKY3aNi+osMhXOVOguOl6DsxvvmGCI26BMpZueu1WXBEcMNCH/lgFwzNC6HHVKu
      kxvYEOrhcgodA5kiOFltgZdwqb1Q7EBFFn1rKPQFvc2XVlJrubyiOXalcwWJ/REa
      o0bTj132BSdfkPF2l1rZBQM2pzPg0U7DiTvEa6yMaj4IN8Gv140ogF0niyDegElt
      ls8R0jfIBZj2N0I=
      -----END CERTIFICATE-----
    PEM

    x509_cert = OpenSSL::X509::Certificate.new(x509_pem_data)
    x509_key = x509_cert.public_key
    x509_jwk = JOSE::JWK::KTY_X509.new(JOSE::JWK::PKeyProxy.new(x509_key))

    from_binary_jwk = JOSE::JWK::KTY_X509.new(JOSE::JWK::PKeyProxy.new(OpenSSL::X509::Certificate.new(x509_pem_data).public_key))

    assert_equal x509_jwk.key.__getobj__.to_pem.strip, from_binary_jwk.key.__getobj__.to_pem.strip
  end
end
