require 'test_helper'

class JOSE::JWK::KTY_X509Test < Minitest::Test
  def test_from_key_and_to_key
    x509_pem_data = <<~PEM
      -----BEGIN CERTIFICATE-----
      MIIDXTCCAkWgAwIBAgIJALnK/Zw01LzPMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
      BAYTAlVTMRAwDgYDVQQIDAdNYXJ5bGFuZDEPMA0GA1UEBwwGQmV0aGVzMRQwEgYD
      VQQKDAtNeSBDb21wYW55IEx0ZDAeFw0xOTA2MjQxOTM4MjZaFw0yOTA2MjExOTM4
      MjZaMEUxCzAJBgNVBAYTAlVTMRAwDgYDVQQIDAdNYXJ5bGFuZDEPMA0GA1UEBwwG
      QmV0aGVzMRQwEgYDVQQKDAtNeSBDb21wYW55IEx0ZDCCASIwDQYJKoZIhvcNAQEB
      BQADggEPADCCAQoCggEBALnlHX/OAD3Z6iShpQmYebJfi5+AMYOhePPoWbE5T3c5
      2e+BB1P1ZG3H0xRzKHr/O3zme6iFzbbm2peSGieAY3dZYZgEU1Irwaf74WZ1zUhu
      l3bjlC2azqDDC/n9u5NZ3mZ2/XbYDwU2jqqmeZDPdCMehwG36H5HkBlRNHlx6bK8
      QWkQ6E9s4d5QgtF4cKJjyk4r1u9f2FE/oA2FptDZ0F1v3UOZnnAnXfrdqgMAx4w2
      vZkmNp7BG8e5Tsa4GF4YFbAQ+9mcXsBrHHtVpOYs80bDt4X8JzD5ZhBe0B9M00gR
      wIZPHQlB9s8b5uCeAQklEgRJKt5DZgGg6FkjH8ZG7sTbEECAwEAAaNTMFEwHQYD
      VR0OBBYEFMvdMOpE+E13jc5B5nH7W0rAVwQtMB8GA1UdIwQYMBaAFMvdMOpE+E13
      jc5B5nH7W0rAVwQtMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB
      AAh34gP8UeRVUDFc2J9/7G4SHXjX7YBboEl7PZhsuwuSC8DfAzGGDFxuIkKpL6ik
      R7o/tHHtdhHi9Uy6WcHKug9Y0by7ADzZbP07m3v4oSGWAKS+CXUVTHt7yXJblsVu
      6CmlPlmx9CG9hQfpO0JYa+v1gL5AMmbsbvby4GnVCg5McRZr1h6U4J83QLUVkSD3
      cQXQGdRHRwPNrK4aFcwhGcYrV0fUw0Rgubz1bkCEdiq3e5XH7mgdd7YUZpCbh6p4
      Rz2eTP4PBhMiZoERazCKK/evGmtM4n5BcdJkpGiMkPf2ke1Dr8cx/7OVGJROtG0e
      W50qVg4iVjtjRuC2t8hXTDVb9BI=
      -----END CERTIFICATE-----
    PEM

    x509_cert = OpenSSL::X509::Certificate.new(x509_pem_data)
    x509_key = x509_cert.public_key
    x509_jwk = JOSE::JWK::KTY_X509.new(JOSE::JWK::PKeyProxy.new(x509_key))
    assert_equal x509_key.to_pem.strip, x509_jwk.to_key.to_pem.strip
  end

  def test_from_binary_and_to_binary
    x509_pem_data = <<~PEM
      -----BEGIN CERTIFICATE-----
      MIIDXTCCAkWgAwIBAgIJALnK/Zw01LzPMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
      BAYTAlVTMRAwDgYDVQQIDAdNYXJ5bGFuZDEPMA0GA1UEBwwGQmV0aGVzMRQwEgYD
      VQQKDAtNeSBDb21wYW55IEx0ZDAeFw0xOTA2MjQxOTM4MjZaFw0yOTA2MjExOTM4
      MjZaMEUxCzAJBgNVBAYTAlVTMRAwDgYDVQQIDAdNYXJ5bGFuZDEPMA0GA1UEBwwG
      QmV0aGVzMRQwEgYDVQQKDAtNeSBDb21wYW55IEx0ZDCCASIwDQYJKoZIhvcNAQEB
      BQADggEPADCCAQoCggEBALnlHX/OAD3Z6iShpQmYebJfi5+AMYOhePPoWbE5T3c5
      2e+BB1P1ZG3H0xRzKHr/O3zme6iFzbbm2peSGieAY3dZYZgEU1Irwaf74WZ1zUhu
      l3bjlC2azqDDC/n9u5NZ3mZ2/XbYDwU2jqqmeZDPdCMehwG36H5HkBlRNHlx6bK8
      QWkQ6E9s4d5QgtF4cKJjyk4r1u9f2FE/oA2FptDZ0F1v3UOZnnAnXfrdqgMAx4w2
      vZkmNp7BG8e5Tsa4GF4YFbAQ+9mcXsBrHHtVpOYs80bDt4X8JzD5ZhBe0B9M00gR
      wIZPHQlB9s8b5uCeAQklEgRJKt5DZgGg6FkjH8ZG7sTbEECAwEAAaNTMFEwHQYD
      VR0OBBYEFMvdMOpE+E13jc5B5nH7W0rAVwQtMB8GA1UdIwQYMBaAFMvdMOpE+E13
      jc5B5nH7W0rAVwQtMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB
      AAh34gP8UeRVUDFc2J9/7G4SHXjX7YBboEl7PZhsuwuSC8DfAzGGDFxuIkKpL6ik
      R7o/tHHtdhHi9Uy6WcHKug9Y0by7ADzZbP07m3v4oSGWAKS+CXUVTHt7yXJblsVu
      6CmlPlmx9CG9hQfpO0JYa+v1gL5AMmbsbvby4GnVCg5McRZr1h6U4J83QLUVkSD3
      cQXQGdRHRwPNrK4aFcwhGcYrV0fUw0Rgubz1bkCEdiq3e5XH7mgdd7YUZpCbh6p4
      Rz2eTP4PBhMiZoERazCKK/evGmtM4n5BcdJkpGiMkPf2ke1Dr8cx/7OVGJROtG0e
      W50qVg4iVjtjRuC2t8hXTDVb9BI=
      -----END CERTIFICATE-----
    PEM

    x509_cert = OpenSSL::X509::Certificate.new(x509_pem_data)
    x509_key = x509_cert.public_key
    x509_jwk = JOSE::JWK::KTY_X509.new(JOSE::JWK::PKeyProxy.new(x509_key))

    binary_data = x509_pem_data.unpack1('m0')
    from_binary_jwk = JOSE::JWK::KTY_X509.new(JOSE::JWK::PKeyProxy.new(OpenSSL::X509::Certificate.new(binary_data).public_key))

    assert_equal x509_jwk.key.__getobj__.to_pem.strip, from_binary_jwk.key.__getobj__.to_pem.strip
  end
end
