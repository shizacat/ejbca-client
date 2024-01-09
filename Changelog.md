## [Unreleased]

## [1.1.1]
### Fix
- Miss OpenSSL, in function cert_pem_extract_serial work through cryptography

## [1.1.0]
### Added
- The method '_generate_csr' rewrite on cryptography.
- Remove work with PyOpenSSL. Now working only with cryptography.
- Convert CRL through cryptography

## [1.0.6]
### Fix
- Remove methods OpenSSL.crypto.load_pkcs12. Work with pkcs12 through cryptography.

## [1.0.5]
### Fix
- Fix version pyOpenSSL == 22.1.0

## [1.0.4]
### Added
- Method restore_certificate_and_private_key_by_sn


## [1.0.3]
### Update
- Set args: end_entity_profile_name, cert_profile_name as None
  for functions: generate_certificate_pkey_on_server, generate_certificate


## [1.0.2]
### Fix
- Fix setup.cfg


## [1.0.1]
### Added
- Add exceptions.


## [1.0.0]
### Added
- Release
