# Authentication API

This is the authentication API used by e-Research Bastion (SSH and OpenVPN) services, linking those services plus a web interface to a MySQL database.

## API endpoints

### Generic

#### System status

```
GET /
```
Example output:

```
{
    "host": "authapi1.example.com",
    "status": "OK",
    "table_counts": {
        "mfa_requests": 0,
        "ssh_keys": 1,
        "users": 3,
        "vpn_keys": 15
    },
    "version": 1
}
```

Use the `version` in API URIs below.

### For web portal

#### Get SSH keys

```
GET /v{API_VERSION}/ssh_keys/<username>
```

Example output:

```
{
    "keys": [
        {
            "created_at": 1619713687,
            "name": "mylaptopkey",
            "pub_key": "AAAAB3NzaC1yc2EAAAADAQABAAABAQDh9I/G9xfiyJIwlhaL8C5iGbfi9oYgal/tHTi9kbjaDGJH3pt509D3iJm/pGw7jKC6dkYLME4vNf/apd98NfwHFpSs6AvSXuoVidsemJA7CJwn1pETlMb8qtNXZA9BbPG2wmhPf82Ck9lrwNBAkmgi1oLuAA2g/NkMirImbFCpv72omqNQFeJGnoBukAX4++2z3xxGBsXlAcAtrELBWfuaViPs+qy8xXIyYPs1ToUD04RKJkQ24XRZCOyUN7y/boplgwiFOcQxnSnYGh9fMGVvMfyOirvgS8vVzX0hP3h4gjLzK4U6iv32CB5rD+iBepC8JGG1rFlMlatXOsjQEsfh",
            "type": "ssh-rsa"
        }
    ],
    "status": "OK"
}
```

#### Get OpenVPN keys

```
GET /v{API_VERSION}/vpn_keys/<username>
```

Example output:

```
{
    "keys": [
        {
            "created_at": 1620308514,
            "expires_at": 1651844574,
            "name": "abcdef",
            "public_cert": "-----BEGIN CERTIFICATE-----\nMIICRTCCAeugAwIBAgIQEcUPCHTg+cPyVFPoe8r2hjAKBggqhkjOPQQDAjApMScw\nJQYDVQQDEx5LQ0wgZS1SZXNlYXJjaCBJbnRlcm1lZGlhdGUgQ0EwHhcNMjEwNTA2\nMTQ0MTU0WhcNMjIwNTA2MTQ0MjU0WjAvMS0wKwYDVQQDEyQ1NmUzNDdhMC1hZTc5\nLTExZWItODY1Zi1lOTVjMmIyYWU4MTQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC\nAASqNHiInzmIUeMgagDIJLYEzJ/pP3/ZJFTq4JhRnrLDOKGdp4B0fdDiVEv0XAKL\ncYlFB1l0KAE4LBWQXxNFP54to4HuMIHrMA4GA1UdDwEB/wQEAwIHgDAdBgNVHSUE\nFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwHQYDVR0OBBYEFJd5QOerju24hCFqOsCg\n6cS3TIILMB8GA1UdIwQYMBaAFNEQg/+Jafr1AL6oRT5Q7d13tN7NMC8GA1UdEQQo\nMCaCJDU2ZTM0N2EwLWFlNzktMTFlYi04NjVmLWU5NWMyYjJhZTgxNDBJBgwrBgEE\nAYKkZMYoQAEEOTA3AgEBBAVhZG1pbgQrUnotOU9MYzdKWjQ0dTNJNktIdUMzT3Bj\nYXFFTmN6OFU0Rm15T3ROeVpZWTAKBggqhkjOPQQDAgNIADBFAiEAzhhjM+h8BQYF\n1PxwzThMKXejYEY4GDeZYH3Ir4EL9N0CIBbLTlg4eDRhOC6vmNbQRKjoZ+a6o9VZ\noV/xZqD38gCi\n-----END CERTIFICATE-----\n",
            "status": "active",
            "uuid": "56e347a0-ae79-11eb-865f-e95c2b2ae814"
        }
    ],
    "status": "OK"
}
```

#### Set SSH keys

```
PUT /v{API_VERSION}/ssh_keys/<username>
```

Parameters should be supplied as JSON dict containing all keys for user.

Example input:

```
{
  "mylaptopkey": {
    "pub_key": "AAAAB3NzaC1yc2EAAAADAQABAAABAQDh9I/G9xfiyJIwlhaL8C5iGbfi9oYgal/tHTi9kbjaDGJH3pt509D3iJm/pGw7jKC6dkYLME4vNf/apd98NfwHFpSs6AvSXuoVidsemJA7CJwn1pETlMb8qtNXZA9BbPG2wmhPf82Ck9lrwNBAkmgi1oLuAA2g/NkMirImbFCpv72omqNQFeJGnoBukAX4++2z3xxGBsXlAcAtrELBWfuaViPs+qy8xXIyYPs1ToUD04RKJkQ24XRZCOyUN7y/boplgwiFOcQxnSnYGh9fMGVvMfyOirvgS8vVzX0hP3h4gjLzK4U6iv32CB5r",
    "type": "ssh-rsa"
  }
}
```

Example output:

```
{
    "keys": [
        {
            "created_at": 1619713687,
            "name": "mylaptopkey",
            "pub_key": "AAAAB3NzaC1yc2EAAAADAQABAAABAQDh9I/G9xfiyJIwlhaL8C5iGbfi9oYgal/tHTi9kbjaDGJH3pt509D3iJm/pGw7jKC6dkYLME4vNf/apd98NfwHFpSs6AvSXuoVidsemJA7CJwn1pETlMb8qtNXZA9BbPG2wmhPf82Ck9lrwNBAkmgi1oLuAA2g/NkMirImbFCpv72omqNQFeJGnoBukAX4++2z3xxGBsXlAcAtrELBWfuaViPs+qy8xXIyYPs1ToUD04RKJkQ24XRZCOyUN7y/boplgwiFOcQxnSnYGh9fMGVvMfyOirvgS8vVzX0hP3h4gjLzK4U6iv32CB5rD+iBepC8JGG1rFlMlatXOsjQEsfh",
            "type": "ssh-rsa"
        }
    ],
    "status": "OK"
}
```

#### Request OpenVPN key

```
POST /v{API_VERSION}/vpn_keys/<username>/<key_name>
```

Example output:

```
{
    "config": "# KCL e-Research OpenVPN configuration\n# Certificate: 56e347a0-ae79-11eb-865f-e95c2b2ae814\n# Generated: 2021-05-06 14:41:54\n# Expires: 2022-05-06 14:42:54\n\nclient\nport 1194\nproto udp\ndev tun\nremote bastion.er.kcl.ac.uk\nresolve-retry infinite\nnobind\npersist-key\npersist-tun\nauth-user-pass\nremote-cert-tls server\nverb 3\ncompress lz4\nverify-x509-name bastion.er.kcl.ac.uk name\ndh none\nca [inline]\ncert [inline]\nkey [inline]\n\n<ca>\n-----BEGIN CERTIFICATE-----\nMIIBhTCCASugAwIBAgIQBCgVbGxTT6V7MybG8FvhNDAKBggqhkjOPQQDAjAhMR8w\nHQYDVQQDExZLQ0wgZS1SZXNlYXJjaCBSb290IENBMB4XDTIxMDMwMTE2MTkxMVoX\nDTMxMDMwMTE2MTkxMVowITEfMB0GA1UEAxMWS0NMIGUtUmVzZWFyY2ggUm9vdCBD\nQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLI2Nl6qgyy+wtoViyCtOweuUtJ0\nMGBMl/I5jtFOpwpA1hO5I49uZkx/FK8pG41PKZShdkrx0gpQ8IFh8QXh2dujRTBD\nMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEBMB0GA1UdDgQWBBST\nIXUIL39dtpbN6AVb+Imd2/8CEjAKBggqhkjOPQQDAgNIADBFAiArZQUB5lorQyB4\nqhEfQEVJBVWYOtdmBxUXrqdIc8FrggIhAJ0514wEfL6HUbBqOVLDK8QhwgtdXgi7\nHfp4lvGRyOyZ\n-----END CERTIFICATE-----\n</ca>\n<cert>\n-----BEGIN CERTIFICATE-----\nMIICRTCCAeugAwIBAgIQEcUPCHTg+cPyVFPoe8r2hjAKBggqhkjOPQQDAjApMScw\nJQYDVQQDEx5LQ0wgZS1SZXNlYXJjaCBJbnRlcm1lZGlhdGUgQ0EwHhcNMjEwNTA2\nMTQ0MTU0WhcNMjIwNTA2MTQ0MjU0WjAvMS0wKwYDVQQDEyQ1NmUzNDdhMC1hZTc5\nLTExZWItODY1Zi1lOTVjMmIyYWU4MTQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC\nAASqNHiInzmIUeMgagDIJLYEzJ/pP3/ZJFTq4JhRnrLDOKGdp4B0fdDiVEv0XAKL\ncYlFB1l0KAE4LBWQXxNFP54to4HuMIHrMA4GA1UdDwEB/wQEAwIHgDAdBgNVHSUE\nFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwHQYDVR0OBBYEFJd5QOerju24hCFqOsCg\n6cS3TIILMB8GA1UdIwQYMBaAFNEQg/+Jafr1AL6oRT5Q7d13tN7NMC8GA1UdEQQo\nMCaCJDU2ZTM0N2EwLWFlNzktMTFlYi04NjVmLWU5NWMyYjJhZTgxNDBJBgwrBgEE\nAYKkZMYoQAEEOTA3AgEBBAVhZG1pbgQrUnotOU9MYzdKWjQ0dTNJNktIdUMzT3Bj\nYXFFTmN6OFU0Rm15T3ROeVpZWTAKBggqhkjOPQQDAgNIADBFAiEAzhhjM+h8BQYF\n1PxwzThMKXejYEY4GDeZYH3Ir4EL9N0CIBbLTlg4eDRhOC6vmNbQRKjoZ+a6o9VZ\noV/xZqD38gCi\n-----END CERTIFICATE-----\n</cert>\n<key>\n-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIBrNfkGYFRJLg3Grh8/sm9DsRkphFHMP0RkPkfVTbVYOoAoGCCqGSM49\nAwEHoUQDQgAEqjR4iJ85iFHjIGoAyCS2BMyf6T9/2SRU6uCYUZ6ywzihnaeAdH3Q\n4lRL9FwCi3GJRQdZdCgBOCwVkF8TRT+eLQ==\n-----END EC PRIVATE KEY-----\n</key>",
    "created_at": 1620308514,
    "expires_at": 1651844574,
    "name": "abcdef",
    "private_key": "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIBrNfkGYFRJLg3Grh8/sm9DsRkphFHMP0RkPkfVTbVYOoAoGCCqGSM49\nAwEHoUQDQgAEqjR4iJ85iFHjIGoAyCS2BMyf6T9/2SRU6uCYUZ6ywzihnaeAdH3Q\n4lRL9FwCi3GJRQdZdCgBOCwVkF8TRT+eLQ==\n-----END EC PRIVATE KEY-----\n",
    "public_cert": "-----BEGIN CERTIFICATE-----\nMIICRTCCAeugAwIBAgIQEcUPCHTg+cPyVFPoe8r2hjAKBggqhkjOPQQDAjApMScw\nJQYDVQQDEx5LQ0wgZS1SZXNlYXJjaCBJbnRlcm1lZGlhdGUgQ0EwHhcNMjEwNTA2\nMTQ0MTU0WhcNMjIwNTA2MTQ0MjU0WjAvMS0wKwYDVQQDEyQ1NmUzNDdhMC1hZTc5\nLTExZWItODY1Zi1lOTVjMmIyYWU4MTQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC\nAASqNHiInzmIUeMgagDIJLYEzJ/pP3/ZJFTq4JhRnrLDOKGdp4B0fdDiVEv0XAKL\ncYlFB1l0KAE4LBWQXxNFP54to4HuMIHrMA4GA1UdDwEB/wQEAwIHgDAdBgNVHSUE\nFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwHQYDVR0OBBYEFJd5QOerju24hCFqOsCg\n6cS3TIILMB8GA1UdIwQYMBaAFNEQg/+Jafr1AL6oRT5Q7d13tN7NMC8GA1UdEQQo\nMCaCJDU2ZTM0N2EwLWFlNzktMTFlYi04NjVmLWU5NWMyYjJhZTgxNDBJBgwrBgEE\nAYKkZMYoQAEEOTA3AgEBBAVhZG1pbgQrUnotOU9MYzdKWjQ0dTNJNktIdUMzT3Bj\nYXFFTmN6OFU0Rm15T3ROeVpZWTAKBggqhkjOPQQDAgNIADBFAiEAzhhjM+h8BQYF\n1PxwzThMKXejYEY4GDeZYH3Ir4EL9N0CIBbLTlg4eDRhOC6vmNbQRKjoZ+a6o9VZ\noV/xZqD38gCi\n-----END CERTIFICATE-----\n",
    "status": "active",
    "uuid": "56e347a0-ae79-11eb-865f-e95c2b2ae814"
}
```

#### Revoke OpenVPN key

```
DELETE /v{API_VERSION}/vpn_keys/<username>/<key_name>
```

Example output:

```
{
    "keys": [
        {
            "created_at": 1620308514,
            "expires_at": 1651844574,
            "name": "abcdef",
            "public_cert": "-----BEGIN CERTIFICATE-----\nMIICRTCCAeugAwIBAgIQEcUPCHTg+cPyVFPoe8r2hjAKBggqhkjOPQQDAjApMScw\nJQYDVQQDEx5LQ0wgZS1SZXNlYXJjaCBJbnRlcm1lZGlhdGUgQ0EwHhcNMjEwNTA2\nMTQ0MTU0WhcNMjIwNTA2MTQ0MjU0WjAvMS0wKwYDVQQDEyQ1NmUzNDdhMC1hZTc5\nLTExZWItODY1Zi1lOTVjMmIyYWU4MTQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC\nAASqNHiInzmIUeMgagDIJLYEzJ/pP3/ZJFTq4JhRnrLDOKGdp4B0fdDiVEv0XAKL\ncYlFB1l0KAE4LBWQXxNFP54to4HuMIHrMA4GA1UdDwEB/wQEAwIHgDAdBgNVHSUE\nFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwHQYDVR0OBBYEFJd5QOerju24hCFqOsCg\n6cS3TIILMB8GA1UdIwQYMBaAFNEQg/+Jafr1AL6oRT5Q7d13tN7NMC8GA1UdEQQo\nMCaCJDU2ZTM0N2EwLWFlNzktMTFlYi04NjVmLWU5NWMyYjJhZTgxNDBJBgwrBgEE\nAYKkZMYoQAEEOTA3AgEBBAVhZG1pbgQrUnotOU9MYzdKWjQ0dTNJNktIdUMzT3Bj\nYXFFTmN6OFU0Rm15T3ROeVpZWTAKBggqhkjOPQQDAgNIADBFAiEAzhhjM+h8BQYF\n1PxwzThMKXejYEY4GDeZYH3Ir4EL9N0CIBbLTlg4eDRhOC6vmNbQRKjoZ+a6o9VZ\noV/xZqD38gCi\n-----END CERTIFICATE-----\n",
            "status": "revoked",
            "uuid": "56e347a0-ae79-11eb-865f-e95c2b2ae814"
        }
    ],
    "status": "OK"
}
```

#### Get MFA requests

```
GET /v{API_VERSION}/mfa_requests/<username>
```

Example output:

```
{
    "mfa_requests": [
        {
            "created_at": 1620312789,
            "expires_at": null,
            "remote_ip": "192.0.2.45",
            "service": "vpn",
            "status": "pending",
            "updated_at": 1620312789
        }
    ],
    "status": "OK"
}
```

#### Approve or reject MFA request

```
POST /v{API_VERSION}/mfa_requests/<username>
```

Requires JSON hash containing: `ip_address`, `service` (`ssh` or `vpn`), `status` (`approved` or `rejected`)

Example input:

```
{
    "ip_address": "192.0.2.45",
    "service": "vpn",
    "status": "approved"
}
```

Example output:

```
{
    "mfa_requests": [
        {
            "created_at": 1620312789,
            "expires_at": 1620917908,
            "remote_ip": "192.0.2.45",
            "service": "vpn",
            "status": "approved",
            "updated_at": 1620313107
        }
    ],
    "status": "OK"
}
```

### For bastion servers

Not yet documented, internal use only.
