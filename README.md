# Authentication API

This is the authentication API used by e-Research Bastion (SSH and OpenVPN) services, linking those services plus a web interface to a MySQL database.

## API endpoints

### `GET /` Shows system status

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

### `GET /v{API_VERSION}/ssh_keys/<username>`

Retrieve the SSH keys belonging to specified username

Example output:

```
{
    "keys": [
        {
            "created_at": 1619713687,
            "name": "mypc",
            "pub_key": "AAAAB3NzaC1yc2EAAAADAQABAAABAQDh9I/G9xfiyJIwlhaL8C5iGbfi9oYgal/tHTi9kbjaDGJH3pt509D3iJm/pGw7jKC6dkYLME4vNf/apd98NfwHFpSs6AvSXuoVidsemJA7CJwn1pETlMb8qtNXZA9BbPG2wmhPf82Ck9lrwNBAkmgi1oLuAA2g/NkMirImbFCpv72omqNQFeJGnoBukAX4++2z3xxGBsXlAcAtrELBWfuaViPs+qy8xXIyYPs1ToUD04RKJkQ24XRZCOyUN7y/boplgwiFOcQxnSnYGh9fMGVvMfyOirvgS8vVzX0hP3h4gjLzK4U6iv32CB5rD+iBepC8JGG1rFlMlatXOsjQEsfh",
            "type": "ssh-rsa"
        }
    ],
    "status": "OK"
}

```
