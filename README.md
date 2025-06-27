Multi-plateform SSH tools

# Features

- Read Keepass for ssh password
- Copy files from/to ssh remote host
- Open tunnels from local or remote host
- Open socks or http proxy through remote host

# 🚀 Version 1.0.5 (Beta)

This beta release introduces **KeePass password caching**, allowing you to avoid re-entering your password for a configurable period (default: **60 minutes**).

---

## 🔧 Configuration

To customize the cache duration for the KeePass password, add the following optional parameter to your `config.cue` file:

```cuelang
package sshor

keepassPwdCacheExpirationMinutes: 360

hosts: {
    ...
}
```
📁 Cache and Salt File Storage
During the caching process, two files are created to securely store authentication data:

🗂️ KeePass password cache file
Stores the SHA-256 hash of the KeePass password.
Location:
%USERPROFILE%\AppData\Local\Temp\sshor_keepass_*.cache

🧂 Salt file
Used to enhance password hashing security.
Location:
%APPDATA%\sshor_keepass_salt.txt

These files are automatically managed by the application and are used to validate the cached password during the defined expiration period.

🛠️ Salt and Cache Management
A PowerShell script named manageSaltAndKeys.ps1 is provided to help manage encryption and cache files:

- Option 1: Generate a new salt (used for password hashing)
- Option 2: Delete the KeePass password cache file

# Install

## From binary

Download appropriate version from [Github release](https://github.com/hurlebouc/sshor/releases/latest).

## From sources

If go 1.23 is installed on your machine, you can do

```sh
go build .
```

# Configure

Sshor currently use its own configuration (It does not read `~/.ssh/config`). This configuration is located at `~/.config/sshor` on Unix host, or at `AppData\Roaming\sshor` for windows.

This location is considered by Sshor as a [Cue package](https://cuelang.org/docs/concept/modules-packages-instances/#packages). This package must be named `sshor`.

Expected structure is an `hosts` map where keys are host names and values are `host` objects with following properties:

* `host`: address of the remote host (if missing uses the last jump host, or local host if none)
* `port`: port of the remote host (22 if missing)
* `user`: SSH user we are connecting to (if missing uses the last jump user, or local user if none)
* `keepass`: keepass location of SSH password (may be missing)
* `jump`: jump host between local and remote host (may be missing)

Field `jump` follows the same structure as `host` objects.

If `keepass` field is present, its value must be an object contaning requested following properties:

* `path`: location of the keepass database
* `id`: location of the password entry in database

Very simple example of configuration is given by the following snippet:

```cuelang
package sshor

hosts: {
    host1: {
        host: "example.com"
        port: 22
        user: "bob"
    }
    host2: {
        host: "my.ssh.host.com"
        port: 22
        user: "alice"
    }
}
```

More complicated example:

```cuelang
package sshor

_machine1: {
	plop: {
		host: "1.2.3.4"
	}
	plip: {
		host: "2.3.4.5"
	}
}

_machine2: {
	plap: {
		host: "8.8.8.8"
	}
	plup: {
		host: "192.168.1.2"
		user: "user"
	}
	testjump: {
		host: "127.0.0.1"
		user: "user"
		jump: plup
	}
}

// hosts whose credentials are stored in keepass database with the same name as the key of the map
hosts: {
	for k, v in _machine1 {
		(k): v
		(k): {
            keepass: {
                path: "/path/to/keepass.kdbx"
                id: "/id/in/keepass/\(k)"
            }
        }
	}
}

hosts: {
	for k, v in _machine2 {
		(k): v
	}
}
```
