# Diuit Session Token Helper

A simple PHP library to help you authenticate your devices from backend easier. It returns session token, which you have to pass to your device and login with it.

## Installation

Package is available on [Packagist](https://packagist.org/packages/diuit/diuit-session-token-helper),
you can install it using [Composer](http://getcomposer.org).

```shell
composer require diuit/diuit-session-token-helper
```

### Dependencies

- PHP 5.4+

## Basic usage

### Getting session token

Just use the DiuitTokenHelper to get a session token:

```php
use Diuit\DiuitTokenHelper;

$session = (new DiuitTokenHelper())->setAppId('your_app_id') // Configures app ID
                        ->setAppKey('your_app_key') // Configures app key
                        ->setKeyID('your_key_id') // Configures key id for finding public key
                        ->setPrivateKey('file://your_pem_file_path') // Configures private key (you can either use file path or a string for your private key)
                        ->setUserSerial('user_serial') // Configures user serial
                        ->setExpDuration(7*24*3600) // Configures length of session valid duration (in seconds), example is in length of a week
                        ->getSessionToken('your_device_serial', 'gcm', 'device_push_token'); // Configures device serial, platform and push token(optional) and retrieves session token

echo $session; // will print session token

```

### And then ... ?

Pass the **session token** you got here to your client (may be an app or browser), and login your client with it for using more features of [Diuit Messaging API](http://api2.diuit.com/).
