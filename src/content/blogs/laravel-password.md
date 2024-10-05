---
title: 'Laravel Password Hashing'
pubDate: 2022-07-01
description: 'Deep dive into how Laravel hashes passwords.'
author: 'quanph'
slug: 'laravel-password-hashing'
icon: 'logos:laravel'
#image:
#    url: 'https://docs.astro.build/assets/rose.webp'
#    alt: 'The Astro logo on a dark background with a pink glow.'
tags: [ "laravel", "web" ]
---

> Bài viết này sử dụng Laravel 11.x

## Phân biệt Hashing và Encryption

- Hashing (băm) là mã hóa dữ liệu một chiều (one-way) , không thể giải mã ngược lại từ dữ liệu đã mã hóa.
- Encryption (mã hóa) là mã hóa dữ liệu hai chiều (two-way), có thể giải mã ngược lại từ dữ liệu đã mã hóa.

> Đối với mật khẩu, chúng ta sẽ sử dụng Hashing thay vì Encryption vì mục đích của mật khẩu là không thể giải mã ngược
> lại. Từ đó sẽ không có cách nào khác để lấy lại mật khẩu gốc từ mật khẩu đã mã hóa và bảo mật thông tin người dùng tốt
> hơn.

## Laravel tạo mật khẩu như thế nào?

```php 
\Illuminate\Support\Facades\Hash::make('password');

// "$2y$12$hqHHnplzZWN51nvTHS61KeS9Rfdfgp9rdOLx8QKu6sQ7b.WEf6Pp."
```

Nếu chúng ta thực hiện câu lệnh trên nhiều lần, kết quả sẽ khác nhau mỗi lần.

```php
// "$2y$12$tIa2SmJtR2QxJYX9LkJ38ODYwpuQUWMColeuDUyBemWIjIl2UlyuS"
// "$2y$12$.fjqXri.DtJ3UYop7K4y9efvnZ88xMX2PmgRRBTjJTV9Q7xPVdxI2"
// "$2y$12$l4da6LfotWk3dvUrggZ/meleoRD6JqHGo7iONDR4Agkt1GM/YCIQi"
```

Xem ví dụ dưới đây, làm thế nào Laravel có thể kiểm tra mật khẩu khi đăng nhập nếu mỗi lần mã hóa mật khẩu sẽ cho ra kết
quả khác nhau?

```php
use Illuminate\Support\Facades\Hash;

// Mật khẩu đã mã hóa được lưu trữ trong cơ sở dữ liệu
$storedHash = '••••••••••••••••••••••••••••••••••••••••';

// Mật khẩu người dùng nhập vào
$userInputPassword = 'password';

// Kiểm tra mật khẩu
if (Hash::check($userInputPassword, $storedHash)) {
    // Mật khẩu đúng
    echo "Password verified!";
} else {
    // Mật khẩu sai
    echo "Invalid password!";
}
```

Laravel sử dụng Bcrypt và Argon2 để mã hóa mật khẩu. Bcrypt thường được ưu tiên hơn vì "work factor" của nó có thể tùy
chỉnh. tức là thời gian để mã hóa mật khẩu có thể tăng nên theo sức mạnh phần cứng. Thuật toán để băm mật khẩu càng chậm
thì sẽ mất nhiều thời gian hơn để các attacker có thể tạo các "rainbow tables" bao gồm tất cả các mật khẩu có thể băm để
tiến hành tấn công "brute force" vào hệ thống.

Argon2 là một thuật toán băm mật khẩu mới hơn và có vẻ mạnh mẽ hơn Bcrypt. Tuy nhiên chúng ta không tìm hiểu sâu vào 2
thuật toán này trong bài viết này. Bạn có thể tham khảo [tài liệu của Laravel](https://laravel.com/docs/11.x/hashing)
để biết thêm thông tin. Trong tài liệu sẽ nói rõ hơn về các config "work factor" của Bcrypt và Argon2.

`Hash` sử dụng 2 phương thức trong PHP là `password_hash` và `password_verify` để mã hóa và kiểm tra mật khẩu.
Cả 2 phương thức này đều là "wrapper" và tương thích với phương thức `crypt` trong PHP. Bạn có thể tham khảo ở đây:

- [https://www.php.net/manual/en/function.crypt.php](https://www.php.net/manual/en/function.crypt.php)
- [https://www.php.net/manual/en/function.password-hash.php](https://www.php.net/manual/en/function.password-hash.php)
- [https://www.php.net/manual/en/function.password-verify.php](https://www.php.net/manual/en/function.password-verify.php)

> Tương thích tức là password được tạo bởi `crypt` có thể được kiểm tra bởi `password_verify` và ngược lại.

Đây là cách mà Laravel triển khai 2 phương thức này trong class `BcryptHasher`

```php
// Hash::make($password);

/**
 * Hash the given value.
 *
 * @param  string  $value
 * @param  array  $options
 * @return string
 *
 * @throws \RuntimeException
 */
public function make(#[\SensitiveParameter] $value, array $options = [])
{
    $hash = password_hash($value, PASSWORD_BCRYPT, [
        'cost' => $this->cost($options),
    ]);

    if ($hash === false) {
        throw new RuntimeException('Bcrypt hashing not supported.');
    }

    return $hash;
}

// Hash::check($value, $hashedValue);

/**
 * Check the given plain value against a hash.
 *
 * @param  string  $value
 * @param  string  $hashedValue
 * @param  array  $options
 * @return bool
 *
 * @throws \RuntimeException
 */
public function check(#[\SensitiveParameter] $value, $hashedValue, array $options = [])
{
    if (is_null($hashedValue) || strlen($hashedValue) === 0) {
        return false;
    }

    if ($this->verifyAlgorithm && ! $this->isUsingCorrectAlgorithm($hashedValue)) {
        throw new RuntimeException('This password does not use the Bcrypt algorithm.');
    }

    return parent::check($value, $hashedValue, $options);
}
```

Trong tài liệu của PHP có mô tả như sau:

> `password_hash()` uses a strong hash, generates a strong salt, and applies proper rounds automatically.
> `password_hash()` is a simple `crypt()` wrapper and compatible with existing password hashes.
> Use of `password_hash()` is encouraged.

Trong các ví dụ về Hash::make('...') ở trên, thực ra tất cả đều là kết quả của hàm `password_hash()`
Chúng ta có thể thấy rằng luôn có 1 phần giống nhau ở đầu chuỗi mã hóa, ví dụ như `$2y$12$`.
Đó là sự kết hợp của `algorithm`, `cost` và `salt` như là một phần của chuỗi mã hóa.
Do đó tất cả các thông tin cần thiết mà chúng ta cần để kiểm tra mật khẩu đều đã được bao gồm trong chuỗi mã hóa.
Nó cho phép hàm `password_verify()` kiểm tra mật khẩu mà không cần phải lưu trữ riêng `salt` hay `algorithm` ở nơi khác.

Sâu hơn một chút, hàm `password_verify()` thực hiện các bước như sau:

- **Trích xuất tham số**: Trích xuất các tham số được lưu trong chính chuỗi mã hóa.
  Các tham số này bao gồm `algorithm`, `cost`, và `salt`.
- **Băm mật khẩu cần kiểm tra**: Sử dụng `algorithm`, `cost`, và `salt` để mã hóa mật khẩu người dùng nhập vào.
- **So sánh**: So sánh chuỗi mã hóa của mật khẩu người dùng với chuỗi mã hóa đã lưu trữ.

Để hiểu rõ hơn ta thử triển khai hàm `password_verify()` bằng cách sử dụng `crypt()` như sau:

```php
function password_verify($userInputPassword, $storedHash) {
    // Trích xuất các tham số từ chuỗi mã hóa
    $params = explode('$', $storedHash);
    $algorithm = $params[1];
    $cost = (int)$params[2];
    $salt = $params[3];

    // Băm mật khẩu người dùng nhập vào
    $rehashedPassword = crypt($userInputPassword, '$' . $algorithm . '$' . $cost . '$' . $salt);

    // So sánh chuỗi mã hóa
    if ($rehashedPassword === $storedHash) {
        return true;
    } else {
        return false;
    }
}
```

## Thiết lập

Hàm `password_hash()` có thể tạo ra chuỗi mã hóa mạnh mẽ bằng `salt`. Chúng ta cũng có thể tùy chỉnh "work factor" trong
file `config/hashing.php` của Laravel.

```php
/*
|--------------------------------------------------------------------------
| Bcrypt Options
|--------------------------------------------------------------------------
|
| Here you may specify the configuration options that should be used when
| passwords are hashed using the Bcrypt algorithm. This will allow you
| to control the amount of time it takes to hash the given password.
|
*/

'bcrypt' => [
    'rounds' => env('BCRYPT_ROUNDS', 12), // xác định số lần Bcrypt thực hiện quy trình băm. Mặc định, số vòng băm là 12.
    'verify' => env('HASH_VERIFY', true), // 
],

/*
|--------------------------------------------------------------------------
| Argon Options
|--------------------------------------------------------------------------
|
| Here you may specify the configuration options that should be used when
| passwords are hashed using the Argon algorithm. These will allow you
| to control the amount of time it takes to hash the given password.
|
*/

'argon' => [
    'memory' => env('ARGON_MEMORY', 65536),
    'threads' => env('ARGON_THREADS', 1),
    'time' => env('ARGON_TIME', 4),
    'verify' => env('HASH_VERIFY', true),
],
```

Đối với Bcrypt, số vòng băm càng cao, thời gian xử lý để tạo ra giá trị băm càng lâu, giúp tăng cường độ bảo mật. Tuy
nhiên, điều này cũng có thể ảnh hưởng đến hiệu suất hệ thống. Thông qua biến môi trường BCRYPT_ROUNDS, bạn có thể dễ
dàng điều chỉnh số vòng băm tùy theo khả năng phần cứng mà không cần thay đổi mã nguồn.
