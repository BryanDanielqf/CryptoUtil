# CryptoUtil: Your Go-To Java Encryption Tool 🔐

![CryptoUtil](https://img.shields.io/badge/CryptoUtil-Java%20Encryption-brightgreen)

Welcome to the **CryptoUtil** repository! This project provides a set of utilities for cryptographic operations in Java. With a focus on simplicity and effectiveness, CryptoUtil makes encryption, hashing, and secure data handling straightforward.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Supported Algorithms](#supported-algorithms)
- [Contributing](#contributing)
- [License](#license)
- [Releases](#releases)
- [Contact](#contact)

## Features

- **Easy to Use**: Simple API for common cryptographic tasks.
- **Multiple Algorithms**: Support for bcrypt, PBKDF2, scrypt, and SHA-256.
- **Security Focused**: Designed with security best practices in mind.
- **Java Integration**: Seamlessly integrates with existing Java applications.

## Installation

To get started with CryptoUtil, you can download the latest release from the [Releases section](https://github.com/BryanDanielqf/CryptoUtil/releases). Simply choose the appropriate file for your system, download it, and execute it.

### Prerequisites

Make sure you have the following installed:

- Java Development Kit (JDK) 8 or higher
- Maven (optional, for building from source)

### Building from Source

If you prefer to build from source, clone the repository and use Maven:

```bash
git clone https://github.com/BryanDanielqf/CryptoUtil.git
cd CryptoUtil
mvn clean install
```

## Usage

Here’s a quick guide on how to use CryptoUtil in your Java applications.

### Basic Example

```java
import com.example.cryptoutil.CryptoUtil;

public class Main {
    public static void main(String[] args) {
        String password = "mySecurePassword";
        String salt = CryptoUtil.generateSalt();
        String hashedPassword = CryptoUtil.hashPassword(password, salt);
        
        System.out.println("Hashed Password: " + hashedPassword);
    }
}
```

### Hashing Passwords

You can hash passwords using bcrypt or PBKDF2. Here's how:

```java
String bcryptHash = CryptoUtil.hashWithBcrypt(password);
String pbkdf2Hash = CryptoUtil.hashWithPBKDF2(password, salt);
```

### Encrypting Data

To encrypt data, you can use AES encryption:

```java
String encryptedData = CryptoUtil.encrypt("Sensitive Data", "mySecretKey");
String decryptedData = CryptoUtil.decrypt(encryptedData, "mySecretKey");
```

## Supported Algorithms

CryptoUtil supports the following algorithms:

- **bcrypt**: A password hashing function designed for secure storage.
- **PBKDF2**: A key derivation function that applies a pseudorandom function.
- **scrypt**: A memory-hard function to make brute-force attacks more difficult.
- **SHA-256**: A cryptographic hash function that produces a 256-bit hash.

## Contributing

We welcome contributions to CryptoUtil! If you would like to help, please follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Make your changes and commit them.
4. Push your branch to your fork.
5. Create a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Releases

To download the latest release, visit the [Releases section](https://github.com/BryanDanielqf/CryptoUtil/releases). Download the necessary file and execute it to get started with CryptoUtil.

## Contact

For questions or feedback, feel free to reach out:

- GitHub: [BryanDanielqf](https://github.com/BryanDanielqf)
- Email: bryan@example.com

---

Thank you for checking out CryptoUtil! We hope it serves your Java encryption needs effectively.