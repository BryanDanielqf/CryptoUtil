# CryptoUtil (JDK 1.8 호환)

Java 1.8 이상에서 사용 가능한 **암호화·복호화 및 해시 유틸리티**입니다.  
AES, SHA, Base64 외에 PBKDF2, bcrypt, scrypt 같은 고급 해시 알고리즘도 포함되어 있으며  
CBC 모드 + IV 지원도 가능합니다.
보안이 필요한 모든 Java 애플리케이션에서 안전하고 손쉬운 암호화·해싱 처리를 지원합니다.

JAR 이용시 mvn clean package로 target 폴더에
[crypto-util-1.0.0.jar](target/sensitive-masker-1.0.0.jar) 생성 후 사용
---

## 기능 요약

| 기능              | 설명                                | 복호화 지원 | 보안 수준 |
|------------------|-------------------------------------|--------------|-----------|
| AES (ECB)        | 대칭키 암호화 (패딩 + 사용자 키)     | ✅ 지원      | 중        |
| AES (CBC + IV)   | 초기화 벡터(IV)를 포함한 안전한 AES | ✅ 지원      | 높음       |
| SHA-256          | 단방향 해시                         | ❌ 미지원    | 낮음       |
| Base64           | 바이너리 → 텍스트 인코딩            | ✅ 지원      | 낮음       |
| PBKDF2           | 솔트 + 반복 기반 키 파생 함수       | ❌ (검증만)  | 중         |
| bcrypt           | 내부 솔트 + 느린 연산 기반 해시     | ❌ (검증만)  | 높음       |
| scrypt           | 메모리 기반 고보안 해시             | ❌ (검증만)  | 매우 높음   |

---

## 사용 예제
###  AES 암호화/복호화 (ECB)
```java
String key = "MySecretKey12345";
String plain = "Hello Crypto";
String encrypted = CryptoUtil.encryptAES(plain, key);
String decrypted = CryptoUtil.decryptAES(encrypted, key);
```
### AES (CBC + IV) 암호화/복호화
```java
String secret = "mykey12345678901"; // 16 bytes
String iv = "initvector1234567";    // 16 bytes
String cipher = CryptoUtil.encryptAESCBC("ABC", secret, iv);
String plain = CryptoUtil.decryptAESCBC(cipher, secret, iv);
```
### SHA-256 해시
```java
String hashed = CryptoUtil.sha256("password123");
```
### PBKDF2 해시 및 검증
```java
String salt = "mySalt";
String hash = CryptoUtil.pbkdf2("password123", salt);
boolean matched = CryptoUtil.pbkdf2Matches("password123", salt, hash);
```
### bcrypt 해시 및 검증
```java
String hash = CryptoUtil.bcrypt("pass123");
boolean matched = CryptoUtil.bcryptMatches("pass123", hash);
```
### scrypt 해시 및 검증
```java
String hash = CryptoUtil.scrypt("pass123");
boolean matched = CryptoUtil.scryptMatches("pass123", hash);
```
### Base64 인코딩/디코딩 (암/복호화 사용 X)
```java
String encoded = CryptoUtil.base64Encode("hello");
String decoded = CryptoUtil.base64Decode(encoded);
```
## 알고리즘 비교표
| 알고리즘 | 내부 구조 / 특징 | 솔트 지원 | 반복 / 비용 설정 | 해시 값 일정성 | 보안 수준 | 추천 사용처 |
|----------|-------------------|-----------|------------------|----------------|------------|------------------|
| **SHA-256** | 단방향 해시 함수 (SHA-2) | ❌ 없음 | ❌ 불가 | ✅ 고정 | ⚠️ 낮음 | 파일 무결성, 인증서 지문 |
| **PBKDF2** | HMAC 기반 반복 해시 | ✅ 필수 | ✅ 가능 | ✅ 고정 | ✅ 중간 | 일반 비밀번호 저장 |
| **bcrypt** | Blowfish + 자동 솔트 | ✅ 자동 | ✅ 비용 설정 | ❌ 매번 다름 | ✅ 높음 | 로그인 비밀번호 |
| **scrypt** | 메모리 하드 해시 함수 | ✅ 자동 | ✅ 복잡도 설정 | ❌ 매번 다름 | ✅ 매우 높음 | 고보안, 지갑 암호화 |

## 설치 방법
1. 로컬 JAR 설치
```
mvn install:install-file \
  -Dfile=target/crypto-util-1.0.0.jar \
  -DgroupId=com.sangmoo \
  -DartifactId=crypto-util \
  -Dversion=1.0.0 \
  -Dpackaging=jar
```
2. Maven 프로젝트에 추가
```
<dependency>
    <groupId>com.sangmoo</groupId>
    <artifactId>crypto-util</artifactId>
    <version>1.0.0</version>
</dependency>
```
## 지원 환경
1. Java 1.8 이상 
2. Maven 프로젝트용 JAR 제공
3. 외부 보안 키/솔트 기반 적용 가능

## 라이센스
MIT License