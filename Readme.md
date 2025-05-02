# CryptoUtil (JDK 1.8 호환)

Java 1.8 이상에서 사용 가능한 **암호화·복호화 및 해시 유틸리티**입니다.  
AES, SHA, Base64 외에 PBKDF2, bcrypt, scrypt 같은 고급 해시 알고리즘도 포함되어 있으며  
CBC 모드 + IV 지원도 가능합니다.
보안이 필요한 모든 Java 애플리케이션에서 안전하고 손쉬운 암호화·해싱 처리를 지원합니다.

JAR 이용시 mvn clean package로 target 폴더에
[crypto-util-1.0.0.jar](target/sensitive-masker-1.0.0.jar) 생성 후 사용
---

## 기능 요약
| 기능            | 설명                                         | 복호화 가능 여부 |
|----------------|----------------------------------------------|------------------|
| AES (CBC)      | 사용자 지정 키와 IV로 암/복호화               | ✅ 지원           |
| SHA-256        | 단방향 해시 (보통 데이터 무결성 확인용)       | ❌ 불가           |
| PBKDF2         | Salt 기반 단방향 해시                         | ❌ 불가           |
| bcrypt         | 비밀번호 보안 해시로 적합 (salt 내장됨)       | ❌ 불가           |
| scrypt         | 고보안 메모리 의존 해시                       | ❌ 불가           |

---

## 사용 예제
```java
String plain = "HelloWorld123";
String key = "MySecretKey1234";
String iv = "MyInitVector1234";

// AES 암/복호화
String enc = CryptoUtil.encryptAES(plain, key, iv);
String dec = CryptoUtil.decryptAES(enc, key, iv);

// SHA256
String sha = CryptoUtil.hashSHA256("mypassword");

// PBKDF2
String pbkdf2 = CryptoUtil.hashPBKDF2("mypassword", "somesalt");

// bcrypt
String bcrypted = CryptoUtil.hashBCrypt("mypassword");
boolean bcryptValid = CryptoUtil.verifyBCrypt("mypassword", bcrypted);

// scrypt
String scrypted = CryptoUtil.hashSCrypt("mypassword");
boolean scryptValid = CryptoUtil.verifySCrypt("mypassword", scrypted);

```
## 알고리즘 비교표
| 알고리즘 | 내부 구조                         | 장점                                 | 사용처 추천 |
|----------|----------------------------------|--------------------------------------|-------------|
| AES      | 블록 암호, CBC 모드, IV 사용     | 빠르고 양방향 처리 가능              | 민감정보 암/복호화 |
| SHA256   | 해시함수, 단방향                 | 간단하고 빠름                         | 무결성 검증 |
| PBKDF2   | 반복 기반 키 스트레칭             | Salt 적용, 비교적 빠름               | 로그인 비밀번호 |
| bcrypt   | Blowfish 기반, salt 내장          | 타임슬로우, 보안 우수                 | 사용자 패스워드 |
| scrypt   | 메모리 기반 키 스트레칭           | 보안 최고, 메모리 소모 큼            | 금융/인증 |

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

## 참고사항
AES 키/IV는 내부적으로 16byte로 맞춰 자동 보정됩니다.
SHA, PBKDF2, bcrypt, scrypt는 단방향 해시입니다.
복호화가 필요한 경우 AES 방식만 사용하세요.

## 라이센스
MIT License