# 내일배움캠프 9주차 개인과제
- JPA 성능 최적화와 Querydsl
- AWS EC2, RDS, S3 설정 및 배포
- 조회 쿼리 성능 최적화

<br/>

## 1. AWS 아키텍쳐 구성
### VPC를 이용한 Private RDS 구성

<br/>

<b>🤔 Private 환경 구축 의사결정 Flow</b>
- 외부에서 직접적으로 DB에 접근하는 아키텍쳐가 안전하지 않다고 생각함. Public한 Endpoint가 늘어나면, 신경써야 하는 부분이 늘어남. 
- [변경된 RDS 정책](https://aws.amazon.com/ko/about-aws/whats-new/2024/02/aws-free-tier-750-hours-free-public-ipv4-addresses/)에 따라 Free Tier에서도 Public IPv4가 할당되면 과금이 되기에, Public DB 접근 환경을 구성할 이유를 찾지 못함.
- SSH를 통한 DB 서버 직접 접근이 불가능하다는 단점은, 같은 VPS에 존재하는 EC2를 통해 접속할 수 있기 때문에 큰 불편은 아니라고 판단.

<br/><br/>

<b>🗺️ 전체적인 그림</b>

<img src="https://github.com/user-attachments/assets/356e353d-086f-44ab-9bca-8d713bb169c1" width=80%/>

- VPC에 EC2, RDS를 위한 보안 그룹을 각각 생성
- EC2는 모든 SSH, HTTP, HTTPS 요청을 허용하도록 보안 그룹 설정
- RDS는 EC2를 통해서만 접근 가능하도록 보안 그룹 설정
- EC2에 배정된 Elastic IP를 통해 서비스 접근

<br/><br/>

<b>💂🏻 보안 그룹 생성 </b>
- EC2

<img width="80%" alt="스크린샷 2025-03-19 18 36 52" src="https://github.com/user-attachments/assets/f1ba5a19-366a-4e68-b965-873df086e48e" />

<br/><br/>

- RDS

<img width="80%" alt="스크린샷 2025-03-19 18 39 13" src="https://github.com/user-attachments/assets/068697d3-abed-4c56-a6d3-dbf8bf1624f9" />

<br/><br/>


<details>
  <summary>
    <b> 💿 RDS Parameter Group 설정 </b> 
  </summary>

  <br/> 
  
  - character_set ➡️ utf8mb4 (한글, 이모티콘 지원)
  
  <img width="30%" alt="스크린샷 2025-03-19 18 49 34" src="https://github.com/user-attachments/assets/c78b7a4d-ff58-4db3-9670-191b5a82927d" />  
  
  <br/> 
  
  - time_zone ➡️ Asia/Seoul
    
  <img width="30%" alt="스크린샷 2025-03-19 18 52 19" src="https://github.com/user-attachments/assets/89e386d1-a585-4104-a331-811df508eee5" />
  
  <br/> 
  
  - collation_connection, collation_server ➡️ utf8mb4_unicode_ci (정렬 방식)
  
  <img width="30%" alt="스크린샷 2025-03-19 18 54 45" src="https://github.com/user-attachments/assets/708031b1-d2a9-40a4-a261-9b71513bb43f" />
  </details>


<br/><br/>

### EC2 heath check API

- `/health`로 요청을 보내면 `status: ok` 요청을 보내줌
<img width="50%" alt="스크린샷 2025-03-18 15 47 41" src="https://github.com/user-attachments/assets/e8a6d6d7-4cca-4fdb-a147-58defcdeefa2" />


<br/><br/>

### S3 구성

<br/>

<details>
  <summary>
    <b>🗑️ 버킷 세팅</b>
  </summary>

- S3 버킷 생성

  - 외부 사용자도 접근하여 다운로드할 수 있도록 한 버킷이므로,  Public Access 허용
<img width="60%" alt="스크린샷 2025-03-19 18 57 21" src="https://github.com/user-attachments/assets/0dd34a3c-7019-4362-8dac-6e1f589e8e62" />

<br/><br/>

- Bucket Policy 설정

  - 외부 사용자가 접근할 수 있는 범위를 Object 조회로 한정함
<img width="50%" alt="스크린샷 2025-03-19 19 05 52" src="https://github.com/user-attachments/assets/bea95251-9efc-439d-bc79-2477281747f8" />

<br/><br/>

- IAM User 설정

  - User에 S3FullAccess permission을 허용
  - 공개키, 개인키를 발급 받아 서버에서 활용
<img width="50%" alt="스크린샷 2025-03-19 19 08 54" src="https://github.com/user-attachments/assets/4b902f31-36d4-402a-91a0-8c8e7b0ce0c4" />

</details>

<br/><br/>

## 2. 조회 쿼리 성능 최적화
### 실험 세팅

- 100만개의 User 데이터를 대상으로 작업 수행.
- Nickname을 기준으로 유저를 조회한다.
- 조회를 100번 수행한 후에, 실행 시간의 평균을 출력한디.

<br/>

### 기본 실행

- 실행한 테스트 코드는 다음과 같다.

```java
    @Test
    void 닉네임으로_유저를_조회하는_성능을_측정한다() {
        long totalElapsed = 0;

        // 100번 실행한 값의 평균을 낸다.
        for (int i = 0; i < 100; i++) {
            long start = System.currentTimeMillis();
            Optional<UserWithIdAndNickname> user500000 = userRepository.findUserByNickname("user500000");
            long end = System.currentTimeMillis();
            totalElapsed += end - start;
        }
        double avgElapsed = totalElapsed / 100.0;

        log.info("avg elapsed time : {} ms", avgElapsed);
    }
```

<br/>

- 결과 (224.36ms)

<img width="90%" alt="스크린샷 2025-03-19 19 05 52" src="https://github.com/user-attachments/assets/d58d5432-83c4-4748-b59b-fad2cf3dd16b" />


<br/><br/>

### 1차 개선 - Index

- nickname column에 index 설정

<img width="90%" alt="스크린샷 2025-03-19 19 05 52" src="https://github.com/user-attachments/assets/abb30c62-5a70-4a2e-be33-ff047b604b6f" />

<br/><br/>

- 결과 (1.47ms)
<img width="90%" alt="스크린샷 2025-03-19 19 05 52" src="https://github.com/user-attachments/assets/051c2e2f-cadb-405e-95ff-d9e901336adb" />


<br/><br/>

### 2차 개선 - Covering Index

- Query에 Index 대상인 컬럼만 포함되어 Covering Index의 혜택을 받을 수 있도록 변경

- DTO 생성
```java
  @Getter
  @AllArgsConstructor
  public class UserWithIdAndNickname {
  
      private long id;
      private String nickname;
  }
```

- Query 수정
```java
    @Query("select new org.example.expert.domain.user.dto.UserWithIdAndNickname(u.id, u.nickname)" +
          " from User u where u.nickname = :nickname")
    Optional<UserWithIdAndNickname> findUserByNickname(@Param("nickname") String nickName);
```

<br/><br/>

- 결과 (0.98ms)
  - 변경된 쿼리와 수행 시간

<img width="90%" src="https://github.com/user-attachments/assets/0dc514c8-8a95-4209-a6a9-b6a29905e08f"></img>

<br/><br/>

### 정리

<b>🧪 실험 결과</b>

| 구분 | 변경 사항 | 결과 | 성능 개선 (직전 단계 대비) |
|-----|---------|----|---------|
|기본실행|-|224.36ms|-|
|1차개선|nickname Column Index 생성|1.47ms|99.34%|
|2차개선|covering index 적용 받도록 쿼리 변경|0.98ms|30%|

<br/>

<b>🧐 총평</b>
- nickname column은 cardinality가 매우 높았기 때문에(Unique에 가까움), Index를 걸었을 때에 좋은 성능을 보임.
- Covering Index는 추가로 성능 개선 효과가 있었으나, JPA 엔티티 전체를 받아오기에는 적합하지 않음.
 
