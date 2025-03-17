package org.example.expert.domain.log.entity;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.example.expert.domain.common.entity.Timestamped;
import org.example.expert.domain.manager.entity.ManagerRequestStatus;
import org.example.expert.domain.user.entity.User;

@Entity
@Table(name = "log")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class ManagerAdditionLog extends Timestamped {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "log_id")
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "requester_id")
    private User requester; //등록 요청한 유저

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "requestee_id")
    private User requestee;

    @Enumerated(EnumType.STRING)
    private ManagerRequestStatus status;

    @Builder
    public ManagerAdditionLog(User requester, User requestee, ManagerRequestStatus status) {
        this.requester = requester;
        this.requestee = requestee;
        this.status = status;
    }
}
