package org.example.expert.domain.log.service;

import lombok.RequiredArgsConstructor;
import org.example.expert.domain.log.entity.ManagerAdditionLog;
import org.example.expert.domain.log.repository.ManagerAdditionLogJpaRepository;
import org.example.expert.domain.manager.entity.ManagerRequestStatus;
import org.example.expert.domain.user.entity.User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(propagation = Propagation.REQUIRES_NEW)
@RequiredArgsConstructor
public class LogWriteService {
    private final ManagerAdditionLogJpaRepository managerAdditionRepository;

    public Long saveManagerAdditionLog(User authUser, User managerUser, ManagerRequestStatus requestStatus) {
        ManagerAdditionLog log = ManagerAdditionLog.builder()
                .requester(authUser)
                .requestee(managerUser)
                .status(requestStatus)
                .build();

        ManagerAdditionLog savedLog = managerAdditionRepository.save(log);

        return savedLog.getId();
    }
}
