package org.example.expert.domain.log.repository;

import org.example.expert.domain.log.entity.ManagerAdditionLog;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ManagerAdditionLogJpaRepository extends JpaRepository<ManagerAdditionLog, Long> {
}