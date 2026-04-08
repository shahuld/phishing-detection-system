package com.phishguard.repository;

import com.phishguard.entity.UrlHistory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface UrlHistoryRepository extends JpaRepository<UrlHistory, Long> {
    List<UrlHistory> findByUserIdOrderByScannedAtDesc(Long userId);
}
