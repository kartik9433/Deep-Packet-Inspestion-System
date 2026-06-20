package com.dpi.repository;

import com.dpi.model.BlockingRule;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface BlockingRuleRepository extends JpaRepository<BlockingRule, Long> {

    List<BlockingRule> findByRuleTypeAndActive(BlockingRule.RuleType ruleType, boolean active);

    Optional<BlockingRule> findByRuleTypeAndValue(BlockingRule.RuleType ruleType, String value);

    List<BlockingRule> findByActive(boolean active);

    void deleteByRuleTypeAndValue(BlockingRule.RuleType ruleType, String value);
}
